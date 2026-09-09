import collections
import configparser
import os
import threading
import time

from ..crypto.keys import (
    AddressKeys, chan_keys_from_name, generate_keys, wif_encode, wif_decode,
)
from ..crypto.pow import (
    PowExecutor, calculate_target, initial_hash_of,
    is_proof_of_work_sufficient,
)
from ..crypto.pow.strategy import PoWStrategy
from ..crypto.pow.standard import StandardPoWStrategy
from ..protocol import address as addr_module
from ..protocol import objects
from ..protocol import packets
from ..protocol.const import (
    OBJECT_GETPUBKEY, OBJECT_PUBKEY, OBJECT_MSG, OBJECT_BROADCAST,
    GETPUBKEY_TTL, PUBKEY_TTL,
    MSG_TTL_DEFAULT, MSG_TTL_MIN, MSG_TTL_MAX, format_ttl_pt,
    BITMESSAGE_ENCODING_TRIVIAL,
)
from ..util.hashing import double_sha512, sha512
from ..net.manager import NetworkManager
from .database import Database
from .events import EventEmitter
from .events.events import LEGACY_MAP
from .models import Message as MessageModel


class Client:

    def __init__(self, data_dir, pow_strategy: PoWStrategy | None = None,
                 network_manager=None, db=None):
        """Client com Dependency Injection para PoW e NetworkManager.

        Args:
            data_dir: diretório de dados (SQLite, knownnodes).
            pow_strategy: Strategy de PoW injetada; se None usa
                StandardPoWStrategy (produção). Testes podem injetar
                MockPoWStrategy para execução instantânea.
            network_manager: NetworkManager injetado; se None cria um
                padrão (mantém compatibilidade).
            db: Database injetada (para testes sem I/O real).
        """
        self.data_dir = data_dir
        self.db = db if db is not None else Database(data_dir)
        self.pow_strategy: PoWStrategy = pow_strategy or StandardPoWStrategy()
        import queue as _queue
        self.ui_queue = _queue.Queue()
        # Observer Pattern: EventEmitter para desacoplar Client da GUI
        self.events = EventEmitter()
        # Bridge: todo put na ui_queue também emite via EventEmitter
        _orig_put = self.ui_queue.put

        def _put_and_emit(item, block=True, timeout=None):  # noqa: C901
            result = _orig_put(item, block, timeout)
            try:
                if isinstance(item, tuple) and item:
                    legacy = item[0]
                    data = item[1:] if len(item) > 1 else None
                    # Desempacota payload único para conveniência do observer
                    if isinstance(data, tuple) and len(data) == 1:
                        data = data[0]
                    elif isinstance(data, tuple) and len(data) == 0:
                        data = None
                    mapped = LEGACY_MAP.get(legacy, legacy)
                    self.events.emit(mapped, data if data is not None else item)
                    if mapped != legacy:
                        self.events.emit(legacy, data)
                    # Evento genérico para listeners que querem tudo
                    self.events.emit('*', item)
            except Exception:
                pass
            return result

        self.ui_queue.put = _put_and_emit  # type: ignore[method-assign]
        # Compat: emite também mudança de conexão quando network tem peers
        self._event_queue_bridge = _put_and_emit
        self.identities = {}
        self.pubkeys = {}
        self._pow_stops = {}
        self._pow_meta = {}
        self._pow_sequencer = 0
        # M1: watch guarda (message_id, registrado_em); varrido com TTL.
        self._ack_watch = {}
        self._ack_retry_counts = {}
        self._msg_in_flight = set()
        self._getpubkey_last = {}
        self._threads = []
        # A2: workers de PoW/relay rastreados para join no stop().
        self._workers = []
        # A11: dedupe de ACKs recentes + pool limitado.
        self._ack_seen = collections.OrderedDict()
        self._ack_pool = None
        self._lock_path = None
        self._lock_owned = False
        self._log_lines = collections.deque(maxlen=200)
        self._lock = threading.RLock()
        if network_manager is not None:
            self.net = network_manager
            # Garante callbacks corretos mesmo quando injetado
            self.net.on_object = self._on_object
            self.net.on_log = self._log
            self.net.db = self.db
        else:
            self.net = NetworkManager(
                data_dir, self.db, on_object=self._on_object, on_log=self._log)
        self.started = False

    # ------------------------------------------------------------------

    @staticmethod
    def _lock_owner_alive(other, mine):
        import errno as _errno
        import os as _os
        if not other or not other.isdigit() or int(other) == int(mine):
            return False
        try:
            _os.kill(int(other), 0)
            return True
        except PermissionError:
            # Existe, mas sem permissão para sinalizar → dono vivo.
            return True
        except OSError as exc:
            if getattr(exc, 'errno', None) == _errno.ESRCH:
                return False
            return True
        except Exception:
            return False

    def _claim_stale_lock(self, mine):
        import os as _os
        fd = _os.open(self._lock_path + '.tmp',
                      _os.O_CREAT | _os.O_TRUNC | _os.O_WRONLY, 0o600)
        try:
            _os.write(fd, mine.encode())
        finally:
            _os.close(fd)
        _os.replace(self._lock_path + '.tmp', self._lock_path)
        # ADV: replace não é atômico entre 2 reclamantes (TOCTOU): dois
        # processos podem ver stale e trocar em sequência, ambos achando
        # que são donos. Re-lê e só assume se o conteúdo for o nosso.
        try:
            with open(self._lock_path, 'r') as handle:
                current = handle.read().strip()
        except Exception:
            current = mine
        if current != mine:
            self._lock_owned = False
            raise RuntimeError(
                'outra instância assumiu o lock (%s)' % current)
        self._lock_owned = True

    def _read_lock_owner(self):
        try:
            with open(self._lock_path, 'r') as handle:
                return handle.read().strip()
        except Exception:
            return ''

    def _write_own_lock(self):
        import os as _os
        # ADV: makedirs sem mode criava 0755 quando o dir não existia
        # (testes/tmp). Força 0700 + chmod como run.py/database.py.
        _os.makedirs(self.data_dir, mode=0o700, exist_ok=True)
        try:
            _os.chmod(self.data_dir, 0o700)
        except Exception:
            pass
        self._lock_path = _os.path.join(self.data_dir, 'bmchat.lock')
        mine = str(_os.getpid())
        if self._try_fresh_lock(mine):
            return
        other = self._read_lock_owner()
        if self._lock_owner_alive(other, mine):
            raise RuntimeError(
                'outra instância em execução (pid %s)' % other)
        try:
            self._claim_stale_lock(mine)
        except RuntimeError:
            # ADV: contenção real (outro reclamante venceu) deve barrar,
            # não seguir sem lock. Só erros de IO silenciam.
            self._lock_owned = False
            raise
        except Exception:
            self._lock_owned = False

    def _try_fresh_lock(self, mine):
        import os as _os
        try:
            fd = _os.open(self._lock_path,
                          _os.O_CREAT | _os.O_EXCL | _os.O_WRONLY)
        except FileExistsError:
            return False
        try:
            _os.write(fd, mine.encode())
        finally:
            _os.close(fd)
        self._lock_owned = True
        return True

    def start(self):
        self._write_own_lock()
        self._load_identities()
        self._load_pubkeys()
        streams = self._participating_streams()
        self.net.start(streams)
        self.started = True
        self._threads = []
        retry = threading.Thread(target=self._retry_loop, daemon=True,
                                 name='client-retry')
        retry.start()
        self._threads.append(retry)
        reannounce = threading.Thread(target=self._reannounce_loop,
                                      daemon=True, name='client-reannounce')
        reannounce.start()
        self._threads.append(reannounce)
        scheduled = threading.Thread(target=self._scheduled_sender_loop,
                                     daemon=True, name='client-scheduled')
        scheduled.start()
        self._threads.append(scheduled)

    def _cancel_all_pow(self):
        self.cancel_all_pow()

    def _stop_network_quietly(self):
        try:
            self.net.stop()
        except Exception:
            pass

    def _track_worker(self, thread):
        with self._lock:
            self._workers.append(thread)
            # Evita crescimento sem limite.
            if len(self._workers) > 64:
                self._workers = [t for t in self._workers if t.is_alive()][-32:]

    def _join_threads(self):
        for thread in list(getattr(self, '_threads', [])):
            try:
                thread.join(timeout=5)
            except Exception:
                pass
        # A2: workers de PoW/relay com join limitado.
        for worker in list(getattr(self, '_workers', [])):
            try:
                worker.join(timeout=5)
            except Exception:
                pass
        with self._lock:
            self._workers = [t for t in self._workers if t.is_alive()]
        pool = getattr(self, '_ack_pool', None)
        if pool is not None:
            try:
                pool.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass
            self._ack_pool = None

    def _own_lock_current(self):
        import os as _os2
        try:
            with open(self._lock_path, 'r') as handle:
                current = handle.read().strip()
        except Exception:
            return True
        try:
            mine = str(_os2.getpid())
        except Exception:
            return False
        return (not current) or current == mine

    def _remove_lock_file(self):
        # A3: remove só o próprio lock; nunca o de outra instância.
        try:
            import os as _os2
            if getattr(self, '_lock_path', None) and getattr(
                    self, '_lock_owned', False):
                if self._own_lock_current():
                    try:
                        _os2.unlink(self._lock_path)
                    except Exception:
                        pass
            self._lock_owned = False
        except Exception:
            pass

    def _close_db_quietly(self):
        try:
            self.db.close()
        except Exception:
            pass

    def stop(self):
        self.started = False
        self._cancel_all_pow()
        self._stop_network_quietly()
        self._join_threads()
        self._remove_lock_file()
        self._close_db_quietly()

    def _retry_loop(self):
        while self.started:
            for _ in range(60):
                if not self.started:
                    return
                time.sleep(10)
            if not self.started:
                return
            try:
                self._retry_awaiting()
            except Exception as exc:
                self._log('rede', 'tentativa de reenvio: %r' % exc)

    def _awaiting_addresses(self):
        try:
            rows = self.db.query(
                "SELECT DISTINCT to_address FROM messages WHERE "
                "direction='out' AND status='awaiting-pubkey'")
        except Exception:
            return []
        return [r['to_address'] for r in rows if r['to_address']]

    def _sweep_ack_watch(self, now=None):  # noqa: C901
        """M1: expira watches antigos (TTL) — unificado."""
        try:
            from ..protocol.const import MSG_TTL
        except Exception:
            MSG_TTL = 4 * 24 * 3600
        now = now if now is not None else time.time()
        with self._lock:
            dead = []
            for key, entry in list(self._ack_watch.items()):
                try:
                    if not isinstance(entry, tuple):
                        dead.append(key)
                        continue
                    ts = entry[1] if len(entry) >= 2 else now
                    # Para deadline (futuro), now - ts é negativo => mantém; só remove timestamps antigos
                    if now - ts > MSG_TTL:
                        dead.append(key)
                except Exception:
                    dead.append(key)
            for key in dead:
                self._ack_watch.pop(key, None)

    def _retry_stuck_sending(self):
        """A2: 'sending' preso p/ sempre volta a 'awaiting-pubkey'."""
        try:
            cutoff = int(time.time()) - 600
            self.db.execute(
                "UPDATE messages SET status='awaiting-pubkey' WHERE "
                "direction='out' AND status='sending' AND timestamp < ?",
                (cutoff,))
        except Exception:
            pass

    def _retry_one_ack_failed(self, row):
        message_id = row['id']
        try:
            full = self.db.get_message(message_id)
        except Exception:
            return
        if not full:
            # ADV: não consome slot para mensagem apagada (antes
            # incrementava e esgotava as 3 tentativas sem fazer nada).
            return
        to_address = full['to_address']
        if to_address in self.pubkeys:
            # ADV: só conta quando vai queimar PoW de verdade; se a
            # identidade sumiu, _pow_and_publish retorna sem lançar e
            # não deve esgotar o limite.
            if full['from_address'] not in self.identities:
                return
            with self._lock:
                tries = int(self._ack_retry_counts.get(message_id, 0))
                if tries >= 3:
                    return
                self._ack_retry_counts[message_id] = tries + 1
            self._pow_and_publish_message(
                message_id, full['from_address'], to_address,
                full['body'], full['encoding'])
            return
        with self._lock:
            tries = int(self._ack_retry_counts.get(message_id, 0))
            if tries >= 3:
                return
            self._ack_retry_counts[message_id] = tries + 1
        try:
            self.db.set_message_status(message_id, 'awaiting-pubkey')
        except Exception:
            pass

    def _retry_ack_failed(self):
        """M5: reenvio limitado de 'ack-failed' (máx 3 tentativas) + prune deadline."""
        # Primeiro descarta watches expirados (TTL) — marca ack-failed
        try:
            self._prune_ack_watch()
        except Exception:
            pass
        try:
            rows = self.db.query(
                "SELECT id, to_address FROM messages WHERE "
                "direction='out' AND status='ack-failed' LIMIT 5")
        except Exception:
            return 0
        for row in rows:
            try:
                self._retry_one_ack_failed(row)
            except Exception:
                pass
        return 0

    def _retry_awaiting(self):  # noqa: C901
        # Sweep/PRUNE de ACKs vencidos antes do retry (nunca espera além do expires).
        # Varreduras locais sempre rodam, mesmo offline, para não acumular watches
        try:
            self._prune_ack_watch()
        except Exception:
            pass
        try:
            self._sweep_ack_watch()
        except Exception:
            pass
        # B7: limite de paralelismo (20/vez) evita fork-bomb
        self._retry_stuck_sending()
        # ADV: sem peers, PoW offline queima CPU/bateria para anunciar
        # no vazio (0 alvos). _send_queued já pulava, mas request_pubkey
        # e _retry_ack_failed não — 20 pendentes offline = fork-bomb.
        # Consistente: varreduras locais rodam, PoW só online.
        # (test_retry_republishes agora simula 1 peer online.)
        try:
            offline = self.net.established_count == 0
        except Exception:
            offline = False
        if offline:
            return
        # Só queima PoW se online
        self._retry_ack_failed()
        for address in self._awaiting_addresses()[:20]:
            if not self.started:
                return
            if address in self.pubkeys:
                self._send_queued(address)
                continue
            self._log('rede', 'republicando pedido de chave para %s' %
                      address[:18])
            try:
                self.request_pubkey(address)
            except Exception:
                continue

    def _log(self, level, message):
        line = '[%s] %s' % (time.strftime('%H:%M:%S'), message)
        with self._lock:
            self._log_lines.append(line)
        self.ui_queue.put(('log', level, str(message)))

    def recent_logs(self, limit=200):
        with self._lock:
            return list(self._log_lines)[-limit:]

    def _refresh_streams(self):
        if self.started:
            streams = self._participating_streams()
            self.net.streams = sorted(set(streams))
            # NOTE: não tocar em connection.their_streams (são os streams do par)

    def _participating_streams(self):
        streams = set()
        for row in self.db.all_identities(enabled_only=True):
            streams.add(row['stream'])
        for contact in self.db.all_contacts():
            try:
                _, _, contact_stream, _ = addr_module.decode_address(
                    contact['address'])
                streams.add(contact_stream)
            except Exception:
                pass
        for subscription in self.db.all_subscriptions():
            try:
                _, _, stream, _ = addr_module.decode_address(
                    subscription['address'])
                streams.add(stream)
            except Exception:
                pass
        # Nunca anuncie lista vazia: nós reais derrubam pares sem stream
        return sorted(streams) or [1]

    # ---------- identidades ----------

    def _load_identities(self):
        self.identities = {}
        for row in self.db.all_identities(enabled_only=True):
            keys = AddressKeys.from_private_keys(
                row['priv_signing'], row['priv_encryption'],
                stream=row['stream'])
            keys.nonce_trials_per_byte = row['noncetrials']
            keys.payload_length_extra_bytes = row['extrabytes']
            self.identities[row['address']] = keys

    def _reparse_orphans(self, limit=100):
        """M7: retenta objetos guardados que não tinham identidade na chegada."""
        try:
            rows = self.db.query(
                'SELECT raw FROM objects WHERE type IN (2, 3) '
                'ORDER BY received DESC LIMIT ?', (int(limit),))
        except Exception:
            return
        for row in rows:
            try:
                raw = bytes(row['raw'])
            except Exception:
                continue
            try:
                parsed = objects.ParsedObject(raw)
            except Exception:
                continue
            try:
                self._on_object(parsed, raw, None)
            except Exception:
                pass

    def create_identity(self, label, stream=1):
        keys = generate_keys(stream=stream)
        self.db.add_identity(
            keys.address, label or keys.address, stream,
            keys.signing_private, keys.encryption_private,
            noncetrials=1000, extrabytes=1000)
        keys.nonce_trials_per_byte = 1000
        keys.payload_length_extra_bytes = 1000
        with self._lock:
            self.identities[keys.address] = keys
        self._refresh_streams()
        self.ui_queue.put(('identity-created', keys.address, label))
        self._reparse_orphans()
        return keys.address

    def rename_identity(self, address, label):
        label = (label or '').strip()
        if not label:
            return 'invalid', 'rótulo vazio'
        if self.db.get_identity(address) is None:
            return 'not-found', 'identidade não encontrada'
        self.db.set_identity_label(address, label)
        self.ui_queue.put(('identity-updated', address, label))
        return 'success', None

    def set_identity_enabled(self, address, enabled):
        if self.db.get_identity(address) is None:
            return 'not-found', 'identidade não encontrada'
        if not enabled:
            enabled_rows = self.db.all_identities(enabled_only=True)
            addrs = [r['address'] for r in enabled_rows]
            if len(addrs) <= 1 and address in addrs:
                return 'last-active', (
                    'não é possível desabilitar a última identidade ativa; '
                    'crie outra antes')
        self.db.set_identity_enabled(address, enabled)
        self._load_identities()
        self._refresh_streams()
        self.ui_queue.put(('identity-updated', address, ''))
        return 'success', None

    def delete_identity(self, address):
        if self.db.get_identity(address) is None:
            return 'not-found', 'identidade não encontrada'
        enabled = self.db.all_identities(enabled_only=True)
        addrs = [r['address'] for r in enabled]
        if len(addrs) <= 1 and address in addrs:
            return 'last-active', (
                'não é possível excluir a última identidade ativa; '
                'crie outra antes')
        self.db.delete_identity(address)
        with self._lock:
            self.identities.pop(address, None)
        self._refresh_streams()
        self.ui_queue.put(('identity-removed', address, ''))
        return 'success', None

    def create_channel(self, name, stream=1, label=None):
        name = (name or '').strip()
        if not name:
            return 'invalid', 'nome do canal vazio'
        try:
            stream = int(stream)
        except (TypeError, ValueError):
            stream = 1
        if stream < 1:
            stream = 1
        keys = chan_keys_from_name(name, stream)
        self.db.add_identity(
            keys.address, label or name, stream,
            keys.signing_private, keys.encryption_private,
            noncetrials=1000, extrabytes=1000, chan=1,
            chan_label=label or name)
        keys.nonce_trials_per_byte = 1000
        keys.payload_length_extra_bytes = 1000
        with self._lock:
            self.identities[keys.address] = keys
        self._refresh_streams()
        self.ui_queue.put(('channel-created', keys.address, label))
        self._reparse_orphans()
        return 'success', keys.address

    def export_identity(self, address):
        keys = self.identities.get(address)
        if keys is None or keys.signing_private is None:
            return None
        row = self.db.get_identity(address)
        return {
            'address': address,
            'label': (row['label'] if row else '') or address,
            'stream': keys.stream,
            'signing_wif': wif_encode(keys.signing_private),
            'encryption_wif': wif_encode(keys.encryption_private),
        }

    def import_identity(self, signing_wif, encryption_wif, label, stream=1):
        try:
            stream = int(stream)
        except (TypeError, ValueError):
            stream = 1
        try:
            signing_private = wif_decode((signing_wif or '').strip())
            encryption_private = wif_decode((encryption_wif or '').strip())
        except Exception:
            return 'invalid', 'chave WIF inválida ou com checksum errado'
        try:
            keys = AddressKeys.from_private_keys(
                signing_private, encryption_private, stream)
        except Exception:
            return 'invalid', 'não foi possível derivar o endereço'
        if keys.address in self.identities:
            return 'exists', 'esta identidade já existe neste dispositivo'
        self.db.add_identity(
            keys.address, label or keys.address, stream,
            signing_private, encryption_private,
            noncetrials=1000, extrabytes=1000)
        keys.nonce_trials_per_byte = 1000
        keys.payload_length_extra_bytes = 1000
        with self._lock:
            self.identities[keys.address] = keys
        self._refresh_streams()
        self.ui_queue.put(('identity-created', keys.address, label))
        self._reparse_orphans()
        return 'success', keys.address

    def export_keys_dat(self):
        blocks = []
        for row in self.db.all_identities(enabled_only=False):
            keys = self.identities.get(row['address'])
            if keys is None or keys.signing_private is None:
                continue
            lines = [
                '[%s]' % row['address'],
                'label = %s' % (row['label'] or row['address']),
                'enabled = %s' % ('true' if row['enabled'] else 'false'),
                'noncetrialsperbyte = %s' % keys.nonce_trials_per_byte,
                'payloadlengthextrabytes = %s'
                % keys.payload_length_extra_bytes,
                'privsigningkey = %s' % keys.signing_private.hex(),
                'privencryptionkey = %s' % keys.encryption_private.hex(),
            ]
            if row['chan']:
                lines.append('chan = true')
                lines.append('chan_label = %s' % (
                    row['chan_label'] or row['label'] or ''))
            blocks.append('\n'.join(lines))
        return '\n\n'.join(blocks) + ('\n' if blocks else '')

    def _import_keys_dat_section(self, parser, section, result):
        try:
            expected = AddressKeys.from_address(section)
            signing_private = bytes.fromhex(
                parser.get(section, 'privsigningkey').strip())
            encryption_private = bytes.fromhex(
                parser.get(section, 'privencryptionkey').strip())
            keys = AddressKeys.from_private_keys(
                signing_private, encryption_private, expected.stream)
        except Exception:
            result['errors'] += 1
            return
        if keys.address != section:
            result['errors'] += 1
            return
        if keys.address in self.identities:
            result['skipped'] += 1
            return
        label = parser.get(
            section, 'label', fallback=keys.address).strip() or \
            keys.address
        chan = parser.get(
            section, 'chan', fallback='false').strip().lower() == 'true'
        chan_label = parser.get(section, 'chan_label', fallback='').strip()
        noncetrials, extrabytes = self._keys_dat_pow_params(parser, section)
        self.db.add_identity(
            keys.address, label, expected.stream,
            signing_private, encryption_private,
            noncetrials=noncetrials, extrabytes=extrabytes,
            chan=1 if chan else 0,
            chan_label=chan_label or (label if chan else ''))
        keys.nonce_trials_per_byte = noncetrials
        keys.payload_length_extra_bytes = extrabytes
        with self._lock:
            self.identities[keys.address] = keys
        result['imported'] += 1
        result['addresses'].append(keys.address)

    @staticmethod
    def _keys_dat_pow_params(parser, section):
        try:
            noncetrials = int(parser.get(
                section, 'noncetrialsperbyte', fallback='1000'))
            extrabytes = int(parser.get(
                section, 'payloadlengthextrabytes', fallback='1000'))
        except ValueError:
            noncetrials, extrabytes = 1000, 1000
        return noncetrials, extrabytes

    def import_keys_dat(self, text):
        parser = configparser.ConfigParser()
        parser.optionxform = str
        try:
            parser.read_string(text or '')
        except Exception:
            return {'imported': 0, 'skipped': 0, 'errors': 1, 'addresses': []}
        result = {'imported': 0, 'skipped': 0, 'errors': 0, 'addresses': []}
        for section in parser.sections():
            if not section.startswith('BM-'):
                continue
            self._import_keys_dat_section(parser, section, result)
        if result['imported']:
            self._refresh_streams()
            self.ui_queue.put(('identity-created', '', ''))
            self._reparse_orphans()
        return result

    def _load_pubkeys(self):
        for row in self.db.all_pubkeys():
            self.pubkeys[row['address']] = {
                'signing_public': row['signing_public'],
                'encryption_public': row['encryption_public'],
                'nonce_trials_per_byte': row['noncetrials'],
                'payload_length_extra_bytes': row['extrabytes'],
            }

    def has_pubkey(self, address):
        return address in self.pubkeys

    # ---------- contatos / canais ----------

    def add_contact(self, address_text, label=None):
        status, version, stream, ripe = addr_module.decode_address(
            address_text)
        if status != 'success':
            return status, version
        if version < 3:
            return 'unsupported', version
        self.db.add_contact(address_text, label or address_text,
                            stream=stream)
        self._refresh_streams()
        self.ui_queue.put(('contact-added', address_text, label))
        return 'success', version

    def remove_contact(self, address_text):
        self.db.remove_contact(address_text)
        self.db.delete_conversation(address_text)
        self._refresh_streams()
        self.ui_queue.put(('contact-removed', address_text, ''))

    def subscribe(self, name_or_address, label=None, stream=1):
        status, _version, _stream, _ripe = addr_module.decode_address(
            name_or_address)
        if status == 'success':
            self.db.add_subscription(name_or_address,
                                     label or name_or_address)
            self._refresh_streams()
            self.ui_queue.put(('subscribed', name_or_address, label))
            return 'success', _version
        name = (name_or_address or '').strip()
        if not name:
            return status, None
        try:
            keys = chan_keys_from_name(name, stream)
        except Exception:
            return 'invalid', None
        self.db.add_subscription(keys.address, label or name, name)
        self._refresh_streams()
        self.ui_queue.put(('subscribed', keys.address, label or name))
        return 'success', 4

    def unsubscribe(self, address_text):
        self.db.remove_subscription(address_text)
        self.db.delete_conversation(address_text)
        self._refresh_streams()
        self.ui_queue.put(('subscribed', address_text, ''))

    # ---------- objetos recebidos ----------

    def _on_object(self, parsed, raw, source):
        try:
            self._maybe_mark_ack(parsed)
            if parsed.object_type == OBJECT_GETPUBKEY:
                self._on_getpubkey(parsed)
            elif parsed.object_type == OBJECT_PUBKEY:
                self._on_pubkey(parsed, raw)
            elif parsed.object_type == OBJECT_MSG:
                self._on_msg(parsed, raw)
            elif parsed.object_type == OBJECT_BROADCAST:
                self._on_broadcast(parsed, raw)
        except Exception as exc:
            self._log('process', 'erro ao processar objeto: %r' % exc)

    def _identities_snapshot(self):
        """M7: snapshot de identities sob lock (iteração segura)."""
        with self._lock:
            return list(self.identities.items())

    def _maybe_mark_ack(self, parsed):
        if parsed.object_type != OBJECT_MSG or parsed.version != 1:
            return
        try:
            key = bytes(parsed.raw[16:])
            with self._lock:
                entry = self._ack_watch.pop(key, None)
        except Exception:
            return
        if not entry:
            return
        message_id = entry[0] if isinstance(entry, tuple) else entry
        if message_id:
            try:
                # A2: DB pode estar fechado no stop(); nunca levantar aqui.
                self.db.set_message_status(message_id, 'ackreceived')
            except Exception:
                return
            try:
                with self._lock:
                    self._ack_retry_counts.pop(message_id, None)
            except Exception:
                pass
            self._log('rede', 'confirmação (ACK) recebida: mensagem entregue')
            self.ui_queue.put(('ack', message_id))

    def _on_getpubkey(self, parsed):
        tag = parsed.data[:32]
        now = time.time()
        try:
            last = self._getpubkey_last.get(bytes(tag), 0)
            if now - last < 300:
                return
        except Exception:
            pass
        for address, keys in self._identities_snapshot():
            if keys.tag == tag:
                if parsed.stream != keys.stream:
                    return
                try:
                    self._getpubkey_last[bytes(tag)] = now
                except Exception:
                    pass
                self._log('rede', 'pedido de chave pública recebido para %s; '
                          'publicando pubkey…' % address[:18])
                self._publish_pubkey(keys, parsed.stream)
                return

    def _on_pubkey(self, parsed, raw):
        tag = parsed.data[:32]
        for contact in self.db.all_contacts():
            try:
                contact_keys = AddressKeys.from_address(contact['address'])
            except Exception:
                continue
            if contact_keys.tag != tag:
                continue
            incoming = objects.process_pubkey(raw, contact_keys)
            if incoming is None:
                continue
            self.db.store_pubkey(
                contact['address'], incoming.signing_public,
                incoming.encryption_public,
                incoming.nonce_trials_per_byte,
                incoming.payload_length_extra_bytes)
            self.pubkeys[contact['address']] = {
                'signing_public': incoming.signing_public,
                'encryption_public': incoming.encryption_public,
                'nonce_trials_per_byte': incoming.nonce_trials_per_byte,
                'payload_length_extra_bytes':
                    incoming.payload_length_extra_bytes,
            }
            self._log('rede', 'chave pública recebida e válida de %s' %
                      contact['address'][:18])
            self.ui_queue.put(('pubkey', contact['address']))
            self._send_queued(contact['address'])
            return

    def _on_msg(self, parsed, raw):
        identities = [keys for _, keys in self._identities_snapshot()]
        incoming = objects.process_msg(raw, identities)
        if incoming is None:
            return
        if self.db.message_exists(incoming.inventory_hash):
            return
        body = _decode_body(incoming.encoding, incoming.message)
        self.db.add_message(
            incoming.inventory_hash, incoming.sender_address,
            incoming.to_identity.address, '', body,
            incoming.encoding, int(time.time()), 'in', 'received',
            expires=parsed.expires)
        self._log('rede', 'mensagem recebida de %s' %
                  incoming.sender_address[:18])
        self.ui_queue.put(('message', incoming.sender_address,
                           incoming.to_identity.address, body, parsed.expires))
        if incoming.ack_data:
            self._relay_ack(incoming.ack_data)

    def _ack_packet_seen(self, packet):
        digest = sha512(bytes(packet))
        with self._lock:
            if digest in self._ack_seen:
                return True
            self._ack_seen[digest] = time.time()
            while len(self._ack_seen) > 512:
                try:
                    self._ack_seen.popitem(last=False)
                except Exception:
                    break
            return False

    def _relay_ack_sync(self, packet):
        try:
            if len(packet) < 24:
                return
            magic, command, length, checksum = packets.parse_header(
                packet[:24])
            obj = packet[24:]
            if magic != packets.MAGIC or command != 'object':
                return
            if len(obj) != length:
                return
            if sha512(obj)[:4] != checksum:
                return
            if not is_proof_of_work_sufficient(obj):
                return
            self.net.announce_object(obj)
        except Exception:
            pass

    def _relay_ack(self, packet):
        # A11: pool 2-4 + dedupe (antes: 1 thread por ACK, sem limite).
        try:
            if self._ack_packet_seen(packet):
                return
        except Exception:
            pass
        try:
            with self._lock:
                if self._ack_pool is None:
                    from concurrent.futures import ThreadPoolExecutor
                    self._ack_pool = ThreadPoolExecutor(
                        max_workers=3, thread_name_prefix='ack-relay')
                pool = self._ack_pool
            pool.submit(self._relay_ack_sync, bytes(packet))
        except Exception:
            thread = threading.Thread(target=self._relay_ack_sync,
                                      args=(bytes(packet),), daemon=True,
                                      name='ack-relay-fallback')
            thread.start()
            self._track_worker(thread)

    def _collect_broadcast_keys(self):
        subscriptions = {}
        reverse = {}
        for subscription in self.db.all_subscriptions():
            try:
                keys = AddressKeys.from_address(subscription['address'])
            except Exception:
                continue
            subscriptions[keys.tag] = keys
            reverse[keys.tag] = subscription['address']
        for channel in self.db.all_identities(enabled_only=False):
            if channel['chan'] and channel['enabled']:
                try:
                    keys = AddressKeys.from_address(channel['address'])
                except Exception:
                    continue
                subscriptions.setdefault(keys.tag, keys)
                reverse.setdefault(keys.tag, channel['address'])
        return subscriptions, reverse

    def _store_incoming_broadcast(self, parsed, incoming, reverse):
        if self.db.message_exists(incoming.inventory_hash):
            return
        channel_address = reverse.get(parsed.data[:32])
        if channel_address is None:
            return
        body = _decode_body(incoming.encoding, incoming.message)
        self.db.add_message(
            incoming.inventory_hash, incoming.address, channel_address,
            '', body, incoming.encoding, int(time.time()), 'in', 'received',
            expires=parsed.expires)
        self._log('rede', 'postagem recebida no canal %s' %
                  str(channel_address)[:18])
        self.ui_queue.put(('broadcast', channel_address, incoming.address,
                           body, parsed.expires))

    def _on_broadcast(self, parsed, raw):
        subscriptions, reverse = self._collect_broadcast_keys()
        if not subscriptions:
            return
        incoming = objects.process_broadcast(raw, subscriptions)
        if incoming is None:
            return
        self._store_incoming_broadcast(parsed, incoming, reverse)

    # ---------- TTL global das mensagens ----------

    @staticmethod
    def _clamp_ttl(value):
        try:
            number = int(value)
        except (TypeError, ValueError):
            return MSG_TTL_DEFAULT
        return max(MSG_TTL_MIN, min(MSG_TTL_MAX, number))

    def get_msg_ttl(self):
        """TTL vigente (s) para as próximas mensagens; sempre dentro da faixa."""
        try:
            raw = self.db.get_setting('msg_ttl_seconds', MSG_TTL_DEFAULT)
        except Exception:
            return MSG_TTL_DEFAULT
        return self._clamp_ttl(raw)

    def set_msg_ttl(self, seconds):
        """Salva o TTL global, clampando para [1h, 21d] e avisando em status.

        Retorna (efetivo, clampado). Nunca trava, nunca aceita silenciosamente.
        """
        try:
            number = int(seconds)
        except (TypeError, ValueError):
            effective, clamped = MSG_TTL_DEFAULT, True
        else:
            effective = self._clamp_ttl(number)
            clamped = effective != number
        self.db.set_setting('msg_ttl_seconds', str(effective))
        if clamped:
            hint = ('TTL das mensagens fora da faixa; usando %s '
                    '(a rede só aceita de 1 hora a 21 dias).')
            self._log('rede', hint % format_ttl_pt(effective))
        return effective, clamped

    def _resolve_message_ttl(self, message_id, ttl=None):
        # Retry usa o TTL guardado na linha; linhas legadas usam o vigente.
        if ttl is not None:
            return self._clamp_ttl(ttl)
        try:
            rows = self.db.query('SELECT ttl FROM messages WHERE id=?',
                                 (message_id,))
            stored = rows[0].get('ttl') if rows else None
        except Exception:
            stored = None
        if stored:
            return self._clamp_ttl(stored)
        return self.get_msg_ttl()

    def _prune_ack_watch(self, now=None):  # noqa: C901
        """Descarta watches além da vida do objeto; vencidos viram ack-failed."""
        moment = int(now) if now is not None else int(time.time())
        expired = []
        with self._lock:
            for key, entry in list(self._ack_watch.items()):
                try:
                    if not isinstance(entry, tuple):
                        continue
                    deadline = entry[1] if len(entry) >= 2 else None
                    if deadline is not None and int(deadline) < moment:
                        expired.append((key, entry[0]))
                except Exception:
                    continue
            for key, _message_id in expired:
                self._ack_watch.pop(key, None)
        for _key, message_id in expired:
            try:
                rows = self.db.query(
                    'SELECT status FROM messages WHERE id=?', (message_id,))
                if rows and rows[0]['status'] == 'sent':
                    self.db.set_message_status(message_id, 'ack-failed')
                    self.ui_queue.put(('status', message_id, 'ack-failed'))
            except Exception:
                pass
        return len(expired)

    # ---------- State Pattern helpers ----------
    def get_message_model(self, message_id: int):
        """Retorna Message model com State Pattern para message_id."""
        row = self.db.get_message(message_id)
        if row is None:
            return None
        return MessageModel(row, client=self)

    def messages_for_conversation_models(self, address: str, limit=None):
        """Retorna mensagens de uma conversa como Message models."""
        rows = self.db.messages_for_conversation(address, limit=limit)
        return [MessageModel(r, client=self) for r in rows]

    # ---------- envio ----------  # noqa: E303

    def request_pubkey(self, address_text):  # noqa: E301
        status, version, stream, ripe = addr_module.decode_address(
            address_text)
        if status != 'success':
            return status
        if version != 4:
            return 'unsupported'
        try:
            keys = AddressKeys.from_address(address_text)
        except Exception:
            return 'invalid'
        unsigned = objects.build_getpubkey_unsigned(
            int(time.time()) + GETPUBKEY_TTL, stream, 4, keys.tag)
        target = calculate_target(1000, 1000, len(unsigned) + 8,
                                  GETPUBKEY_TTL)
        self._pow_and_publish(
            unsigned, target,
            done_cb=lambda complete, nonce: self.net.announce_object(complete),
            dest=address_text, preview='pedido de chave pública',
            kind='getpubkey')
        return 'success'

    def _send_queued(self, to_address):
        # A12: cap por ciclo (~5) + pular se sem peers quando há muitos pendentes
        # (evita PoW em massa offline / fork-bomb). Um único pendente ainda
        # pode ser enviado direto (caso do teste TTL), por isso o skip só
        # vale quando há >1 pendente — preserva tanto o teste de capacidade
        # quanto o de TTL.
        try:
            rows = self.db.query(
                "SELECT * FROM messages WHERE to_address=? "
                "AND status='awaiting-pubkey' LIMIT 5", (to_address,))
        except Exception:
            return
        if not rows:
            return
        try:
            if self.net.established_count == 0 and len(rows) > 1:
                return
        except Exception:
            pass
        for row in rows:
            self._pow_and_publish_message(
                row['id'], row['from_address'], to_address,
                row['body'], row['encoding'], ttl=row.get('ttl'))

    @staticmethod
    def _wire_too_large(wire_body):
        from ..protocol.const import MAX_WIRE_BODY_BYTES
        try:
            return len(wire_body.encode('utf-8')) > MAX_WIRE_BODY_BYTES
        except Exception:
            return True

    def send_message(self, identity_address, to_address, subject, body,
                     encoding=BITMESSAGE_ENCODING_TRIVIAL):
        status, version, stream, ripe = addr_module.decode_address(to_address)
        if status != 'success':
            return status, 'endereço inválido'
        if version != 4:
            return 'unsupported', 'somente endereços versão 4 são suportados'
        try:
            contact_keys = AddressKeys.from_address(to_address)
        except Exception:
            return 'invalid', 'endereço inválido'
        body = body or ''
        # B2: subject nunca trafegava no wire — prefixa para não haver perda silenciosa
        wire_body = ('Subject: %s\n\n%s' % (subject, body)) if (subject or '').strip() else body
        # C3: teto único no wire (b64+overhead ≤ 200k) ANTES do PoW.
        try:
            if self._wire_too_large(wire_body):
                return 'too-large', 'mensagem grande demais para um objeto'
        except Exception:
            return 'invalid', 'corpo de mensagem inválido'
        ttl = self.get_msg_ttl()
        message_id = self.db.add_message(
            None, identity_address, to_address, subject or '', body,
            encoding, int(time.time()), 'out', 'awaiting-pubkey', ttl=ttl)
        self.ui_queue.put(('status', message_id, 'sending'))
        if to_address in self.pubkeys:
            self._pow_and_publish_message(message_id, identity_address,
                                          to_address, body, encoding, ttl=ttl)
            return 'success', None
        unsigned = objects.build_getpubkey_unsigned(
            int(time.time()) + GETPUBKEY_TTL, stream, 4, contact_keys.tag)
        target = calculate_target(1000, 1000, len(unsigned) + 8,
                                  GETPUBKEY_TTL)
        # A1: antes o PoW era descartado (sem done_cb) — agora anuncia
        self._pow_and_publish(
            unsigned, target,
            done_cb=lambda complete, nonce: self.net.announce_object(complete),
            dest=to_address, preview='pedido de chave pública',
            kind='getpubkey')
        return 'success', None

    def _fail_message_no_ack(self, message_id):
        # B3: sem ACK não envia degradado silencioso
        try:
            self.db.set_message_status(message_id, 'ack-failed')
            self.ui_queue.put(('status', message_id, 'ack-failed'))
        finally:
            with self._lock:
                self._msg_in_flight.discard(message_id)

    def _message_wire_body(self, message_id, body):
        # B2: inclui subject no wire (retry lê do DB via _send_queued)
        try:
            rows = self.db.query(
                "SELECT subject FROM messages WHERE id=?", (message_id,))
            subj = (rows[0]['subject'] if rows else '') or ''
        except Exception:
            subj = ''
        wire = ('Subject: %s\n\n%s' % (subj, body)) if subj.strip() else (body or '')
        try:
            return wire.encode('utf-8')
        except Exception:
            with self._lock:
                self._msg_in_flight.discard(message_id)
            return None

    def _finish_message_send(self, message_id, complete):
        # B1: revalida antes de anunciar (conversa pode ter sido apagada)
        try:
            rows = self.db.query(
                "SELECT status FROM messages WHERE id=?", (message_id,))
            if not rows or rows[0]['status'] not in (
                    'sending', 'awaiting-pubkey'):
                return
        except Exception:
            pass
        finally:
            with self._lock:
                self._msg_in_flight.discard(message_id)
        # A2: DB pode estar fechado no stop(); anuncia antes de gravar
        # e tolera falha de escrita sem levantar na thread de PoW.
        try:
            self.net.announce_object(complete)
        except Exception:
            pass
        try:
            self.db.set_message_status(message_id, 'sent')
        except Exception:
            return
        self.ui_queue.put(('status', message_id, 'sent'))

    def _drop_oversize_wire(self, message_id, watch):
        try:
            self.db.set_message_status(message_id, 'ack-failed')
        except Exception:
            pass
        with self._lock:
            self._msg_in_flight.discard(message_id)
            self._ack_watch.pop(watch, None)
        self.ui_queue.put(('status', message_id, 'ack-failed'))

    def _send_message_worker(self, message_id, stream, keys, pub,  # noqa: C901
                             to_address, body, encoding, expires, ripe, ttl):
        ack_packet, watch = self._build_ack_packet(stream, expires=expires)
        if not watch:
            self._fail_message_no_ack(message_id)
            return
        with self._lock:
            self._ack_watch[watch] = (message_id, expires)
            # Merge: mantém TTL (expires) + sweep de segurança (varre antigos)
            try:
                self._sweep_ack_watch_locked()
            except Exception:
                pass
        wire_bytes = self._message_wire_body(message_id, body)
        if wire_bytes is None:
            return
        # C3: revalida o teto único antes do PoW (texto pode ter crescido).
        try:
            from ..protocol.const import MAX_WIRE_BODY_BYTES
            oversize = len(wire_bytes) > MAX_WIRE_BODY_BYTES
        except Exception:
            oversize = False
        if oversize:
            self._drop_oversize_wire(message_id, watch)
            return
        unsigned = objects.build_msg_unsigned(
            expires, stream, keys, pub['encryption_public'], ripe,
            wire_bytes, encoding, ack_packet)
        target = calculate_target(
            pub['nonce_trials_per_byte'],
            pub['payload_length_extra_bytes'],
            len(unsigned) + 8, ttl)

        def done(complete, nonce):
            self._finish_message_send(message_id, complete)

        with self._lock:
            self._pow_sequencer += 1
            token = self._pow_sequencer
            stop_event = threading.Event()
        self._track_pow(token, stop_event, message_id=message_id,
                        dest=to_address, preview=self._pow_preview(body),
                        kind='msg')
        try:
            self._run_pow_and_done(
                unsigned, target, message_id=message_id, done_cb=done,
                token=token, stop_event=stop_event)
        except Exception:
            with self._lock:
                self._msg_in_flight.discard(message_id)
            raise

    def _sweep_ack_watch_locked(self):  # noqa: C901
        """Sweep interno (chamador já detém self._lock)."""
        try:
            from ..protocol.const import MSG_TTL
        except Exception:
            MSG_TTL = 4 * 24 * 3600
        now = time.time()
        dead = []
        for key, entry in list(self._ack_watch.items()):
            try:
                if not isinstance(entry, tuple):
                    dead.append(key)
                    continue
                ts = entry[1] if len(entry) >= 2 else now
                if now - ts > MSG_TTL:
                    dead.append(key)
            except Exception:
                dead.append(key)
        for key in dead:
            self._ack_watch.pop(key, None)

    def _claim_resend_slot(self, message_id):
        with self._lock:
            tries = int(self._ack_retry_counts.get(message_id, 0))
            if tries >= 3:
                return False
            self._ack_retry_counts[message_id] = tries + 1
            return True

    def _resend_without_pubkey(self, message_id, to_address):
        try:
            self.db.set_message_status(message_id, 'awaiting-pubkey')
        except Exception:
            pass
        try:
            self.request_pubkey(to_address)
        except Exception:
            pass
        return 'success', None

    def resend_message(self, message_id):
        """M5: reenvio manual de mensagem 'ack-failed'/'sending'."""
        try:
            row = self.db.get_message(message_id)
        except Exception:
            return 'error', 'mensagem não encontrada'
        if not row or row['direction'] != 'out':
            return 'error', 'mensagem não encontrada'
        if row['status'] not in ('ack-failed', 'sending', 'awaiting-pubkey'):
            return 'error', 'estado não permite reenvio (%s)' % row['status']
        to_address = row['to_address']
        if to_address not in self.pubkeys:
            if not self._claim_resend_slot(message_id):
                return 'error', 'limite de reenvios atingido'
            return self._resend_without_pubkey(message_id, to_address)
        # ADV: não consome slot se a identidade sumiu (pow retornaria
        # sem lançar e esgotaria o limite sem queimar PoW).
        if row['from_address'] not in self.identities:
            return 'error', 'identidade de origem ausente'
        if not self._claim_resend_slot(message_id):
            return 'error', 'limite de reenvios atingido'
        self._pow_and_publish_message(message_id, row['from_address'],
                                      to_address, row['body'], row['encoding'])
        return 'success', None

    def _pow_and_publish_message(self, message_id, identity_address,
                                 to_address, body, encoding, ttl=None):
        pub = self.pubkeys.get(to_address)
        if pub is None:
            return
        keys = self.identities.get(identity_address)
        if keys is None:
            return
        status, version, stream, ripe = addr_module.decode_address(to_address)
        if status != 'success':
            return
        with self._lock:
            if message_id in self._msg_in_flight:
                return
            self._msg_in_flight.add(message_id)
        try:
            self.db.set_message_status(message_id, 'sending')
        except Exception:
            pass
        ttl = self._resolve_message_ttl(message_id, ttl)
        expires = int(time.time()) + ttl
        try:
            self.db.set_message_expiry(message_id, expires)
        except Exception:
            pass
        worker = threading.Thread(target=self._send_message_worker,
                                  args=(message_id, stream, keys, pub, to_address,
                                        body, encoding, expires, ripe, ttl),
                                  daemon=True,
                                  name='msg-pow-%s' % message_id)
        worker.start()
        # A2: registra para join no stop().
        self._track_worker(worker)

    def _build_ack_packet(self, stream, expires=None, ttl=None):
        # O ACK acompanha a vida do objeto: expira junto, nunca além dele.
        now = int(time.time())
        if expires is None:
            ttl = self._clamp_ttl(
                ttl if ttl is not None else self.get_msg_ttl())
            expires = now + ttl
        else:
            expires = int(expires)
            ttl = max(300, expires - now)
        watch = os.urandom(32)
        unsigned = objects.build_ack_unsigned(expires, watch, stream)
        target = calculate_target(1000, 1000, len(unsigned) + 8, ttl)
        try:
            nonce = self._quick_pow(unsigned, target)
        except Exception:
            return b'', None
        ack_object = objects.complete_object(unsigned, nonce)
        return packets.create_packet('object', ack_object), \
            objects.ack_watch_key(ack_object)

    def _quick_pow(self, unsigned, target):
        # Strategy Pattern: delega ao PoWStrategy injetado quando disponível
        initial = initial_hash_of(unsigned)
        # Se mock injetado, usa-o para testes rápidos
        from ..crypto.pow.mock import MockPoWStrategy
        if isinstance(self.pow_strategy, MockPoWStrategy):
            return self.pow_strategy.solve(initial, target, stop_event=threading.Event())
        return PowExecutor(
            workers=1, progress_cb=None,
            stop_event=threading.Event()
        ).run(initial, target)

    def _pow_and_publish(self, unsigned, target, message_id=None,
                         done_cb=None, dest=None, preview=None, kind=None):
        with self._lock:
            self._pow_sequencer += 1
            token = self._pow_sequencer
            stop_event = threading.Event()
        self._track_pow(token, stop_event, message_id=message_id,
                        dest=dest, preview=preview, kind=kind)

        def worker():
            self._run_pow_and_done(
                unsigned, target, message_id=message_id, done_cb=done_cb,
                token=token, stop_event=stop_event)

        thread = threading.Thread(target=worker, daemon=True,
                                  name='pow-%d' % token)
        thread.start()
        self._track_worker(thread)
        return token

    def _ensure_pow_entry(self, token, stop_event, message_id):
        with self._lock:
            self._pow_stops[token] = stop_event
            meta = self._pow_meta.get(token)
            if meta is None:
                self._pow_meta[token] = {
                    'token': token,
                    'message_id': message_id,
                    'dest': None,
                    'preview': '',
                    'kind': '',
                    'started': time.time(),
                    'tried': 0,
                    'rate': 0.0,
                }
            elif message_id is not None and meta.get('message_id') is None:
                meta['message_id'] = message_id

    def _fail_pow(self, token, message_id):
        self.ui_queue.put(('pow-cancelled', token))
        if message_id is not None:
            with self._lock:
                self._msg_in_flight.discard(message_id)
        else:
            with self._lock:
                meta = self._pow_meta.get(token)
                pending = meta.get('message_id') if meta else None
            if pending is not None:
                with self._lock:
                    self._msg_in_flight.discard(pending)
        self._untrack_pow(token)

    def _run_pow_and_done(self, unsigned, target, message_id=None,
                          done_cb=None, token=None, stop_event=None):
        with self._lock:
            if token is None:
                self._pow_sequencer += 1
                token = self._pow_sequencer
            if stop_event is None:
                stop_event = threading.Event()
        self._ensure_pow_entry(token, stop_event, message_id)
        # Strategy Pattern: usa PoWStrategy injetado quando for Mock,
        # caso contrário usa Standard via PowExecutor (mantém workers dinâmico)
        from ..crypto.pow.mock import MockPoWStrategy
        use_mock = isinstance(self.pow_strategy, MockPoWStrategy)
        if use_mock:
            try:
                nonce = self.pow_strategy.solve(
                    initial_hash_of(unsigned), target,
                    progress_cb=self._pow_progress(token),
                    stop_event=stop_event,
                )
            except Exception:
                self._fail_pow(token, message_id)
                return
        else:
            executor = PowExecutor(
                workers=max(1, self.db.get_int('pow_workers', 0) or 0) or
                max(1, os.cpu_count() or 2),
                progress_cb=self._pow_progress(token),
                stop_event=stop_event)
            try:
                nonce = executor.run(initial_hash_of(unsigned), target)
            except Exception:
                self._fail_pow(token, message_id)
                return
        complete = objects.complete_object(unsigned, nonce)
        self._untrack_pow(token)
        if done_cb is not None:
            done_cb(complete, nonce)

    def _pow_progress(self, token):
        def progress(tried, rate):
            self._note_pow_progress(token, tried, rate)
            self.ui_queue.put(('pow-progress', token, tried, rate))
        return progress

    def cancel_pow(self, token):
        with self._lock:
            event = self._pow_stops.get(token)
        if event is not None:
            event.set()

    @staticmethod
    def _pow_preview(body, limit=40):
        try:
            text = str(body or '').replace('\n', ' ').strip()
        except Exception:
            return ''
        if len(text) <= limit:
            return text
        if limit <= 1:
            return '…'
        return text[:limit - 1] + '…'

    def _track_pow(self, token, stop_event, message_id=None,
                   dest=None, preview=None, kind=None):
        with self._lock:
            self._pow_stops[token] = stop_event
            current = self._pow_meta.get(token)
            if current is None:
                self._pow_meta[token] = {
                    'token': token,
                    'message_id': message_id,
                    'dest': dest,
                    'preview': preview or '',
                    'kind': kind or '',
                    'started': time.time(),
                    'tried': 0,
                    'rate': 0.0,
                }
                return
            if message_id is not None:
                current['message_id'] = message_id
            if dest is not None:
                current['dest'] = dest
            if preview:
                current['preview'] = preview
            if kind:
                current['kind'] = kind

    def _untrack_pow(self, token):
        with self._lock:
            self._pow_stops.pop(token, None)
            self._pow_meta.pop(token, None)

    def _note_pow_progress(self, token, tried, rate):
        with self._lock:
            meta = self._pow_meta.get(token)
            if meta is not None:
                meta['tried'] = tried
                meta['rate'] = rate

    def cancel_all_pow(self):
        with self._lock:
            events = list(self._pow_stops.values())
        for event in events:
            try:
                event.set()
            except Exception:
                pass

    def list_pow_tasks(self):
        now = time.time()
        with self._lock:
            items = list(self._pow_meta.values())
            stops = dict(self._pow_stops)
        tasks = []
        for meta in items:
            tasks.append(self._describe_pow_task(meta, stops, now))
        tasks.sort(key=lambda item: item['token'] or 0)
        return tasks

    @staticmethod
    def _describe_pow_task(meta, stops, now):
        token = meta.get('token')
        event = stops.get(token)
        try:
            cancelling = bool(event is not None and event.is_set())
        except Exception:
            cancelling = False
        started = meta.get('started') or now
        return {
            'token': token,
            'message_id': meta.get('message_id'),
            'dest': meta.get('dest'),
            'preview': meta.get('preview') or '',
            'kind': meta.get('kind') or '',
            'started': started,
            'elapsed': max(0.0, now - started),
            'tried': meta.get('tried') or 0,
            'rate': meta.get('rate') or 0.0,
            'cancelling': cancelling,
        }

    def broadcast(self, identity_address, body,
                  encoding=BITMESSAGE_ENCODING_TRIVIAL):
        keys = self.identities.get(identity_address)
        if keys is None:
            return 'error'
        try:
            if self._wire_too_large(body or ''):
                return 'too-large'
        except Exception:
            return 'error'
        ttl = self.get_msg_ttl()
        expires = int(time.time()) + ttl
        unsigned = objects.build_broadcast_unsigned(
            expires, keys.stream, keys, body.encode('utf-8'), encoding)
        target = calculate_target(
            keys.nonce_trials_per_byte,
            keys.payload_length_extra_bytes,
            len(unsigned) + 8, ttl)

        def done(complete, nonce):
            self.net.announce_object(complete)
            self.db.add_message(
                None, identity_address, identity_address, '', body, encoding,
                int(time.time()), 'out', 'sent', keys.stream,
                ttl=ttl, expires=expires)
            self.ui_queue.put(('broadcast-sent', identity_address))

        self._pow_and_publish(
            unsigned, target, done_cb=done, dest=identity_address,
            preview=self._pow_preview(body), kind='broadcast')
        return 'success'

    def _derive_chan_keys(self, address, name, stream):
        try:
            derived = chan_keys_from_name(name, stream)
        except Exception:
            return None
        return derived if derived.address == address else None

    def _chan_posting_keys(self, address, name=None):
        keys = self.identities.get(address)
        if keys is not None:
            return keys
        status, _version, stream, _ripe = addr_module.decode_address(address)
        if status != 'success':
            return None
        if name is not None:
            candidate = (name or '').strip()
            if not candidate:
                return None
            return self._derive_chan_keys(address, candidate, stream)
        row = self.db.get_subscription(address)
        stored = (row.get('name') if row else '') or ''
        if not stored.strip():
            return None
        return self._derive_chan_keys(address, stored.strip(), stream)

    def broadcast_chan(self, address, body,
                       encoding=BITMESSAGE_ENCODING_TRIVIAL, name=None):
        try:
            if self._wire_too_large(body or ''):
                return 'too-large', 'mensagem grande demais para um objeto'
        except Exception:
            return 'error', 'corpo inválido'
        explicit = name is not None
        keys = self._chan_posting_keys(address, name)
        if keys is None:
            if explicit:
                return 'mismatch', ('esse nome não gera este canal; '
                                    'confira a digitação')
            return 'noname', ('para publicar é preciso o nome do canal; '
                              'só quem tem o nome pode postar')
        if explicit:
            try:
                self.db.set_subscription_name(address, (name or '').strip())
            except Exception:
                pass
        ttl = self.get_msg_ttl()
        expires = int(time.time()) + ttl
        unsigned = objects.build_broadcast_unsigned(
            expires, keys.stream, keys, body.encode('utf-8'), encoding)
        target = calculate_target(
            keys.nonce_trials_per_byte,
            keys.payload_length_extra_bytes,
            len(unsigned) + 8, ttl)

        def done(complete, nonce):
            self.net.announce_object(complete)
            self.db.add_message(
                None, address, address, '', body, encoding,
                int(time.time()), 'out', 'sent', keys.stream,
                ttl=ttl, expires=expires)
            self.ui_queue.put(('broadcast-sent', address))

        self._pow_and_publish(
            unsigned, target, done_cb=done, dest=address,
            preview=self._pow_preview(body), kind='chan')
        return 'success', None

    # ---------- publicação de chave pública ----------

    def _publish_pubkey(self, keys, stream=None, force=False):
        now = int(time.time())
        unsigned = objects.build_pubkey_unsigned(
            now + PUBKEY_TTL, stream or keys.stream, keys)
        target = calculate_target(
            keys.nonce_trials_per_byte,
            keys.payload_length_extra_bytes,
            len(unsigned) + 8, PUBKEY_TTL)

        def done(complete, nonce):
            self.net.announce_object(complete)
            try:
                self.db.store_object(
                    double_sha512(complete)[:32], complete,
                    OBJECT_PUBKEY, 4, stream or keys.stream,
                    now + PUBKEY_TTL)
            except Exception:
                pass
            self._log('rede', 'pubkey publicada na rede')

        self._pow_and_publish(
            unsigned, target, done_cb=done, dest=getattr(keys, 'address', None),
            preview='publicação de chave pública', kind='pubkey')

    def _reannounce_loop(self):
        self._reannounce_pubkeys_once()
        while self.started:
            for _ in range(24 * 60):
                if not self.started:
                    return
                time.sleep(60)
            if not self.started:
                return
            try:
                self._reannounce_pubkeys_once()
            except Exception as exc:
                self._log('rede', 'reannounce: %r' % exc)

    def _scan_pubkey_rows(self, rows, keys, address):
        for row in rows:
            try:
                raw = bytes(row['raw'])
            except Exception:
                continue
            try:
                incoming = objects.process_pubkey(raw, keys)
            except Exception:
                continue
            if incoming is None:
                continue
            try:
                self.net.announce_object(raw)
            except Exception:
                pass
            self._log('rede', 'pubkey de %s reanunciada' % address[:18])
            break

    def _maybe_reannounce_identity(self, identity, now):
        address = identity['address']
        try:
            keys = AddressKeys.from_address(address)
        except Exception:
            return
        try:
            rows = self.db.query(
                'SELECT raw FROM objects WHERE type=1 AND version=4 AND '
                'expires > ? ORDER BY expires DESC LIMIT 5',
                (now,))
        except Exception:
            return
        self._scan_pubkey_rows(rows, keys, address)

    def _reannounce_pubkeys_once(self):
        now = int(time.time())
        for identity in self.db.all_identities(enabled_only=False):
            if not self.started:
                return
            self._maybe_reannounce_identity(identity, now)

    def _reannounce_pubkeys(self):
        # compat: testes antigos chamam direto (1-shot)
        return self._reannounce_pubkeys_once()

    def _send_due_scheduled(self):
        pending = self.db.get_pending_scheduled()
        for msg in pending:
            if not self.started:
                return
            try:
                self._send_one_scheduled(msg)
            except Exception as exc:
                self._log('agendada', f'erro ao enviar: {exc}')

    def _drop_scheduled(self, msg_id):
        try:
            self.db.mark_scheduled_sent(msg_id)
        except Exception:
            pass

    def _deliver_scheduled(self, msg, is_channel, identity, to_addr, body):
        try:
            if is_channel:
                status, error = self.broadcast_chan(to_addr, body or '')
            else:
                status, error = self.send_message(
                    identity, to_addr, '', body or '')
        except Exception as exc:
            self._log('agendada', 'erro ao enviar: %s' % exc)
            return
        if status == 'success':
            self._drop_scheduled(msg['id'])
            self._log('agendada', 'mensagem para %s enviada'
                      % str(to_addr)[:18])
            return
        self._log('agendada', 'falha (%s): %s'
                  % (status, error or 'erro'))
        if status in ('too-large', 'invalid', 'unsupported', 'mismatch',
                      'noname', 'error'):
            self._drop_scheduled(msg['id'])

    def _send_one_scheduled(self, msg):
        # A4: só marca sent em success; identidade ausente → erro+log
        # (descarta para não virar pendente eterno); canal via
        # broadcast_chan (antes virava DM via send_message).
        identity = msg['identity_address']
        to_addr = msg['to_address']
        body = msg['body']
        if identity not in self.identities:
            self._log('agendada', 'identidade ausente; descartando '
                      'agendada %s' % msg['id'])
            self._drop_scheduled(msg['id'])
            return
        try:
            is_channel = self.db.get_subscription(to_addr) is not None
        except Exception:
            is_channel = False
        self._deliver_scheduled(msg, is_channel, identity, to_addr, body)

    def _scheduled_sender_loop(self):
        """Background thread to send scheduled messages."""
        while self.started:
            try:
                self._send_due_scheduled()
            except Exception as exc:
                self._log('agendada', f'erro no loop: {exc}')
            # Check every 30 seconds
            for _ in range(30):
                if not self.started:
                    return
                time.sleep(1)


def _decode_body(encoding, message):
    if encoding == 0:
        return ''
    if isinstance(message, bytes):
        return message.decode('utf-8', 'replace')
    return message
