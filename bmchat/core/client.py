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
from ..protocol import address as addr_module
from ..protocol import objects
from ..protocol import packets
from ..protocol.const import (
    OBJECT_GETPUBKEY, OBJECT_PUBKEY, OBJECT_MSG, OBJECT_BROADCAST,
    MSG_TTL, GETPUBKEY_TTL, PUBKEY_TTL,
    BITMESSAGE_ENCODING_TRIVIAL,
)
from ..util.hashing import double_sha512, sha512
from ..net.manager import NetworkManager
from .database import Database


class Client:

    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.db = Database(data_dir)
        self.ui_queue = __import__('queue').Queue()
        self.identities = {}
        self.pubkeys = {}
        self._pow_stops = {}
        self._pow_sequencer = 0
        self._ack_watch = {}
        self._msg_in_flight = set()
        self._log_lines = collections.deque(maxlen=200)
        self._lock = threading.RLock()
        self.net = NetworkManager(
            data_dir, self.db, on_object=self._on_object, on_log=self._log)
        self.started = False

    # ------------------------------------------------------------------

    def start(self):
        self._load_identities()
        self._load_pubkeys()
        streams = self._participating_streams()
        self.net.start(streams)
        self.started = True
        retry = threading.Thread(target=self._retry_loop, daemon=True,
                                 name='client-retry')
        retry.start()
        reannounce = threading.Thread(target=self._reannounce_pubkeys,
                                      daemon=True, name='client-reannounce')
        reannounce.start()

    def stop(self):
        self.started = False
        for event in self._pow_stops.values():
            event.set()
        self.net.stop()
        self.db.close()

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

    def _retry_awaiting(self):
        # B7: não queima PoW offline + limite de paralelismo
        try:
            established = sum(
                1 for c in list(self.net.connections.values())
                if getattr(c, 'established', False))
        except Exception:
            established = 0
        if established == 0:
            return
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
            for connection in list(self.net.connections.values()):
                connection.their_streams = self.net.streams

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
        return keys.address

    def create_channel(self, name, stream=1, label=None):
        name = (name or '').strip()
        if not name:
            return None
        try:
            stream = int(stream)
        except (TypeError, ValueError):
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
        return keys.address

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
                continue
            if keys.address != section:
                result['errors'] += 1
                continue
            if keys.address in self.identities:
                result['skipped'] += 1
                continue
            label = parser.get(
                section, 'label', fallback=keys.address).strip() or \
                keys.address
            chan = parser.get(
                section, 'chan', fallback='false').strip().lower() == 'true'
            chan_label = parser.get(section, 'chan_label', fallback='').strip()
            try:
                noncetrials = int(parser.get(
                    section, 'noncetrialsperbyte', fallback='1000'))
                extrabytes = int(parser.get(
                    section, 'payloadlengthextrabytes', fallback='1000'))
            except ValueError:
                noncetrials, extrabytes = 1000, 1000
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
        if result['imported']:
            self._refresh_streams()
            self.ui_queue.put(('identity-created', '', ''))
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
        self.ui_queue.put(('contact-added', address_text, ''))

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

    def _maybe_mark_ack(self, parsed):
        if parsed.object_type != OBJECT_MSG or parsed.version != 1:
            return
        try:
            key = parsed.raw[16:]
            message_id = self._ack_watch.get(key)
        except Exception:
            return
        if message_id:
            self.db.set_message_status(message_id, 'ackreceived')
            self._log('rede', 'confirmação (ACK) recebida: mensagem entregue')
            self.ui_queue.put(('ack', message_id))

    def _on_getpubkey(self, parsed):
        tag = parsed.data[:32]
        for address, keys in list(self.identities.items()):
            if keys.tag == tag:
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
        identities = list(self.identities.values())
        incoming = objects.process_msg(raw, identities)
        if incoming is None:
            return
        if self.db.message_exists(incoming.inventory_hash):
            return
        body = _decode_body(incoming.encoding, incoming.message)
        self.db.add_message(
            incoming.inventory_hash, incoming.sender_address,
            incoming.to_identity.address, '', body,
            incoming.encoding, int(time.time()), 'in', 'received')
        self._log('rede', 'mensagem recebida de %s' %
                  incoming.sender_address[:18])
        self.ui_queue.put(('message', incoming.sender_address,
                           incoming.to_identity.address, body, parsed.expires))
        if incoming.ack_data:
            self._relay_ack(incoming.ack_data)

    def _relay_ack(self, packet):
        def worker():
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
        threading.Thread(target=worker, daemon=True).start()

    def _on_broadcast(self, parsed, raw):
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
        if not subscriptions:
            return
        incoming = objects.process_broadcast(raw, subscriptions)
        if incoming is None:
            return
        if self.db.message_exists(incoming.inventory_hash):
            return
        channel_address = reverse.get(parsed.data[:32])
        if channel_address is None:
            return
        body = _decode_body(incoming.encoding, incoming.message)
        self.db.add_message(
            incoming.inventory_hash, incoming.address, channel_address,
            '', body, incoming.encoding, int(time.time()), 'in', 'received')
        self._log('rede', 'postagem recebida no canal %s' %
                  str(channel_address)[:18])
        self.ui_queue.put(('broadcast', channel_address, incoming.address,
                           body, parsed.expires))

    # ---------- envio ----------

    def request_pubkey(self, address_text):
        status, version, stream, ripe = addr_module.decode_address(
            address_text)
        if status != 'success':
            return status
        keys = AddressKeys.from_address(address_text)
        unsigned = objects.build_getpubkey_unsigned(
            int(time.time()) + GETPUBKEY_TTL, stream, 4, keys.tag)
        target = calculate_target(1000, 1000, len(unsigned) + 8,
                                  GETPUBKEY_TTL)
        self._pow_and_publish(
            unsigned, target,
            done_cb=lambda complete, nonce: self.net.announce_object(complete))
        return 'success'

    def _send_queued(self, to_address):
        rows = self.db.query(
            "SELECT * FROM messages WHERE to_address=? "
            "AND status='awaiting-pubkey'", (to_address,))
        for row in rows:
            self._pow_and_publish_message(
                row['id'], row['from_address'], to_address,
                row['body'], row['encoding'])

    def send_message(self, identity_address, to_address, subject, body,
                      encoding=BITMESSAGE_ENCODING_TRIVIAL):
        from ..protocol.const import MAX_OBJECT_LENGTH
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
        try:
            if len(wire_body.encode('utf-8')) + 1000 > MAX_OBJECT_LENGTH:
                return 'too-large', 'mensagem grande demais para um objeto'
        except Exception:
            return 'invalid', 'corpo de mensagem inválido'
        message_id = self.db.add_message(
            None, identity_address, to_address, subject or '', body,
            encoding, int(time.time()), 'out', 'awaiting-pubkey')
        self.ui_queue.put(('status', message_id, 'sending'))
        if to_address in self.pubkeys:
            self._pow_and_publish_message(message_id, identity_address,
                                          to_address, body, encoding)
            return 'success', None
        unsigned = objects.build_getpubkey_unsigned(
            int(time.time()) + GETPUBKEY_TTL, stream, 4, contact_keys.tag)
        target = calculate_target(1000, 1000, len(unsigned) + 8,
                                  GETPUBKEY_TTL)
        # A1: antes o PoW era descartado (sem done_cb) — agora anuncia
        self._pow_and_publish(
            unsigned, target,
            done_cb=lambda complete, nonce: self.net.announce_object(complete))
        return 'success', None

    def _pow_and_publish_message(self, message_id, identity_address,
                                  to_address, body, encoding):
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
        expires = int(time.time()) + MSG_TTL

        def worker():
            ack_packet, watch = self._build_ack_packet(stream)
            if not watch:
                # B3: sem ACK não envia degradado silencioso
                try:
                    self.db.set_message_status(message_id, 'ack-failed')
                    self.ui_queue.put(('status', message_id, 'ack-failed'))
                finally:
                    with self._lock:
                        self._msg_in_flight.discard(message_id)
                return
            with self._lock:
                self._ack_watch[watch] = message_id
            # B2: inclui subject no wire (retry lê do DB via _send_queued)
            try:
                rows = self.db.query(
                    "SELECT subject FROM messages WHERE id=?", (message_id,))
                subj = (rows[0]['subject'] if rows else '') or ''
            except Exception:
                subj = ''
            wire = ('Subject: %s\n\n%s' % (subj, body)) if subj.strip() else (body or '')
            try:
                wire_bytes = wire.encode('utf-8')
            except Exception:
                with self._lock:
                    self._msg_in_flight.discard(message_id)
                return
            unsigned = objects.build_msg_unsigned(
                expires, stream, keys, pub['encryption_public'], ripe,
                wire_bytes, encoding, ack_packet)
            target = calculate_target(
                pub['nonce_trials_per_byte'],
                pub['payload_length_extra_bytes'],
                len(unsigned) + 8, MSG_TTL)

            def done(complete, nonce):
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
                self.net.announce_object(complete)
                self.db.set_message_status(message_id, 'sent')
                self.ui_queue.put(('status', message_id, 'sent'))

            try:
                self._run_pow_and_done(
                    unsigned, target, message_id=message_id, done_cb=done)
            except Exception:
                with self._lock:
                    self._msg_in_flight.discard(message_id)
                raise

        threading.Thread(target=worker, daemon=True,
                         name='msg-pow-%s' % message_id).start()

    def _build_ack_packet(self, stream):
        ack_ttl = 28 * 24 * 3600 if MSG_TTL >= 28 * 24 * 3600 else \
            (7 * 24 * 3600 if MSG_TTL >= 7 * 24 * 3600 else 24 * 3600)
        ack_ttl = int(ack_ttl + (os.urandom(1)[0] - 128) * 5)
        expires = int(time.time()) + ack_ttl
        watch = os.urandom(32)
        unsigned = objects.build_ack_unsigned(expires, watch, stream)
        target = calculate_target(1000, 1000, len(unsigned) + 8, ack_ttl)
        try:
            nonce = self._quick_pow(unsigned, target)
        except Exception:
            return b'', None
        ack_object = objects.complete_object(unsigned, nonce)
        return packets.create_packet('object', ack_object), \
            objects.ack_watch_key(ack_object)

    def _quick_pow(self, unsigned, target):
        return PowExecutor(
            workers=1, progress_cb=None,
            stop_event=threading.Event()
        ).run(initial_hash_of(unsigned), target)

    def _pow_and_publish(self, unsigned, target, message_id=None,
                         done_cb=None):
        with self._lock:
            self._pow_sequencer += 1
            token = self._pow_sequencer
            stop_event = threading.Event()
            self._pow_stops[token] = stop_event

        def worker():
            self._run_pow_and_done(
                unsigned, target, message_id=message_id, done_cb=done_cb,
                token=token, stop_event=stop_event)

        threading.Thread(target=worker, daemon=True,
                         name='pow-%d' % token).start()

    def _run_pow_and_done(self, unsigned, target, message_id=None,
                          done_cb=None, token=None, stop_event=None):
        with self._lock:
            if token is None:
                self._pow_sequencer += 1
                token = self._pow_sequencer
            if stop_event is None:
                stop_event = threading.Event()
            self._pow_stops[token] = stop_event
        executor = PowExecutor(
            workers=max(1, self.db.get_int('pow_workers', 0) or 0) or
            max(1, os.cpu_count() or 2),
            progress_cb=self._pow_progress(token),
            stop_event=stop_event)
        try:
            nonce = executor.run(initial_hash_of(unsigned), target)
        except Exception:
            self.ui_queue.put(('pow-cancelled', token))
            with self._lock:
                self._pow_stops.pop(token, None)
            return
        complete = objects.complete_object(unsigned, nonce)
        with self._lock:
            self._pow_stops.pop(token, None)
        if done_cb is not None:
            done_cb(complete, nonce)

    def _pow_progress(self, token):
        def progress(tried, rate):
            self.ui_queue.put(('pow-progress', token, tried, rate))
        return progress

    def cancel_pow(self, token):
        with self._lock:
            event = self._pow_stops.get(token)
        if event is not None:
            event.set()

    def broadcast(self, identity_address, body,
                   encoding=BITMESSAGE_ENCODING_TRIVIAL):
        from ..protocol.const import MAX_OBJECT_LENGTH
        keys = self.identities.get(identity_address)
        if keys is None:
            return 'error'
        try:
            if len((body or '').encode('utf-8')) + 1000 > MAX_OBJECT_LENGTH:
                return 'too-large'
        except Exception:
            return 'error'
        expires = int(time.time()) + MSG_TTL
        unsigned = objects.build_broadcast_unsigned(
            expires, keys.stream, keys, body.encode('utf-8'), encoding)
        target = calculate_target(
            keys.nonce_trials_per_byte,
            keys.payload_length_extra_bytes,
            len(unsigned) + 8, MSG_TTL)

        def done(complete, nonce):
            self.net.announce_object(complete)
            self.db.add_message(
                None, identity_address, identity_address, '', body, encoding,
                int(time.time()), 'out', 'sent', keys.stream)
            self.ui_queue.put(('broadcast-sent', identity_address))

        self._pow_and_publish(unsigned, target, done_cb=done)
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
        from ..protocol.const import MAX_OBJECT_LENGTH
        try:
            if len((body or '').encode('utf-8')) + 1000 > MAX_OBJECT_LENGTH:
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
        expires = int(time.time()) + MSG_TTL
        unsigned = objects.build_broadcast_unsigned(
            expires, keys.stream, keys, body.encode('utf-8'), encoding)
        target = calculate_target(
            keys.nonce_trials_per_byte,
            keys.payload_length_extra_bytes,
            len(unsigned) + 8, MSG_TTL)

        def done(complete, nonce):
            self.net.announce_object(complete)
            self.db.add_message(
                None, address, address, '', body, encoding,
                int(time.time()), 'out', 'sent', keys.stream)
            self.ui_queue.put(('broadcast-sent', address))

        self._pow_and_publish(unsigned, target, done_cb=done)
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

        self._pow_and_publish(unsigned, target, done_cb=done)

    def _reannounce_pubkeys(self):
        try:
            rows = self.db.query(
                'SELECT raw FROM objects WHERE type=1 AND version=4 AND '
                'expires > ? ORDER BY expires DESC LIMIT 200',
                (int(time.time()),))
        except Exception:
            return
        for identity in self.db.all_identities(enabled_only=False):
            address = identity['address']
            try:
                keys = AddressKeys.from_address(address)
            except Exception:
                continue
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
                self.net.announce_object(raw)
                self._log('rede', 'pubkey de %s reanunciada' % address[:18])
                break


def _decode_body(encoding, message):
    if encoding == 0:
        return ''
    if isinstance(message, bytes):
        return message.decode('utf-8', 'replace')
    return message