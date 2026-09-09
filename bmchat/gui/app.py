import datetime
import os
import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog
from tkinter import font as tkfont

from . import dialogs
from .theme import get_theme, Theme
from .tooltip import ToolTip
from .notification import notify
from .. import SUPPORT_ADDRESS, SUPPORT_LABEL
from ..core.client import Client
from .commands import CommandHistory, SendMessageCommand, DeleteContactCommand, BackupKeysCommand
from ..protocol.const import (
    MSG_TTL_DEFAULT, MSG_TTL_MAX, MSG_TTL_MIN, MSG_TTL_PRESETS,
    format_ttl_pt,
)
from ..crypto.encrypted_db import (
    is_encrypted, export_encrypted_backup, import_encrypted_backup,
    change_password
)
from ..version import __version__ as BMCHAT_VERSION
from ..net.proxy import (
    ProxyProfile, DARKNET_PRESETS,
)

# Default theme (can be switched at runtime)
_current_theme_name = 'light'
_theme = get_theme(_current_theme_name)


def get_theme_colors() -> Theme:
    """Get current theme colors."""
    return _theme


def set_theme(name: str) -> None:
    """Switch theme globally."""
    global _theme, _current_theme_name
    _current_theme_name = name
    _theme = get_theme(name)


# Backward-compatible color constants (read from current theme)
def _c(name: str) -> str:
    return getattr(_theme, name)


# These will be updated when theme changes
HEADER_BG = _c('header_bg')
HEADER_BG_DARK = _c('header_bg_hover')
HEADER_FG = _c('header_fg')
HEADER_DIM = _c('header_dim')
PANEL_BG = _c('panel_bg')
ROW_HOVER = _c('row_hover')
ROW_SELECTED = _c('row_selected')
LINE = _c('divider')
TEXT_INK = _c('text_primary')
TEXT_GRAY = _c('text_secondary')
TIME_GRAY = _c('text_muted')
CHAT_BG = _c('chat_bg')
DOODLE = _c('doodle')
BUBBLE_IN = _c('bubble_in')
BUBBLE_OUT = _c('bubble_out')
BADGE_BG = _c('unread_badge')
FAB_BG = _c('accent')
READ_BLUE = _c('info')
DATE_BG = _c('border')
INPUT_ICON = _c('text_muted')

SENDER_COLORS = _theme.sender_colors

ROW_H = 68
AVATAR_R = 22
PAD_X = 12

SPACING_XS = 4
SPACING_SM = 8
SPACING_MD = 12
SPACING_LG = 16
SPACING_XL = 24

RADIUS_SM = 4
RADIUS_MD = 8
RADIUS_LG = 12
RADIUS_FULL = 999

# CVE-2026-25990/CVE-2026-40192/CVE-2026-42311/CVE-2026-59204: prévia de
# anexo só decodifica formatos comuns de foto. PSD/FITS/JPEG2000/etc.
# vindos de peer caem no ícone de arquivo (sem Image.open/load nesses
# decoders). Pillow>=12.3.0 no requirements.txt corrige as CVEs; isto é
# defesa em profundidade para quem rodar com Pillow antigo.
ALLOWED_PREVIEW_FORMATS = frozenset({'PNG', 'JPEG', 'GIF', 'BMP', 'WEBP'})

BACKUP_WARNING = (
    'ATENÇÃO — CHAVES PRIVADAS da identidade\n%s\n\n'
    '• Salve-as em um lugar SEGURO (papel, gerenciador de senhas ou '
    'pendrive offline).\n'
    '• NUNCA compartilhe: quem tiver essas chaves controla a sua '
    'identidade e lê as suas mensagens.\n'
    '• Se você PERDER essas chaves e perder este dispositivo, é '
    'IMPOSSÍVEL recuperar a identidade e as mensagens — não existe '
    '"esqueci minha senha" no Bitmessage.\n\n'
    'Deseja ver as chaves agora?')


def _fmt_bytes(count):
    try:
        count = int(count)
    except (TypeError, ValueError):
        return '0 B'
    for unit in ('B', 'KB', 'MB', 'GB'):
        if count < 1024 or unit == 'GB':
            return '%d %s' % (count, unit) if unit == 'B' else \
                '%.1f %s' % (count, unit)
        count /= 1024.0
    return '%d B' % count


def _fmt_uptime(seconds):
    seconds = max(0, int(seconds or 0))
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    if days:
        return '%dd %02d:%02d:%02d' % (days, hours, minutes, seconds)
    return '%02d:%02d:%02d' % (hours, minutes, seconds)


def _get_update_flag(obj, name, default=False):
    """M9: leitura de flag de update sob lock (tolera objeto sem lock)."""
    try:
        lock = getattr(obj, '_update_lock', None)
        if lock is None:
            return getattr(obj, name, default)
        with lock:
            return getattr(obj, name, default)
    except Exception:
        return getattr(obj, name, default)


def _set_update_flag(obj, name, value):
    """M9: escrita de flag de update sob lock (tolera objeto sem lock)."""
    try:
        lock = getattr(obj, '_update_lock', None)
        if lock is None:
            setattr(obj, name, value)
            return
        with lock:
            setattr(obj, name, value)
    except Exception:
        try:
            setattr(obj, name, value)
        except Exception:
            pass


def _report_identities(client, lines):
    try:
        identities = list(client.identities.keys())
    except Exception:
        identities = []
    lines.append('identidades: %d' % len(identities))
    for address in identities:
        lines.append('  - %s' % address)
    try:
        contacts = client.db.all_contacts()
    except Exception:
        contacts = []
    lines.append('contatos: %d' % len(contacts))


def _report_pending(client, lines):
    try:
        awaiting = client.db.query(
            "SELECT to_address, COUNT(*) AS n, MIN(timestamp) AS oldest "
            "FROM messages WHERE direction='out' AND "
            "status='awaiting-pubkey' GROUP BY to_address")
    except Exception:
        awaiting = []
    lines.append('pendentes (aguardando chave): %d conversa(s)'
                 % len(awaiting))
    for row in awaiting:
        try:
            age = int(time.time()) - int(row['oldest'] or 0)
        except Exception:
            age = 0
        lines.append('  - %s: %s msg(s), mais antiga ha %s' % (
            row['to_address'], row['n'], _fmt_uptime(age)))


def _report_states(client, lines):
    try:
        states = client.db.query(
            'SELECT direction, status, COUNT(*) AS n FROM messages '
            'GROUP BY direction, status')
    except Exception:
        states = []
    for row in states:
        lines.append('  mensagens %s/%s: %s' % (
            row['direction'], row['status'], row['n']))
    try:
        unread = client.db.unread_count()
    except Exception:
        unread = 0
    lines.append('nao lidas: %d' % unread)


def _report_config(client, lines):
    for key, default in (('connect_timeout', 30), ('recv_timeout', 30),
                         ('max_connections', 8),
                         ('maintenance_interval', 5), ('pow_workers', 0)):
        try:
            value = client.db.get_setting(key, default)
        except Exception:
            value = default
        lines.append('%s: %s' % (key, value))
    try:
        active = len(client._pow_stops)
    except Exception:
        active = 0
    lines.append('PoW ativos: %d' % active)


def _report_recent_logs(client, lines):
    try:
        logs = client.recent_logs(50)
    except Exception:
        logs = []
    lines.extend(logs or ['(vazio)'])


def _build_support_report(client):
    import platform
    try:
        snap = client.net.snapshot()
    except Exception:
        snap = None
    lines = [
        'DIAGNOSTICO BMCHAT (triagem de suporte)',
        'Gerado em: %s' % datetime.datetime.now().strftime('%d/%m/%Y %H:%M'),
        'App: bmchat %s' % BMCHAT_VERSION,
        'Sistema: %s | Python: %s' % (
            platform.platform(), platform.python_version()),
        '',
        '== Rede ==',
        _diagnostics_report(snap) if snap else '(rede indisponivel)',
        '',
        '== Conta e conversas ==',
    ]
    _report_identities(client, lines)
    _report_pending(client, lines)
    _report_states(client, lines)
    lines.append('')
    lines.append('== Config ==')
    _report_config(client, lines)
    lines.append('')
    lines.append('== Log recente ==')
    _report_recent_logs(client, lines)
    lines.append('')
    lines.append('NAO incluido: chaves privadas, conteudo das mensagens.')
    return '\n'.join(lines)


def _snap_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


def _snap_timeouts(snapshot):
    timeouts = snapshot.get('timeouts') or {}
    return (_snap_int(timeouts.get('handshake', 20), 20),
            _snap_int(timeouts.get('silent', 60), 60))


def _state_line(snapshot, established, stats):
    """Estado honesto: distingue "procurando" de "parado" (0 invs)."""
    state = snapshot.get('net_state')
    handshake, silent = _snap_timeouts(snapshot)
    invs = _snap_int(stats.get('invs', 0))
    pending = _snap_int(snapshot.get('pending_getdata', 0))
    uptime = _fmt_uptime(snapshot.get('uptime', 0))
    if state == 'parado':
        return 'Estado: rede parada.'
    if state == 'procurando-pares':
        return ('Estado: procurando pares… (nenhuma conexão; girando a '
                'lista e re-consultando as sementes DNS)')
    if state == 'negociando':
        return ('Estado: negociando com %d par(es)… (sem version/verack '
                'há ~%ds o handshake fecha e tenta outro)'
                % (snapshot['connection_count'], handshake))
    if state == 'aguardando-inv':
        return ('Estado: %d estabelecida(s), aguardando inventário '
                '(0 invs em %s; par mudo há ~%ds é desconectado)'
                % (established, uptime, silent))
    if state == 'sincronizando':
        return 'Estado: sincronizando: %d objeto(s) pendente(s)…' % pending
    if invs == 0 and not snapshot.get('inventory'):
        return ('Estado: conectado, mas nenhum inventário chegou ainda '
                '(0 invs em %s).' % uptime)
    return 'Estado: conectado (%d estabelecida(s)).' % established


def _conn_extra(conn, snapshot):
    """Anotação por par: handshake há Ns / silencioso há Ns."""
    handshake, silent = _snap_timeouts(snapshot)
    if not conn['established']:
        age = _snap_int(conn.get('handshake_for', conn['age']), conn['age'])
        return ', handshake há %ds (fecha em ~%ds sem resposta)' % (
            age, handshake)
    if not conn.get('has_useful', False):
        quiet = _snap_int(conn.get('silent_for', conn['age']), conn['age'])
        return (', silencioso há %ds (sem addr/inv/objeto; '
                'evicção em ~%ds)' % (quiet, silent))
    return ''


def _search_counts(snap):
    """(tentativas, conhecidos, ignorados) p/ o status de procura."""
    try:
        attempts = int((snap.get('stats') or {}).get('dial_attempts', 0))
    except Exception:
        attempts = 0
    try:
        known = int(snap.get('peers_stored', 0))
    except Exception:
        known = 0
    try:
        ignored = int(snap.get('peers_backoff', 0))
    except Exception:
        ignored = 0
    return attempts, known, ignored


def _status_state_part(snap, established):
    """Trecho honesto da barra de status ('' = nada a acrescentar)."""
    resync = snap.get('resync') or {}
    if resync.get('active'):
        return ('Re-sync: %d pendentes (há %s; pode levar minutos)'
                % (_snap_int(resync.get('pending', 0)),
                   _fmt_uptime(resync.get('elapsed', 0))))
    if not snap.get('running', True):
        return 'rede parada'
    if established == 0 and snap['connection_count'] == 0:
        attempts, known, ignored = _search_counts(snap)
        return ('procurando pares: %d tentativa(s), %d conhecido(s), '
                '%d ignorado(s) por falha recente…'
                % (attempts, known, ignored))
    if established == 0:
        return 'negociando…'
    invs = _snap_int((snap.get('stats') or {}).get('invs', 0))
    if invs == 0 and not snap.get('inventory'):
        return 'aguardando inventário… (0 invs)'
    if _snap_int(snap.get('pending_getdata', 0)) > 0:
        return 'sincronizando: %d pendente(s)' % _snap_int(
            snap.get('pending_getdata', 0))
    return ''


def _diagnostics_report(snapshot):
    established = sum(1 for c in snapshot['connections'] if c['established'])
    stats = snapshot.get('stats') or {}
    up_bytes = sum(c['bytes_sent'] for c in snapshot['connections'])
    down_bytes = sum(c['bytes_received'] for c in snapshot['connections'])
    lines = [
        'Proxy: %s' % snapshot['proxy'],
        'Streams: %s' % (', '.join(str(s) for s in snapshot['streams'])
                         or '—'),
        'Ativo há: %s' % _fmt_uptime(snapshot.get('uptime', 0)),
        'Conexões: %d estabelecidas de %d' % (
            established, snapshot['connection_count']),
        'Tráfego total: ↑ %s  ↓ %s' % (
            _fmt_bytes(up_bytes), _fmt_bytes(down_bytes)),
        'Pares conhecidos: %d' % snapshot['peers_stored'],
        'Objetos guardados: %d' % (snapshot.get('objects_stored')
                                   if snapshot.get('objects_stored')
                                   is not None
                                   else snapshot['inventory']),
        'Hashes conhecidos: %d' % snapshot['known_hashes'],
        'Sessão: %d objetos recebidos, %d anunciados, %d invs, %d getdatas'
        % (stats.get('objects_received', 0),
           stats.get('objects_announced', 0), stats.get('invs', 0),
           stats.get('getdatas', 0)),
        _state_line(snapshot, established, stats),
        '',
    ]
    if not snapshot['connections']:
        lines.append('Nenhuma conexão. Verifique a internet ou o proxy.')
    for conn in snapshot['connections']:
        state = 'estabelecida' if conn['established'] else 'negociando'
        version = conn['version'] if conn['version'] is not None else '?'
        streams = ','.join(str(s) for s in conn['streams']) or '?'
        offset = conn.get('time_offset')
        if offset is None:
            clock = 'relógio ?'
        else:
            clock = 'relógio %+ds' % offset
            if abs(offset) > 3600:
                clock += ' (DIVERGENTE: ajuste o relógio!)'
        lines.append(
            '%s:%s — %s, versão %s, streams [%s], serviços %s, nota %.0f, '
            '%s%s' % (conn['host'], conn['port'], state, version, streams,
                      conn['services'], conn.get('rating', 0), clock,
                      _conn_extra(conn, snapshot)))
        lines.append(
            '  ↑ %s  ↓ %s  há %ds' % (
                _fmt_bytes(conn['bytes_sent']),
                _fmt_bytes(conn['bytes_received']), conn['age']))
    return '\n'.join(lines)


def _avatar_color(key):
    return SENDER_COLORS[abs(hash(key)) % len(SENDER_COLORS)]


def _short_address(address):
    """Endereço curto ex.: BM-2cX8…91qZ (rótulo + … + sufixo)."""
    text = str(address or '')
    if len(text) <= 13:
        return text
    return text[:7] + '…' + text[-4:]


CURRENT_IDENTITY_KEY = 'current_identity'


def _initials(label):
    parts = [p for p in str(label).split() if p]
    if not parts:
        return '?'
    if parts[0].startswith('#'):
        parts[0] = parts[0][1:]
        if not parts[0]:
            return '?'
    if len(parts) == 1:
        return parts[0][0].upper()
    return (parts[0][0] + parts[1][0]).upper()


def _fit_width(font, text, max_width):
    if font.measure(text) <= max_width:
        return text
    ellipsis = '…'
    low, high = 0, len(text)
    while low < high:
        mid = (low + high + 1) // 2
        if font.measure(text[:mid] + ellipsis) <= max_width:
            low = mid
        else:
            high = mid - 1
    return text[:low] + ellipsis


def _fit_long_word(font, word, max_width):
    probe = word[:64]
    avg = font.measure(probe) / max(1, len(probe))
    if avg <= 0:
        return 1
    cut = max(1, min(int(max_width / avg), len(word)))
    for _ in range(12):
        if cut > 1 and font.measure(word[:cut]) > max_width:
            cut = max(1, cut // 2)
        else:
            break
    for _ in range(8):
        if cut < len(word) and font.measure(word[:cut + 1]) <= max_width:
            cut += 1
        else:
            break
    return cut


def _wrap_lines(font, text, max_width):
    lines = []
    for paragraph in str(text).split('\n'):
        if not paragraph:
            lines.append('')
            continue
        words = paragraph.split(' ')
        current = ''
        for word in words:
            trial = word if not current else current + ' ' + word
            if font.measure(trial) <= max_width:
                current = trial
            else:
                if current:
                    lines.append(current)
                while word and font.measure(word) > max_width:
                    cut = _fit_long_word(font, word, max_width)
                    lines.append(word[:cut])
                    word = word[cut:]
                current = word
        lines.append(current)
    return lines


def _cached_measure(font, fid, word, measure_cache):
    """font.measure with cache + eviction; returns word width."""
    wkey = (fid, word)
    word_w = measure_cache.get(wkey)
    if word_w is None:
        word_w = font.measure(word)
        measure_cache[wkey] = word_w
        if len(measure_cache) > 5000:
            for k in list(measure_cache.keys())[:2500]:
                measure_cache.pop(k, None)
    return word_w


def _chop_long_word(font, fid, lines, word, word_w, max_width,
                    measure_cache):
    """Split an over-wide word, appending pieces; return (rest, width)."""
    while word and word_w > max_width:
        cut = _fit_long_word(font, word, max_width)
        lines.append(word[:cut])
        word = word[cut:]
        word_w = _cached_measure(font, fid, word, measure_cache)
    return word, word_w


def _wrap_lines_cached(font, text, max_width, measure_cache):
    """Versão otimizada de _wrap_lines com cache de font.measure."""
    lines = []
    fid = id(font)
    for paragraph in str(text).split('\n'):
        if not paragraph:
            lines.append('')
            continue
        words = paragraph.split(' ')
        current = ''
        current_w = 0
        space_w = measure_cache.get((fid, ' '))
        if space_w is None:
            space_w = font.measure(' ')
            measure_cache[(fid, ' ')] = space_w
        for word in words:
            word_w = _cached_measure(font, fid, word, measure_cache)
            trial_w = word_w if not current else current_w + space_w + word_w
            if trial_w <= max_width:
                current = word if not current else current + ' ' + word
                current_w = trial_w
            else:
                if current:
                    lines.append(current)
                word, word_w = _chop_long_word(
                    font, fid, lines, word, word_w, max_width,
                    measure_cache)
                current = word
                current_w = word_w
        lines.append(current)
    return lines if lines else ['']


def _format_time(timestamp):
    try:
        return datetime.datetime.fromtimestamp(
            int(timestamp)).strftime('%d/%m %H:%M')
    except Exception:
        return ''


def _clock(timestamp):
    try:
        return datetime.datetime.fromtimestamp(int(timestamp)).strftime('%H:%M')
    except Exception:
        return ''


def _day_key(timestamp):
    try:
        return datetime.datetime.fromtimestamp(int(timestamp)).date()
    except Exception:
        return None


def _day_label(day):
    if day is None:
        return ''
    today = datetime.date.today()
    if day == today:
        return 'Hoje'
    if day == today - datetime.timedelta(days=1):
        return 'Ontem'
    return day.strftime('%d/%m/%Y')


class _ConvListAdapter:

    def __init__(self, app):
        self._app = app
        self._bindings = {}

    def size(self):
        return len(self._app._conv_meta)

    def get(self, index):
        return self._app._conv_labels[index] \
            if 0 <= index < len(self._app._conv_labels) else ''

    def curselection(self):
        selected = self._app._conv_selected
        return (selected,) if selected is not None else ()

    def selection_clear(self, _first=None, _last=None):
        self._app._conv_selected = None
        self._app._draw_conversations()

    def selection_set(self, index):
        if 0 <= index < len(self._app._conv_meta):
            self._app._conv_selected = index
            self._app._draw_conversations()

    def bind(self, sequence, callback):
        self._bindings[sequence] = callback


class _ChatTextAdapter:

    def __init__(self):
        self._plain = ''
        self._tags = set()

    def get(self, _first=None, _last=None):
        return self._plain

    def tag_names(self):
        return set(self._tags)

    def see(self, _index=None):
        pass

    def config(self, **_kwargs):
        pass

    def configure(self, **_kwargs):
        pass


class App(tk.Tk):

    def _launch_client_start(self):
        # Startup: rede/DB pesado roda em thread; a janela pinta antes.
        try:
            threading.Thread(target=self._start_client_bg, daemon=True,
                             name='client-start').start()
        except Exception:
            try:
                self.client.start()
                self._client_started = True
            except Exception as exc:
                self._client_start_error = exc

    def _schedule_startup(self, call):
        """Schedule next startup slice; tolerate dead widgets."""
        try:
            self._startup_after = call()
        except Exception:
            self._startup_after = None

    @staticmethod
    def _refresh_quietly(action):
        try:
            action()
        except Exception:
            pass

    def __init__(self, data_dir, client=None):
        """App com Dependency Injection.

        Args:
            data_dir: diretório de dados (usado se client=None)
            client: Client injetado; se None cria um com DI padrão
                    (mantém compatibilidade com chamada antiga main(directory)).
        """
        super().__init__()
        # Item 1 — startup percebido: começa escondida, mostra uma casca
        # mínima e monta o pesado em etapas (after), com a rede em thread.
        # A cadeia completa exige bombear o loop (update + esperas dos
        # after); ver _startup_step_*.
        try:
            self.withdraw()
        except Exception:
            pass
        self.data_dir = data_dir
        # Dependency Injection: permite injetar Client mockado para testes
        if client is not None:
            self.client = client
            # Garante que data_dir do app coincide com o do client
            try:
                self.data_dir = getattr(client, 'data_dir', data_dir)
            except Exception:
                pass
        else:
            self.client = Client(data_dir)
        self._client_started = False
        self._client_start_error = None
        self._bind_observer_events()
        self._launch_client_start()

        self.title('bmchat')
        self.geometry('1100x700')
        self.minsize(760, 480)
        self.configure(bg=PANEL_BG)

        self._conv_meta = []
        self._conv_labels = []
        self._conv_selected = None
        self._conv_hover_index = None
        self._conv_filter = ''
        self.current_kind = None
        self.current_address = None
        self._chat_rows = []
        self._chat_layouts = []
        self._redraw_after = None
        self._stick_bottom = True
        self._wrap_cache = {}
        self._wrap_order = []
        self._chat_limit = 200
        self._chat_has_more = False
        self._chat_pill = None
        self._conv_hover_after = None
        self._conv_draw_after = None
        self._refresh_after = None
        self._pow_last = {}
        # Item 3 — cache de elipse {(font-id, text, max_w): fitted}, FIFO ~300.
        self._fit_cache = {}
        self._fit_order = []
        self._ellipsis_w = {}
        # Virtual scroll state
        self._chat_first_visible = 0
        self._chat_last_visible = 0
        self._chat_viewport_height = 0
        # Font metrics cache
        self._font_measure_cache = {}
        self._line_h_cache = {}
        # Item 4 — última largura com layout de chat calculado.
        self._last_chat_w = None
        # Item 6 — higiene de after(): ids pendentes + flag de encerrado.
        self._closed = False
        self._startup_after = None
        self._poll_after = None
        self._tick_after = None
        # Item 1 — só True após a cadeia de init diferido terminar.
        self._startup_done = False
        # M9: lock para flags de update (lidas/escritas em workers).
        self._update_lock = threading.Lock()
        self._update_checking = False
        self._update_applying = False
        self._update_auto = False
        # Command Pattern: histórico para Undo/Redo futuro
        self._command_history = CommandHistory()

        self.conv_list = _ConvListAdapter(self)
        self.chat_text = _ChatTextAdapter()
        self._identity_map = {}
        self._updating_identity = False
        self._identity_tooltip = None
        self._badge_tooltip = None
        self._open_menu = None
        self._menu_opened_at = 0.0
        self.bind_all('<ButtonPress>', self._dismiss_open_menu, add='+')

        # Keyboard shortcuts
        self.bind_all('<Control-n>', lambda e: self._new_contact())
        self.bind_all('<Control-f>', lambda e: self._toggle_search())
        self.bind_all('<Control-w>', lambda e: self._close_current_dialog())
        self.bind_all('<Escape>', lambda e: self._handle_escape())
        self.bind_all('<Control-q>', lambda e: self._on_close())
        self.bind_all('<Control-comma>', lambda e: self._network_settings())

        # Item 1 — casca mínima (barata): placeholder até o build real.
        # `place` não conflita com o grid/pack que _build_widgets usa.
        self._boot_label = tk.Label(
            self, text='Abrindo bmchat…', bg=PANEL_BG, fg=TEXT_GRAY,
            font=('TkDefaultFont', 11))
        self._boot_label.place(relx=0.5, rely=0.5, anchor='center')
        try:
            self.deiconify()
        except Exception:
            pass

        self.protocol('WM_DELETE_WINDOW', self._on_close)
        self._schedule_startup(lambda: self.after_idle(self._startup_step_build))

    # -------------------------------------------------- startup diferido (item 1)

    def _bind_observer_events(self):
        """Observer Pattern: GUI se registra como observer dos eventos do Client.

        Cada evento emitido pelo Client via EventEmitter agenda o handling
        no main thread (after 0). Mantém compatibilidade com polling legado
        (queue) — observer é caminho preferencial, polling é fallback.
        """
        try:
            # Mapeia eventos legados (ui_queue) para handlers da GUI
            def _make_handler(kind):
                def _handler(data):
                    # data é o payload sem o kind; reconstrói tupla completa
                    if data is None:
                        full = (kind,)
                    elif isinstance(data, tuple):
                        full = (kind,) + data
                    else:
                        full = (kind, data)
                    try:
                        # Agenda no main thread para segurança Tk
                        self.after(0, lambda f=full: self._dispatch_event(f))
                    except Exception:
                        pass
                return _handler

            for legacy_kind in App._KNOWN_UI_EVENTS:
                try:
                    self.client.events.on(legacy_kind, _make_handler(legacy_kind))
                except Exception:
                    pass
            # Eventos tipados novos (ex.: NEW_MESSAGE) também disparam refresh
            try:
                from ..core.events import NEW_MESSAGE, POW_PROGRESS, CONNECTION_CHANGE
                # Já cobertos via legacy; mantém para exemplificar uso tipado
                _ = (NEW_MESSAGE, POW_PROGRESS, CONNECTION_CHANGE)
            except Exception:
                pass
        except Exception:
            pass

    def _start_client_bg(self):
        try:
            self.client.start()
            self._client_started = True
        except Exception as exc:
            self._client_start_error = exc

    def _paint_boot_progress(self):
        try:
            boot = getattr(self, '_boot_label', None)
            if boot is not None:
                try:
                    boot.config(text='Abrindo bmchat… montando conversa…')
                except Exception:
                    pass
            try:
                self.update_idletasks()
            except Exception:
                pass
        except Exception:
            pass

    def _startup_step_build(self):
        self._startup_after = None
        if getattr(self, '_closed', False):
            return
        self._refresh_quietly(self._build_widgets_left)
        if getattr(self, '_closed', False):
            return
        self._paint_boot_progress()
        # after(ms) em vez de after_idle: dá chance de paint entre fatias
        # (idle callbacks esgotariam no mesmo update()).
        self._schedule_startup(
            lambda: self.after(30, self._startup_step_build_left_b))

    def _startup_step_build_left_b(self):
        self._startup_after = None
        if getattr(self, '_closed', False):
            return
        self._refresh_quietly(self._build_widgets_left_b)
        if getattr(self, '_closed', False):
            return
        self._refresh_quietly(self.update_idletasks)
        self._schedule_startup(
            lambda: self.after(30, self._startup_step_build_right))

    def _destroy_boot_label(self):
        try:
            boot = getattr(self, '_boot_label', None)
            if boot is not None:
                try:
                    boot.destroy()
                except Exception:
                    pass
            self._boot_label = None
        except Exception:
            pass

    def _startup_step_build_right(self):
        self._startup_after = None
        if getattr(self, '_closed', False):
            return
        self._refresh_quietly(self._build_widgets_right)
        if getattr(self, '_closed', False):
            return
        self._destroy_boot_label()
        self._schedule_startup(lambda: self.after_idle(self._startup_step_data))

    def _note_client_start_error(self):
        try:
            boot = getattr(self, '_boot_label', None)
            if boot is not None:
                boot.config(text='Falha ao iniciar rede local; tentando…')
        except Exception:
            pass

    def _wait_client_start(self):
        """True when the client is up (or failed); else reschedule + False."""
        if getattr(self, '_client_started', False):
            return True
        if getattr(self, '_client_start_error', None) is not None:
            self._note_client_start_error()
            return True
        self._schedule_startup(
            lambda: self.after(100, self._startup_step_data))
        return False

    def _ensure_default_identity(self):
        try:
            if not self.client.identities:
                self.client.create_identity('Minha identidade')
        except Exception:
            pass

    def _startup_step_data(self):
        self._startup_after = None
        if getattr(self, '_closed', False):
            return
        if not self._wait_client_start():
            return
        self._ensure_default_identity()
        self._refresh_quietly(self._refresh_identity_menu)
        self._refresh_quietly(self._update_identity_indicator)
        self._refresh_quietly(self._check_restored_identity_fallback)
        self._refresh_quietly(self._refresh_conversations)
        self._refresh_quietly(self._restore_pending_draft)
        if getattr(self, '_closed', False):
            return
        self._schedule_startup(lambda: self.after_idle(self._startup_step_live))

    def _startup_step_live(self):
        self._startup_after = None
        if getattr(self, '_closed', False):
            return
        try:
            self._poll_after = self.after(250, self._poll)
        except Exception:
            self._poll_after = None
        try:
            self._tick_after = self.after(1500, self._tick_status)
        except Exception:
            self._tick_after = None
        try:
            threading.Thread(target=self._auto_update_check, daemon=True,
                             name='update-check').start()
        except Exception:
            pass
        try:
            self._schedule_periodic_update_check()
        except Exception:
            pass
        self._startup_done = True

    # -------------------------------------------------- widgets

    def _build_widgets(self):
        # Compat: monta tudo de uma vez (startup usa as partes fatiadas).
        self._build_widgets_left()
        self._build_widgets_left_b()
        self._build_widgets_right()

    def _build_widgets_left(self):
        self.name_font = tkfont.Font(family='TkDefaultFont', size=11,
                                     weight='bold')
        self.preview_font = tkfont.Font(family='TkDefaultFont', size=10)
        self.small_font = tkfont.Font(family='TkDefaultFont', size=9)
        self.msg_font = tkfont.Font(family='TkDefaultFont', size=11)
        self.sender_font = tkfont.Font(family='TkDefaultFont', size=10,
                                       weight='bold')
        self.avatar_font = tkfont.Font(family='TkDefaultFont', size=12,
                                       weight='bold')
        self.title_font = tkfont.Font(family='TkDefaultFont', size=13,
                                      weight='bold')
        self.welcome_title_font = tkfont.Font(family='TkDefaultFont', size=14,
                                              weight='bold')

        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        self.panes = tk.PanedWindow(self, orient='horizontal', sashwidth=3,
                                    bg=LINE, bd=0)
        self.panes.grid(row=0, column=0, sticky='nsew')

        self.left = tk.Frame(self.panes, bg=PANEL_BG, width=320)
        self.panes.add(self.left, minsize=240)
        self.right = tk.Frame(self.panes, bg=CHAT_BG)
        self.panes.add(self.right, minsize=480)
        self.right.rowconfigure(1, weight=1)
        self.right.columnconfigure(0, weight=1)

        # ---- left header ----
        self.left_header = tk.Frame(self.left, bg=HEADER_BG, height=52)
        self.left_header.pack(fill='x')
        self.left_header.pack_propagate(False)
        self.hamburger_btn = tk.Button(self.left_header, text='☰', fg=HEADER_FG, bg=HEADER_BG,
                                       activebackground=HEADER_BG_DARK, activeforeground=HEADER_FG,
                                       relief='flat', bd=0, font=('', 14),
                                       command=self._hamburger_menu)
        self.hamburger_btn.pack(side='left', padx=6)
        ToolTip(self.hamburger_btn, 'Menu principal (Ctrl+,)')
        tk.Label(self.left_header, text='bmchat', fg=HEADER_FG, bg=HEADER_BG,
                 font=self.title_font).pack(side='left')
        self.search_btn = tk.Button(self.left_header, text='🔍', fg=HEADER_FG, bg=HEADER_BG,
                                    activebackground=HEADER_BG_DARK, activeforeground=HEADER_FG,
                                    relief='flat', bd=0, font=('', 13),
                                    command=self._toggle_search)
        self.search_btn.pack(side='right', padx=6)
        ToolTip(self.search_btn, 'Buscar conversas (Ctrl+F)')

        self.search_frame = tk.Frame(self.left, bg=PANEL_BG)
        self.search_var = tk.StringVar()
        self.search_var.trace_add('write', self._on_search_type)
        self.search_entry = tk.Entry(
            self.search_frame, textvariable=self.search_var, relief='solid',
            bd=1, highlightthickness=0, font=self.preview_font)
        self.search_entry.pack(fill='x', padx=10, pady=6)

        # ---- conversation list ----
        self.conv_canvas = tk.Canvas(self.left, bg=PANEL_BG,
                                     highlightthickness=0, bd=0)
        self.conv_scroll = tk.Scrollbar(self.left, orient='vertical',
                                        command=self.conv_canvas.yview)
        self.conv_canvas.configure(yscrollcommand=self.conv_scroll.set)
        self.conv_scroll.pack(side='right', fill='y')
        self.conv_canvas.pack(side='left', fill='both', expand=True)
        self.conv_canvas.bind('<Button-1>', self._conv_click)
        self.conv_canvas.bind('<Motion>', self._conv_hover_debounced)
        self.conv_canvas.bind('<Leave>', self._conv_leave)
        self.conv_canvas.bind('<Button-3>', self._conv_right_click)
        self._bind_wheel(self.conv_canvas)
        self.conv_canvas.bind('<Configure>',
                              lambda _e: self._schedule_conv_redraw())

    def _build_widgets_left_b(self):
        # Segunda fatia da esquerda: FAB + linha de identidade.
        self.fab = tk.Canvas(self.left, width=56, height=56,
                             highlightthickness=0, bd=0, bg=PANEL_BG)
        self.fab.place(relx=1.0, rely=1.0, x=-76, y=-76, anchor='center')
        self.fab.create_oval(2, 2, 54, 54, fill=FAB_BG, outline=FAB_BG)
        self.fab.create_text(28, 28, text='✎', fill='white',
                             font=('', 20))
        self.fab.bind('<Button-1>', lambda _e: self._compose_menu())
        ToolTip(self.fab, 'Nova conversa (Ctrl+N)')

        # ---- identity row ----
        id_row = tk.Frame(self.left, bg=PANEL_BG, highlightthickness=0)
        id_row.pack(fill='x', side='bottom')
        tk.Frame(id_row, bg=LINE, height=1).pack(fill='x')
        inner = tk.Frame(id_row, bg=PANEL_BG)
        inner.pack(fill='x', padx=8, pady=(6, 2))
        tk.Label(inner, text='Enviar como:', bg=PANEL_BG, fg=TEXT_GRAY,
                 font=self.small_font).pack(side='left')
        self.identity_var = tk.StringVar()
        self.identity_menu = tk.OptionMenu(inner, self.identity_var, '')
        self.identity_menu.configure(bg=PANEL_BG, fg=TEXT_INK, relief='flat',
                                     highlightthickness=0, activebackground=ROW_HOVER,
                                     font=self.preview_font)
        self.identity_menu['menu'].configure(bg=PANEL_BG, fg=TEXT_INK)
        self.identity_menu.pack(side='left', padx=4, fill='x', expand=True)
        ToolTip(self.identity_menu, 'Selecionar identidade (1 clique p/ trocar)')
        self.new_identity_btn = tk.Button(inner, text='+', command=self._new_identity, bg=FAB_BG,
                                          fg='white', relief='flat', width=3,
                                          font=self.preview_font)
        self.new_identity_btn.pack(side='left')
        ToolTip(self.new_identity_btn, 'Nova identidade')
        self.backup_btn = tk.Button(inner, text='Backup', command=self._backup_identity,
                                    bg=PANEL_BG, fg=TEXT_INK, relief='solid', bd=1,
                                    font=self.small_font)
        self.backup_btn.pack(side='left', padx=(4, 0))
        ToolTip(self.backup_btn, 'Backup de identidade')
        self._build_identity_indicator(id_row)
        try:
            self.identity_var.trace_add('write', self._on_identity_var_changed)
        except Exception:
            pass

    def _build_identity_indicator(self, id_row):
        box = tk.Frame(id_row, bg=PANEL_BG)
        box.pack(fill='x', padx=8, pady=(0, 6))
        self.identity_avatar = tk.Canvas(box, width=24, height=24,
                                         highlightthickness=0, bd=0,
                                         bg=PANEL_BG)
        self.identity_avatar.pack(side='left')
        self.identity_avatar.bind('<Button-1>',
                                  lambda _e: self._copy_current_identity_address())
        self.identity_indicator_label = tk.Label(
            box, bg=PANEL_BG, fg=TEXT_INK, font=self.preview_font,
            anchor='w', justify='left', cursor='hand2')
        self.identity_indicator_label.pack(side='left', padx=(6, 0),
                                           fill='x', expand=True)
        self.identity_indicator_label.bind(
            '<Button-1>',
            lambda _e: self._copy_current_identity_address())
        self._identity_tooltip = ToolTip(self.identity_indicator_label, '')
        ToolTip(self.identity_avatar, 'Clique p/ copiar o endereço')
        self.manage_identities_btn = tk.Button(
            box, text='⚙', command=self._manage_identities,
            bg=PANEL_BG, fg=TEXT_INK, relief='flat',
            font=self.preview_font, width=3)
        self.manage_identities_btn.pack(side='right')
        ToolTip(self.manage_identities_btn, 'Gerenciar identidades')

    def _build_widgets_right(self):
        # Segunda metade: cabeçalho/chat/input/statusbar (roda no próximo idle).
        # Pré-condição: _build_widgets_left já criou panes/right + fontes.
        self.chat_header = tk.Frame(self.right, bg=HEADER_BG, height=52)
        self.chat_header.grid(row=0, column=0, sticky='ew')
        self.chat_header.grid_propagate(False)
        self.chat_header.columnconfigure(1, weight=1)
        self.peer_avatar = tk.Canvas(self.chat_header, width=36, height=36,
                                     highlightthickness=0, bd=0, bg=HEADER_BG)
        self.peer_avatar.grid(row=0, column=0, padx=(10, 4), pady=8)
        title_box = tk.Frame(self.chat_header, bg=HEADER_BG)
        title_box.grid(row=0, column=1, sticky='w')
        self.chat_title = tk.Label(title_box, text='Selecione uma conversa',
                                   bg=HEADER_BG, fg=HEADER_FG,
                                   font=self.title_font, anchor='w')
        self.chat_title.pack(anchor='w')
        self.chat_subtitle = tk.Label(title_box, text='', bg=HEADER_BG,
                                      fg=HEADER_DIM, font=self.small_font,
                                      anchor='w')
        self.chat_subtitle.pack(anchor='w')
        self.chat_header.columnconfigure(2, weight=0)
        self.identity_badge = tk.Frame(self.chat_header, bg=HEADER_BG)
        self.identity_badge.grid(row=0, column=2, padx=(4, 10), pady=8,
                                 sticky='e')
        self.identity_badge_avatar = tk.Canvas(
            self.identity_badge, width=28, height=28,
            highlightthickness=0, bd=0, bg=HEADER_BG)
        self.identity_badge_avatar.pack(side='left')
        self.identity_badge_avatar.bind(
            '<Button-1>',
            lambda _e: self._copy_current_identity_address())
        self.identity_badge_label = tk.Label(
            self.identity_badge, bg=HEADER_BG, fg=HEADER_FG,
            font=self.small_font, anchor='e', justify='right',
            cursor='hand2')
        self.identity_badge_label.pack(side='left', padx=(6, 0))
        self.identity_badge_label.bind(
            '<Button-1>',
            lambda _e: self._copy_current_identity_address())
        self._badge_tooltip = ToolTip(self.identity_badge_label, '')
        ToolTip(self.identity_badge_avatar, 'Identidade atual (clique p/ copiar)')

        # ---- chat canvas ----
        self.chat_frame = tk.Frame(self.right, bg=CHAT_BG)
        self.chat_frame.grid(row=1, column=0, sticky='nsew')
        self.chat_frame.rowconfigure(1, weight=1)
        self.chat_frame.columnconfigure(0, weight=1)
        self.triage_banner = tk.Frame(self.chat_frame, bg=PANEL_BG)
        self.triage_banner.grid(row=0, column=0, columnspan=2, sticky='ew')
        tk.Frame(self.triage_banner, bg=LINE, height=1).pack(
            side='bottom', fill='x')
        tk.Label(self.triage_banner,
                 text='Problemas? Envie um diagnóstico ao suporte.',
                 bg=PANEL_BG, fg=TEXT_GRAY,
                 font=self.small_font).pack(side='left', padx=10, pady=6)
        tk.Button(self.triage_banner, text='Enviar diagnóstico',
                  command=self._send_diagnostics, bg=FAB_BG, fg='white',
                  relief='flat', font=self.preview_font).pack(
                      side='right', padx=10, pady=4)
        self.triage_banner.grid_remove()
        self.chat_canvas = tk.Canvas(self.chat_frame, bg=CHAT_BG,
                                     highlightthickness=0, bd=0)
        self.chat_canvas.grid(row=1, column=0, sticky='nsew')
        self.chat_scroll = tk.Scrollbar(self.chat_frame, orient='vertical',
                                        command=self._chat_yview)
        self.chat_scroll.grid(row=1, column=1, sticky='ns')
        self.chat_canvas.configure(yscrollcommand=self._chat_yscroll)
        self._bind_wheel(self.chat_canvas)
        self.chat_canvas.bind('<Configure>', lambda _e: self._schedule_chat_redraw())
        self.chat_canvas.bind('<Button-3>', self._chat_right_click)
        self.chat_canvas.bind('<Button-1>', self._chat_click)

        self.jump_btn = tk.Button(
            self.chat_frame, text='↓', bg=PANEL_BG, fg=INPUT_ICON,
            relief='solid', bd=1, font=('', 12), width=2,
            command=lambda: self.chat_canvas.yview_moveto(1.0))
        self.jump_btn.place_forget()
        ToolTip(self.jump_btn, 'Ir para mensagens mais recentes')

        self.welcome_copy_btn = tk.Button(
            self.chat_frame, text='Copiar meu endereço', bg=FAB_BG,
            fg='white', activebackground=FAB_BG, relief='flat',
            font=self.preview_font, padx=12, pady=6,
            command=self._copy_my_address)
        self.welcome_copy_btn.place_forget()
        ToolTip(self.welcome_copy_btn, 'Copiar seu endereço')

        # ---- input bar ----
        self.input_frame = tk.Frame(self.right, bg=PANEL_BG)
        self.input_frame.grid(row=2, column=0, sticky='ew')
        self.input_frame.columnconfigure(0, weight=0)
        self.input_frame.columnconfigure(1, weight=0)
        self.input_frame.columnconfigure(2, weight=1)
        self.input_frame.columnconfigure(3, weight=0)
        self.input_frame.columnconfigure(4, weight=0)
        self.input_frame.rowconfigure(1, weight=0)
        tk.Frame(self.input_frame, bg=LINE, height=1).grid(
            row=0, column=0, columnspan=5, sticky='ew')
        self.attach_btn = tk.Button(self.input_frame, text='📎', fg=INPUT_ICON, bg=PANEL_BG,
                                    activebackground=ROW_HOVER, relief='flat', bd=0,
                                    font=('', 16), command=self._attach_file)
        self.attach_btn.grid(row=1, column=0, padx=(6, 2), pady=8)
        ToolTip(self.attach_btn, 'Anexar arquivo')
        self.emoji_btn = tk.Button(self.input_frame, text='☺', fg=INPUT_ICON, bg=PANEL_BG,
                                   activebackground=ROW_HOVER, relief='flat', bd=0,
                                   font=('', 16), command=self._emoji_popup)
        self.emoji_btn.grid(row=1, column=1, padx=(2, 2), pady=8)
        ToolTip(self.emoji_btn, 'Emojis')
        self.input_var = tk.StringVar()
        self.field_box = tk.Frame(
            self.input_frame, bg=_c('input_bg'),
            highlightthickness=1,
            highlightbackground=_c('input_border'),
            highlightcolor=_c('input_border'))
        self.field_box.grid(row=1, column=2, sticky='nsew', padx=4, pady=6)
        self.input_entry = tk.Entry(
            self.field_box, textvariable=self.input_var, relief='flat',
            bd=0, highlightthickness=0, font=self.msg_font,
            bg=_c('input_bg'), fg=_c('input_fg'),
            insertbackground=_c('input_fg'),
            disabledbackground=_c('input_bg'),
            disabledforeground=_c('input_placeholder'),
            readonlybackground=_c('input_bg'))
        self.input_entry.pack(fill='x', expand=True, padx=10, pady=7)
        self.input_entry.bind('<Return>', lambda _e: self._send())
        self.input_entry.bind('<FocusIn>', self._clear_placeholder)
        self.input_entry.bind('<FocusOut>', self._restore_placeholder)
        self._placeholder_on = True
        self._set_placeholder()
        self.send_btn = tk.Canvas(self.input_frame, width=36, height=36,
                                  highlightthickness=0, bd=0, bg=PANEL_BG)
        self.send_btn.grid(row=1, column=3, padx=(2, 4), pady=6)
        self._send_oval = self.send_btn.create_oval(
            2, 2, 34, 34, fill=FAB_BG, outline=FAB_BG)
        self._send_arrow = self.send_btn.create_text(
            18, 18, text='➤', fill='white', font=('', 14))
        self._input_enabled = True
        self.send_btn.bind('<Button-1>', lambda _e: self._send())
        ToolTip(self.send_btn, 'Enviar (Enter)')

        # Schedule button
        self.schedule_btn = tk.Button(self.input_frame, text='🕐', fg=INPUT_ICON, bg=PANEL_BG,
                                      activebackground=ROW_HOVER, relief='flat', bd=0,
                                      font=('', 16), command=self._schedule_message)
        self.schedule_btn.grid(row=1, column=4, padx=(0, 8), pady=6)
        ToolTip(self.schedule_btn, 'Agendar envio')

        self._set_input_enabled(False)

        self.statusbar = tk.Label(self, text='Conectando...', anchor='e',
                                  bg=_c('panel_bg_secondary'), fg=TEXT_GRAY, padx=8,
                                  font=self.small_font)
        self.statusbar.grid(row=1, column=0, sticky='ew')

    def _bind_wheel(self, canvas):
        canvas.bind('<MouseWheel>',
                    lambda e: canvas.yview_scroll(-1 if e.delta > 0 else 1,
                                                  'units'))
        canvas.bind('<Button-4>', lambda _e: canvas.yview_scroll(-1, 'units'))
        canvas.bind('<Button-5>', lambda _e: canvas.yview_scroll(1, 'units'))

    # -------------------------------------------------- header menus

    def _track_menu(self, menu):
        previous = self._open_menu
        if previous is not None and previous is not menu:
            try:
                previous.unpost()
            except Exception:
                pass
        self._open_menu = menu
        self._menu_opened_at = time.time()

    @staticmethod
    def _event_targets_menu(event, menu):
        widget = getattr(event, 'widget', None)
        if widget is None:
            return False
        try:
            return bool(widget is menu or widget.winfo_class() == 'Menu')
        except Exception:
            return False

    def _release_open_menu(self, menu):
        self._open_menu = None
        try:
            menu.unpost()
        except Exception:
            pass
        try:
            menu.grab_release()
        except Exception:
            pass

    def _dismiss_open_menu(self, event=None):
        menu = self._open_menu
        if menu is None:
            return
        if self._event_targets_menu(event, menu):
            return
        if time.time() - self._menu_opened_at < 0.05:
            return
        self._release_open_menu(menu)

    def _popup(self, menu, widget):
        menu.tk_popup(widget.winfo_rootx(), widget.winfo_rooty() +
                      widget.winfo_height())
        self._track_menu(menu)

    def _hamburger_menu(self):
        menu = self._build_hamburger_menu()
        self._popup(menu, self.left_header)
        return menu

    def _build_identity_submenu(self, parent):
        submenu = tk.Menu(parent, tearoff=0)
        submenu.add_command(label='Minha identidade',
                            command=self._show_welcome)
        submenu.add_command(label='Nova identidade',
                            command=self._new_identity)
        submenu.add_separator()
        submenu.add_command(label='Backup de identidade…',
                            command=self._backup_identity)
        return submenu

    def _build_security_submenu(self, parent):
        submenu = tk.Menu(parent, tearoff=0)
        submenu.add_command(label='Backup criptografado…',
                            command=self._encrypted_backup)
        submenu.add_command(label='Restaurar backup criptografado…',
                            command=self._restore_encrypted_backup)
        submenu.add_separator()
        submenu.add_command(label='Criptografar banco de dados…',
                            command=self._encrypt_database)
        submenu.add_command(label='Alterar senha do banco…',
                            command=self._change_db_password)
        return submenu

    def _build_network_submenu(self, parent):
        submenu = tk.Menu(parent, tearoff=0)
        submenu.add_command(label='Diagnóstico de rede…',
                            command=self._network_diagnostics)
        submenu.add_command(label='Ver log…', command=self._show_log)
        submenu.add_command(label='Configurações de rede…',
                            command=self._network_settings)
        submenu.add_command(label='Proxy / Darknet...',
                            command=self._proxy_dialog)
        submenu.add_separator()
        submenu.add_command(label='Apagar objetos…',
                            command=self._wipe_objects)
        submenu.add_command(label='Verificar POW ativos',
                            command=self._show_pows)
        return submenu

    def _build_contacts_submenu(self, parent):
        submenu = tk.Menu(parent, tearoff=0)
        submenu.add_command(label='Novo contato', command=self._new_contact)
        return submenu

    def _build_system_submenu(self, parent):
        submenu = tk.Menu(parent, tearoff=0)
        submenu.add_command(label='Verificar atualizações',
                            command=self._check_updates_manual)
        submenu.add_separator()
        theme_menu = tk.Menu(submenu, tearoff=0)
        theme_menu.add_command(label='☀️  Claro',
                               command=lambda: self._set_theme('light'))
        theme_menu.add_command(label='🌙  Escuro',
                               command=lambda: self._set_theme('dark'))
        submenu.add_cascade(label='Tema', menu=theme_menu)
        submenu.add_command(label='Legenda de confirmações',
                            command=self._confirmation_legend)
        submenu.add_command(label='Tempo de vida das mensagens…',
                            command=self._msg_ttl_dialog)
        submenu.add_command(label='Sobre', command=self._about)
        submenu._theme_menu = theme_menu
        return submenu

    def _build_hamburger_menu(self):
        menu = tk.Menu(self, tearoff=0)
        identity = self._build_identity_submenu(menu)
        menu.add_cascade(label='Identidade', menu=identity)
        security = self._build_security_submenu(menu)
        menu.add_cascade(label='Segurança', menu=security)
        network = self._build_network_submenu(menu)
        menu.add_cascade(label='Rede', menu=network)
        contacts = self._build_contacts_submenu(menu)
        menu.add_cascade(label='Contatos', menu=contacts)
        system = self._build_system_submenu(menu)
        menu.add_cascade(label='Sistema', menu=system)
        menu.add_command(label='Suporte…', command=self._support)
        menu._bm_submenus = (identity, security, network, contacts,
                             system, system._theme_menu)
        return menu

    def _set_theme(self, name: str):
        """Switch application theme."""
        set_theme(name)
        self._refresh_theme_colors()
        if getattr(self, '_startup_done', False):
            self._draw_conversations()
            self._redraw_chat()
            self._refresh_identity_menu()
            # Update placeholder color
            if self._placeholder_on:
                self.input_entry.config(fg=_c('input_placeholder'))
            self._flash_status(f'Tema alterado para {name}')

    def _refresh_theme_colors(self):
        """Refresh all theme-dependent colors."""
        global HEADER_BG, HEADER_BG_DARK, HEADER_FG, HEADER_DIM
        global PANEL_BG, ROW_HOVER, ROW_SELECTED, LINE
        global TEXT_INK, TEXT_GRAY, TIME_GRAY, CHAT_BG, DOODLE
        global BUBBLE_IN, BUBBLE_OUT, BADGE_BG, FAB_BG, READ_BLUE
        global DATE_BG, INPUT_ICON, SENDER_COLORS

        HEADER_BG = _c('header_bg')
        HEADER_BG_DARK = _c('header_bg_hover')
        HEADER_FG = _c('header_fg')
        HEADER_DIM = _c('header_dim')
        PANEL_BG = _c('panel_bg')
        ROW_HOVER = _c('row_hover')
        ROW_SELECTED = _c('row_selected')
        LINE = _c('divider')
        TEXT_INK = _c('text_primary')
        TEXT_GRAY = _c('text_secondary')
        TIME_GRAY = _c('text_muted')
        CHAT_BG = _c('chat_bg')
        DOODLE = _c('doodle')
        BUBBLE_IN = _c('bubble_in')
        BUBBLE_OUT = _c('bubble_out')
        BADGE_BG = _c('unread_badge')
        FAB_BG = _c('accent')
        READ_BLUE = _c('info')
        DATE_BG = _c('border')
        INPUT_ICON = _c('text_muted')
        SENDER_COLORS = _theme.sender_colors

        # Update widget backgrounds if widgets exist
        try:
            self._recolor_widgets()
        except Exception:
            pass

    def _live_widget(self, name):
        """Return widget attr when it exists, else None (tolerates dead)."""
        try:
            widget = getattr(self, name, None)
            if widget is not None and widget.winfo_exists():
                return widget
        except Exception:
            pass
        return None

    def _recolor_frames(self):
        for name, color in (('left', PANEL_BG), ('right', CHAT_BG),
                            ('left_header', HEADER_BG),
                            ('chat_frame', CHAT_BG),
                            ('input_frame', PANEL_BG),
                            ('search_frame', PANEL_BG),
                            ('conv_canvas', PANEL_BG),
                            ('chat_canvas', CHAT_BG)):
            widget = self._live_widget(name)
            if widget is not None:
                widget.configure(bg=color)

    def _recolor_input_entry(self):
        widget = self._live_widget('input_entry')
        if widget is None:
            return
        try:
            ph_on = bool(getattr(self, '_placeholder_on', False))
        except Exception:
            ph_on = False
        widget.configure(
            bg=_c('input_bg'),
            fg=_c('input_placeholder') if ph_on else _c('input_fg'),
            insertbackground=_c('input_fg'),
            disabledbackground=_c('input_bg'),
            disabledforeground=_c('input_placeholder'),
            readonlybackground=_c('input_bg'))

    def _recolor_header_buttons(self):
        header = self._live_widget('left_header')
        if header is None:
            return
        for btn in header.winfo_children():
            if isinstance(btn, tk.Button):
                btn.configure(bg=HEADER_BG, activebackground=HEADER_BG_DARK,
                              fg=HEADER_FG)

    def _recolor_widgets(self):
        self._recolor_frames()
        widget = self._live_widget('welcome_copy_btn')
        if widget is not None:
            widget.configure(bg=FAB_BG, activebackground=_c('accent_hover'))
        widget = self._live_widget('jump_btn')
        if widget is not None:
            widget.configure(bg=PANEL_BG, fg=_c('text_secondary'))
        widget = self._live_widget('send_btn')
        if widget is not None:
            widget.configure(bg=PANEL_BG)
        widget = self._live_widget('field_box')
        if widget is not None:
            widget.configure(bg=_c('input_bg'),
                             highlightbackground=_c('input_border'),
                             highlightcolor=_c('input_border'))
        self._recolor_input_entry()
        self._recolor_header_buttons()

    def _compose_menu(self):
        self._new_contact()

    def _toggle_search(self):
        if self.search_frame.winfo_manager():
            self.search_frame.pack_forget()
            self.search_var.set('')
        else:
            self.search_frame.pack(fill='x', after=self.left_header)
            self.search_entry.focus_set()

    def _on_search_type(self, *_args):
        self._conv_filter = self.search_var.get().strip().lower()
        self._draw_conversations()

    # -------------------------------------------------- input bar

    def _set_placeholder(self):
        try:
            address = self._current_identity()
            label = self._identity_label(address) if address else ''
        except Exception:
            label = ''
        text = 'Mensagem como %s' % label if label else 'Mensagem'
        self.input_var.set(text)
        try:
            self.input_entry.config(fg=_c('input_placeholder'))
        except Exception:
            pass
        self._placeholder_on = True

    def _clear_placeholder(self, _event=None):
        if self._placeholder_on:
            self.input_var.set('')
            try:
                self.input_entry.config(fg=_c('input_fg'))
            except Exception:
                pass
            self._placeholder_on = False

    def _restore_placeholder(self, _event=None):
        if not self._placeholder_on and not self.input_var.get().strip():
            if getattr(self, '_input_enabled', False):
                self._set_placeholder()

    def _show_input_frame(self, enabled):
        try:
            if enabled:
                self.input_frame.grid()
            else:
                self.input_frame.grid_remove()
        except Exception:
            pass

    def _set_entry_state(self, enabled):
        try:
            # Nunca 'disabled' para placeholder: 'readonly' quando sem conversa.
            self.input_entry.config(
                state='normal' if enabled else 'readonly')
        except Exception:
            pass

    def _paint_send_button(self, enabled):
        try:
            color = FAB_BG if enabled else '#c3ccd4'
            fg = 'white' if enabled else '#eef1f4'
            self.send_btn.itemconfig(self._send_oval, fill=color,
                                     outline=color)
            self.send_btn.itemconfig(self._send_arrow, fill=fg)
        except Exception:
            pass

    def _restore_input_on_enable(self):
        try:
            self.input_entry.config(state='normal')
        except Exception:
            pass
        if getattr(self, '_placeholder_on', False) or \
                not self.input_var.get().strip():
            self._set_placeholder()

    def _reset_input_placeholder(self):
        # SEM conversa: barra oculta (Telegram-fiel); mantém texto
        # placeholder consistente sem usar 'disabled'.
        if getattr(self, '_placeholder_on', False) or \
                not self.input_var.get().strip():
            try:
                self.input_var.set(self._placeholder_text())
            except Exception:
                pass
            try:
                self.input_entry.config(fg=_c('input_placeholder'))
            except Exception:
                pass
            self._placeholder_on = True

    def _placeholder_text(self):
        try:
            address = self._current_identity()
            label = self._identity_label(address) if address else ''
        except Exception:
            label = ''
        return 'Mensagem como %s' % label if label else 'Mensagem'

    def _set_input_enabled(self, enabled):
        self._input_enabled = enabled
        self._show_input_frame(enabled)
        self._set_entry_state(enabled)
        self._paint_send_button(enabled)
        if enabled:
            self._restore_input_on_enable()
        else:
            self._reset_input_placeholder()

    def _emoji_popup(self):
        existing = getattr(self, '_emoji_win', None)
        try:
            alive = existing is not None and bool(existing.winfo_exists())
        except Exception:
            alive = False
        if alive:
            try:
                existing.lift()
                existing.focus_set()
            except Exception:
                pass
            return
        # Item 2: abre a casca já (deiconify) e preenche os 30 botões em
        # after_idle, por fileiras de 6, para a janela pintar imediatamente.
        popup = self._dialog_shell('Emoji')
        self._emoji_win = popup
        popup.resizable(False, False)
        emojis = ['😀', '😁', '😂', '😊', '😍', '😎', '👍', '👎', '🙏', '👏',
                  '🔥', '🎉', '❤️', '💯', '🚀', '⭐', '✅', '❌', '😢', '😮',
                  '🤔', '👋', '💡', '📌', '🎵', '☀️', '🌙', '🍕', '⚽', '🚗']
        try:
            popup.after_idle(lambda: self._fill_emoji(popup, emojis, 0))
        except Exception:
            pass

    def _insert_emoji(self, popup, emoji):
        self._clear_placeholder()
        self.input_entry.insert('insert', emoji)
        self.input_entry.focus_set()
        popup.destroy()

    def _make_emoji_button(self, popup, emoji, index):
        try:
            tk.Button(popup, text=emoji, font=('', 14), relief='flat',
                      bd=0,
                      command=lambda: self._insert_emoji(popup, emoji)).grid(
                          row=index // 6, column=index % 6,
                          padx=2, pady=2)
        except Exception:
            return False
        return True

    def _schedule_emoji_rest(self, popup, emojis, start):
        if start + 6 < len(emojis):
            try:
                popup.after_idle(
                    lambda: self._fill_emoji(popup, emojis, start + 6))
            except Exception:
                pass

    def _fill_emoji(self, popup, emojis, start):
        try:
            alive = bool(popup.winfo_exists())
        except Exception:
            return
        if not alive or getattr(self, '_closed', False):
            return
        if popup is not getattr(self, '_emoji_win', None):
            return
        for offset in range(6):
            index = start + offset
            if index >= len(emojis):
                break
            if not self._make_emoji_button(popup, emojis[index], index):
                return
        self._schedule_emoji_rest(popup, emojis, start)

    # -------------------------------------------------- events

    _KNOWN_UI_EVENTS = frozenset([
        'log', 'message', 'broadcast', 'pubkey', 'status',
        'identity-created', 'identity-updated', 'identity-removed',
        'contact-added', 'contact-removed', 'subscribed',
        'channel-created', 'broadcast-sent', 'pow-progress',
        'pow-cancelled', 'ack', 'update-available', 'update-check-result',
        'update-result',
    ])

    def _dispatch_event(self, event):
        try:
            kind = event[0]
        except Exception:
            return
        try:
            self._handle_event(event)
        except Exception as exc:
            self._report_event_error(kind, exc)

    @staticmethod
    def _is_known_event(kind):
        return kind in App._KNOWN_UI_EVENTS

    def _report_event_error(self, kind, exc):
        if not self._is_known_event(kind):
            return
        try:
            self.statusbar.config(
                text='Erro interno: %s' % exc)
        except Exception:
            pass

    def _drain_events(self):
        while True:
            try:
                event = self.client.ui_queue.get_nowait()
            except queue.Empty:
                break
            self._dispatch_event(event)

    def _report_poll_error(self, exc):
        try:
            self.statusbar.config(text='Erro: %s' % exc)
        except Exception:
            pass

    def _reschedule_poll(self):
        if getattr(self, '_closed', False):
            self._poll_after = None
        else:
            try:
                self._poll_after = self.after(250, self._poll)
            except Exception:
                self._poll_after = None

    def _poll(self):
        # Item 6: não reagenda nada após _on_close.
        if getattr(self, '_closed', False):
            self._poll_after = None
            return
        try:
            self._drain_events()
        except Exception as exc:
            self._report_poll_error(exc)
        finally:
            self._reschedule_poll()

    def _schedule_refresh(self):
        if getattr(self, '_closed', False):
            return
        if getattr(self, '_refresh_after', None) is not None:
            try:
                self.after_cancel(self._refresh_after)
            except Exception:
                pass
        try:
            self._refresh_after = self.after(200, self._do_refresh)
        except Exception:
            self._refresh_after = None

    def _do_refresh(self):
        self._refresh_after = None
        if getattr(self, '_closed', False):
            return
        try:
            self._refresh_conversations()
        except Exception as exc:
            try:
                self.statusbar.config(
                    text='Erro ao atualizar conversas: %s' % exc)
            except Exception:
                pass
        try:
            self._reload_chat()
        except Exception as exc:
            try:
                self.statusbar.config(
                    text='Erro ao atualizar chat: %s' % exc)
            except Exception:
                pass

    def _on_message_event(self, event):
        # event: ('message', from_address, to_address, body, expires)
        from_addr = event[1]
        body = event[3] if len(event) > 3 else ''
        # Truncate body for notification
        clean_body = body.split('[attachment:')[0].strip()
        preview = clean_body[:100] + ('…' if len(clean_body) > 100 else '')
        self._flash_status('Mensagem recebida')
        self._schedule_refresh()
        # Desktop notification
        try:
            notify(f'Mensagem de {from_addr[:18]}', preview)
        except Exception:
            pass

    def _on_broadcast_event(self, _event):
        self._flash_status('Nova postagem no canal')
        self._schedule_refresh()
        try:
            notify('Novo post no canal', 'Nova mensagem em canal inscrito')
        except Exception:
            pass

    def _on_pow_progress(self, event):
        try:
            _, token, _tried, rate = event
        except Exception:
            return
        now = time.time()
        last = self._pow_last.get(token, 0.0)
        if now - last < 1.0:
            return
        self._pow_last[token] = now
        try:
            self.statusbar.config(
                text='POW %d: %.0f hashes/s' % (token, rate))
        except Exception:
            pass

    def _set_update_flag(self, name, value):
        """M9: escrita de flag de update sob lock."""
        _set_update_flag(self, name, value)

    def _get_update_flag(self, name, default=False):
        """M9: leitura de flag de update sob lock."""
        return _get_update_flag(self, name, default)

    def _on_update_result(self, event):
        _set_update_flag(self, '_update_applying', False)
        _, ok, message = event
        auto = bool(_get_update_flag(self, '_update_auto', False))
        _set_update_flag(self, '_update_auto', False)
        if ok:
            self._flash_status('Atualizado! Reiniciando…')
            self.after(800, self._restart_after_update)
        elif auto:
            try:
                self.client._log('update', 'Atualização automática falhou: %s' % message)
            except Exception:
                pass
        else:
            dialogs.warn(self, 'Atualização', message)

    def _handle_event(self, event):
        kind = event[0]
        if kind == 'log':
            self._flash_status(event[2])
        elif kind == 'message':
            self._on_message_event(event)
        elif kind == 'broadcast':
            self._on_broadcast_event(event)
        elif kind == 'pubkey':
            self._flash_status('Chave pública recebida')
            self._schedule_refresh()
        elif kind == 'status':
            self._schedule_refresh()
        elif kind == 'ack':
            self._flash_status('Mensagem entregue (ACK recebido)')
            self._reload_chat()
        elif kind == 'identity-created':
            self._refresh_identity_menu()
            self._update_identity_indicator()
            self._refresh_conversations()
        elif kind in ('identity-updated', 'identity-removed'):
            self._refresh_identity_menu()
            self._update_identity_indicator()
            self._refresh_conversations()
        else:
            self._handle_event_tail(event, kind)

    def _handle_event_tail(self, event, kind):
        if kind in ('contact-added', 'contact-removed', 'subscribed',
                    'channel-created'):
            self._refresh_conversations()
        elif kind == 'broadcast-sent':
            self._reload_chat()
        elif kind == 'pow-progress':
            self._on_pow_progress(event)
        elif kind == 'pow-cancelled':
            self.statusbar.config(text='POW cancelado')
        elif kind == 'update-available':
            _, behind = event
            self._offer_update(behind)
        elif kind == 'update-check-result':
            _, result = event
            self._show_update_check(result)
        elif kind == 'update-result':
            self._on_update_result(event)

    def _tick_status(self):
        # Item 6: para de reagendar após _on_close.
        if getattr(self, '_closed', False):
            self._tick_after = None
            return
        try:
            snap = self.client.net.snapshot()
            established = sum(
                1 for c in snap['connections'] if c['established'])
            stored = snap.get('objects_stored')
            if stored is None:
                stored = snap['inventory']
            parts = [
                'Rede: %d/%d' % (established, snap['connection_count']),
                'Objetos: %d' % stored,
                'Pares: %d' % snap['peers_stored'],
                'PoW: %d' % len(self.client._pow_stops),
                'Pendentes: %d' % len(self.client._awaiting_addresses()),
                'Proxy: %s' % snap['proxy'],
            ]
            state_part = _status_state_part(snap, established)
            if state_part:
                parts.append(state_part)
            self.statusbar.config(text=' | '.join(parts))
        except Exception:
            pass
        if getattr(self, '_closed', False):
            self._tick_after = None
            return
        try:
            self._tick_after = self.after(1500, self._tick_status)
        except Exception:
            self._tick_after = None

    def _flash_status(self, message):
        self.statusbar.config(text=message)

    def _identity_display(self, address):
        row = self.client.db.get_identity(address)
        label = (row['label'] if row else '') or 'Identidade'
        return '%s (%s…)' % (label, address[:12])

    def _identity_label(self, address):
        try:
            row = self.client.db.get_identity(address)
        except Exception:
            row = None
        if row and row.get('label'):
            return row['label']
        return 'Identidade'

    def _current_identity(self):
        try:
            value = self.identity_var.get()
        except Exception:
            return ''
        return self._identity_map.get(value, value)

    def _load_saved_identity(self):
        try:
            return str(self.client.db.get_setting(
                CURRENT_IDENTITY_KEY, '') or '')
        except Exception:
            return ''

    def _save_current_identity(self, address):
        try:
            self.client.db.set_setting(CURRENT_IDENTITY_KEY, address)
        except Exception:
            pass

    def _check_restored_identity_fallback(self):
        saved = self._load_saved_identity()
        if not saved:
            return
        try:
            current = self._current_identity()
        except Exception:
            return
        if saved in self.client.identities:
            return
        label = self._identity_label(current)
        self._flash_status(
            'Identidade anterior não encontrada; usando %s (sem popup)'
            % label)

    def _on_identity_var_changed(self, *_args):
        if getattr(self, '_updating_identity', False):
            return
        if getattr(self, '_closed', False):
            return
        try:
            address = self._current_identity()
        except Exception:
            return
        if not address or address not in self.client.identities:
            return
        self._save_current_identity(address)
        self._update_identity_indicator()
        self._after_identity_switch(address)

    def _after_identity_switch(self, address):
        label = self._identity_label(address)
        self._update_identity_composer()
        self._update_identity_subtitle()
        try:
            self._refresh_conversations()
        except Exception:
            pass
        try:
            if getattr(self, 'current_address', None):
                self._reload_chat()
            else:
                self._redraw_chat()
        except Exception:
            pass
        self._flash_status('Enviando como %s (%s)'
                           % (label, _short_address(address)))

    def _set_current_identity(self, address):
        if not address or address not in self.client.identities:
            return False
        try:
            current = self._current_identity()
        except Exception:
            current = ''
        if current == address:
            self._save_current_identity(address)
            self._update_identity_indicator()
            self._after_identity_switch(address)
            return True
        self._updating_identity = True
        try:
            self.identity_var.set(self._identity_display(address))
        except Exception:
            self._updating_identity = False
            return False
        self._updating_identity = False
        self._save_current_identity(address)
        self._update_identity_indicator()
        self._after_identity_switch(address)
        return True

    def _pick_identity_target(self, addresses, previous, saved):
        if previous in addresses:
            return previous
        if saved in addresses:
            return saved
        return addresses[0]

    def _rebuild_identity_map(self, addresses):
        mapping = {}
        menu = self.identity_menu['menu']
        menu.delete(0, 'end')
        for address in addresses:
            display = self._identity_display(address)
            mapping[display] = address
            menu.add_command(
                label=display,
                command=lambda disp=display: self.identity_var.set(disp))
        return mapping

    def _refresh_identity_menu(self):
        addresses = list(self.client.identities.keys())
        if not addresses:
            return
        try:
            previous = self._current_identity()
        except Exception:
            previous = ''
        saved = self._load_saved_identity()
        self._identity_map = self._rebuild_identity_map(addresses)
        target = self._pick_identity_target(addresses, previous, saved)
        if self.identity_var.get() not in self._identity_map:
            self._updating_identity = True
            try:
                self.identity_var.set(self._identity_display(target))
            finally:
                self._updating_identity = False
            self._save_current_identity(target)
        self._update_identity_indicator()

    def _paint_identity_avatar(self, canvas, address, label, size):
        try:
            canvas.delete('all')
        except Exception:
            return
        color = _avatar_color(address or label)
        try:
            canvas.create_oval(1, 1, size - 1, size - 1,
                               fill=color, outline=color)
            canvas.create_text(size / 2, size / 2, text=_initials(label),
                               fill='white', font=('', 9, 'bold'))
        except Exception:
            pass

    def _set_identity_label_texts(self, indicator, badge):
        try:
            self.identity_indicator_label.config(text=indicator)
        except Exception:
            pass
        try:
            self.identity_badge_label.config(text=badge)
        except Exception:
            pass

    def _set_identity_tooltips(self, address):
        try:
            if self._identity_tooltip is not None:
                self._identity_tooltip.update_text(address)
        except Exception:
            pass
        try:
            if self._badge_tooltip is not None:
                self._badge_tooltip.update_text(address)
        except Exception:
            pass

    def _update_identity_texts(self, address, label, short):
        indicator = '%s  %s' % (label, short)
        badge = '%s\n%s' % (label, short)
        self._set_identity_label_texts(indicator, badge)
        self._set_identity_tooltips(address)

    def _update_identity_indicator(self):
        try:
            address = self._current_identity()
        except Exception:
            return
        if not address:
            return
        if address not in self.client.identities:
            addrs = list(self.client.identities.keys())
            if not addrs:
                return
            address = addrs[0]
        label = self._identity_label(address)
        short = _short_address(address)
        try:
            self._paint_identity_avatar(self.identity_avatar, address,
                                        label, 24)
        except Exception:
            pass
        try:
            self._paint_identity_avatar(self.identity_badge_avatar,
                                        address, label, 28)
        except Exception:
            pass
        self._update_identity_texts(address, label, short)

    def _update_identity_composer(self):
        if not getattr(self, '_placeholder_on', False):
            return
        try:
            self._set_placeholder()
        except Exception:
            pass

    def _update_identity_subtitle(self):
        if getattr(self, 'current_address', None):
            return
        try:
            address = self._current_identity()
        except Exception:
            return
        if not address:
            return
        label = self._identity_label(address)
        try:
            self.chat_subtitle.config(
                text='Enviando como %s (%s)'
                % (label, _short_address(address)))
        except Exception:
            pass

    def _copy_current_identity_address(self):
        try:
            address = self._current_identity()
        except Exception:
            return
        if not address:
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(address)
        except Exception:
            return
        self._flash_status('Endereço copiado: %s'
                           % _short_address(address))

    def _identity_stats(self, address):
        try:
            rows = self.client.db.query(
                'SELECT from_address, to_address FROM messages WHERE '
                'from_address=? OR to_address=?', (address, address))
        except Exception:
            rows = []
        peers = set()
        for row in rows:
            other = row['to_address'] if row['from_address'] == address \
                else row['from_address']
            if other:
                peers.add(other)
        return len(rows), len(peers)

    @staticmethod
    def _format_identity_created(created):
        try:
            stamp = int(created or 0)
        except Exception:
            return '—'
        if not stamp:
            return '—'
        try:
            return datetime.datetime.fromtimestamp(stamp).strftime(
                '%d/%m/%Y %H:%M')
        except Exception:
            return '—'

    def _identity_row(self, address):
        try:
            return self.client.db.get_identity(address)
        except Exception:
            return None

    def _refresh_after_identity_change(self):
        try:
            self._refresh_identity_menu()
        except Exception:
            pass
        try:
            self._update_identity_indicator()
        except Exception:
            pass
        try:
            self._refresh_conversations()
        except Exception:
            pass

    def _rename_identity(self, address, new_label=None):
        row = self._identity_row(address)
        if row is None:
            dialogs.warn(self, 'Renomear',
                         'Identidade não encontrada.')
            return False
        if new_label is None:
            result = dialogs.ask_simple(
                self, 'Renomear identidade', ['label'],
                {'label': row.get('label') or ''})
            if not result:
                return False
            new_label = result.get('label') or ''
        new_label = (new_label or '').strip()
        if not new_label:
            dialogs.warn(self, 'Renomear', 'Rótulo vazio.')
            return False
        status, error = self.client.rename_identity(address, new_label)
        if status != 'success':
            dialogs.warn(self, 'Renomear', error or status)
            return False
        self._refresh_after_identity_change()
        self._flash_status('Identidade renomeada para %s' % new_label)
        return True

    def _set_identity_enabled_ui(self, address, enabled):
        row = self._identity_row(address)
        if row is None:
            dialogs.warn(self, 'Identidade',
                         'Identidade não encontrada.')
            return False
        status, error = self.client.set_identity_enabled(address, enabled)
        if status != 'success':
            dialogs.warn(self, 'Identidade', error or status)
            return False
        self._refresh_after_identity_change()
        try:
            current = self._current_identity()
            label = self._identity_label(current) if current else ''
        except Exception:
            current, label = '', ''
        if enabled:
            self._flash_status('Identidade ativada: %s' % label)
        else:
            self._flash_status('Identidade desativada; enviando como %s'
                               % label)
        return True

    def _delete_identity(self, address):
        row = self._identity_row(address)
        if row is None:
            dialogs.warn(self, 'Excluir',
                         'Identidade não encontrada.')
            return False
        try:
            enabled = self.client.db.all_identities(enabled_only=True)
            addrs = [r['address'] for r in enabled]
        except Exception:
            addrs = []
        if len(addrs) <= 1 and address in addrs:
            dialogs.warn(self, 'Excluir',
                         'Não é possível excluir a última identidade ativa; '
                         'crie outra antes.')
            return False
        label = (row.get('label') if row else '') or address
        ok = dialogs.confirm(
            self, 'Excluir identidade',
            'Excluir a identidade "%s" (%s)?\n\n'
            '• Faça BACKUP das chaves antes: sem backup é IMPOSSÍVEL '
            'recuperar.\n'
            '• As chaves privadas serão removidas deste dispositivo.\n'
            '• O histórico de mensagens é mantido.\n\n'
            'Continuar?' % (label, _short_address(address)))
        if not ok:
            return False
        status, error = self.client.delete_identity(address)
        if status != 'success':
            dialogs.warn(self, 'Excluir', error or status)
            return False
        self._refresh_after_identity_change()
        try:
            current = self._current_identity()
            label_now = self._identity_label(current) if current else ''
        except Exception:
            label_now = ''
        self._flash_status('Identidade excluída; enviando como %s'
                           % label_now)
        return True

    def _copy_identity_address(self, address):
        try:
            self.clipboard_clear()
            self.clipboard_append(address)
        except Exception:
            return
        self._flash_status('Endereço copiado: %s'
                           % _short_address(address))

    def _show_identity_details(self, address):
        row = self._identity_row(address)
        if row is None:
            dialogs.warn(self, 'Identidade',
                         'Identidade não encontrada.')
            return None
        label = (row.get('label') if row else '') or 'Identidade'
        window = self._dialog_shell('Identidade — %s' % label[:24])
        window.resizable(False, False)
        self._fill_identity_details(window, address, row)
        return window

    def _identity_detail_fields(self, address, row):
        try:
            total, peers = self._identity_stats(address)
        except Exception:
            total, peers = 0, 0
        try:
            current = self._current_identity()
        except Exception:
            current = ''
        if address == current:
            status = 'em uso'
        elif row.get('enabled'):
            status = 'ativa'
        else:
            status = 'desativada'
        return [
            ('Rótulo', (row.get('label') if row else '') or '—'),
            ('Endereço', address),
            ('Stream', str(row.get('stream') if row else '—')),
            ('Criada em',
             self._format_identity_created((row or {}).get('created'))),
            ('Mensagens', str(total)),
            ('Conversas', str(peers)),
            ('Estado', status),
        ]

    def _fill_identity_details(self, window, address, row):
        try:
            alive = bool(window.winfo_exists())
        except Exception:
            return
        if not alive or getattr(self, '_closed', False):
            return
        frame = tk.Frame(window, bg=PANEL_BG)
        frame.pack(padx=16, pady=16, fill='both', expand=True)
        fields = self._identity_detail_fields(address, row)
        for number, (name, value) in enumerate(fields):
            tk.Label(frame, text=name + ':', bg=PANEL_BG, fg=TEXT_GRAY,
                     font=self.small_font).grid(row=number, column=0,
                                                sticky='nw', pady=3)
            text = tk.Label(frame, text=str(value), bg=PANEL_BG, fg=TEXT_INK,
                            font=self.preview_font, wraplength=360,
                            justify='left')
            text.grid(row=number, column=1, sticky='w', pady=3, padx=(10, 0))
        buttons = tk.Frame(window, bg=PANEL_BG)
        buttons.pack(side='bottom', fill='x', padx=12, pady=10)
        tk.Button(buttons, text='Copiar endereço',
                  command=lambda: self._copy_identity_address(address),
                  bg=PANEL_BG, fg=TEXT_INK, relief='solid',
                  bd=1).pack(side='left')
        tk.Button(buttons, text='Fechar', command=window.destroy,
                  bg=FAB_BG, fg='white', relief='flat').pack(side='right')

    def _manage_list_entries(self):
        try:
            rows = self.client.db.all_identities(enabled_only=False)
        except Exception:
            rows = []
        try:
            current = self._current_identity()
        except Exception:
            current = ''
        entries = []
        for row in rows:
            address = row.get('address')
            label = (row.get('label') if row else '') or 'Identidade'
            short = _short_address(address)
            suffix = ''
            if not row.get('enabled'):
                suffix += ' (desativada)'
            if address == current:
                suffix += ' [em uso]'
            entries.append((address, '%s  %s%s' % (label, short, suffix)))
        return entries

    def _refresh_manage_window(self, window):
        try:
            listbox = window._ident_listbox
        except Exception:
            return
        try:
            entries = self._manage_list_entries()
        except Exception:
            entries = []
        try:
            window._ident_addrs = [a for a, _d in entries]
            listbox.delete(0, 'end')
            for _address, display in entries:
                listbox.insert('end', display)
        except Exception:
            return
        try:
            window._ident_count.config(
                text='%d identidade(s)' % len(entries))
        except Exception:
            pass

    def _manage_selected_address(self, window):
        try:
            listbox = window._ident_listbox
            selection = listbox.curselection()
        except Exception:
            return None
        if not selection:
            return None
        try:
            return window._ident_addrs[selection[0]]
        except Exception:
            return None

    def _use_selected_identity(self, window):
        address = self._manage_selected_address(window)
        if address is None:
            self._flash_status('Selecione uma identidade')
            return
        if not self._set_current_identity(address):
            dialogs.warn(self, 'Identidade',
                         'Selecione uma identidade ativa.')
            return
        self._refresh_manage_window(window)

    def _details_selected_identity(self, window):
        address = self._manage_selected_address(window)
        if address is None:
            self._flash_status('Selecione uma identidade')
            return
        self._show_identity_details(address)

    def _rename_selected_identity(self, window):
        address = self._manage_selected_address(window)
        if address is None:
            self._flash_status('Selecione uma identidade')
            return
        if self._rename_identity(address):
            self._refresh_manage_window(window)

    def _toggle_selected_identity(self, window):
        address = self._manage_selected_address(window)
        if address is None:
            self._flash_status('Selecione uma identidade')
            return
        row = self._identity_row(address)
        if row is None:
            return
        enabled = not bool(row.get('enabled'))
        if self._set_identity_enabled_ui(address, enabled):
            self._refresh_manage_window(window)

    def _delete_selected_identity(self, window):
        address = self._manage_selected_address(window)
        if address is None:
            self._flash_status('Selecione uma identidade')
            return
        if self._delete_identity(address):
            self._refresh_manage_window(window)

    def _new_from_manage(self, window):
        self._new_identity()
        try:
            self._refresh_manage_window(window)
        except Exception:
            pass

    def _manage_identities(self):
        window = self._dialog_shell('Gerenciar identidades', '560x420')
        header = tk.Frame(window, bg=PANEL_BG)
        header.pack(fill='x', padx=12, pady=(10, 4))
        count = tk.Label(header, text='…', bg=PANEL_BG, fg=TEXT_GRAY,
                         font=self.small_font)
        count.pack(side='left')
        body = tk.Frame(window, bg=PANEL_BG)
        body.pack(fill='both', expand=True, padx=12)
        scrollbar = tk.Scrollbar(body, orient='vertical')
        listbox = tk.Listbox(body, bg='#f1f3f5', fg=TEXT_INK,
                             selectbackground=FAB_BG,
                             selectforeground='white', height=12,
                             yscrollcommand=scrollbar.set,
                             exportselection=False, activestyle='none',
                             highlightthickness=0, bd=0,
                             font=self.preview_font)
        scrollbar.config(command=listbox.yview)
        listbox.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        buttons = tk.Frame(window, bg=PANEL_BG)
        buttons.pack(side='bottom', fill='x', padx=12, pady=10)
        tk.Button(buttons, text='Usar',
                  command=lambda: self._use_selected_identity(window),
                  bg=FAB_BG, fg='white', relief='flat').pack(side='left')
        tk.Button(buttons, text='Detalhes',
                  command=lambda: self._details_selected_identity(window),
                  bg=PANEL_BG, fg=TEXT_INK, relief='solid',
                  bd=1).pack(side='left', padx=(8, 0))
        tk.Button(buttons, text='Renomear',
                  command=lambda: self._rename_selected_identity(window),
                  bg=PANEL_BG, fg=TEXT_INK, relief='solid',
                  bd=1).pack(side='left', padx=(8, 0))
        tk.Button(buttons, text='Ativar/Desativar',
                  command=lambda: self._toggle_selected_identity(window),
                  bg=PANEL_BG, fg=TEXT_INK, relief='solid',
                  bd=1).pack(side='left', padx=(8, 0))
        tk.Button(buttons, text='Excluir',
                  command=lambda: self._delete_selected_identity(window),
                  bg=PANEL_BG, fg='#b00020', relief='solid',
                  bd=1).pack(side='left', padx=(8, 0))
        second = tk.Frame(window, bg=PANEL_BG)
        second.pack(side='bottom', fill='x', padx=12, pady=(0, 10))
        tk.Button(second, text='Nova identidade…',
                  command=lambda: self._new_from_manage(window),
                  bg=PANEL_BG, fg=TEXT_INK, relief='solid',
                  bd=1).pack(side='left')
        tk.Button(second, text='Fechar', command=window.destroy,
                  bg=PANEL_BG, fg=TEXT_INK, relief='solid',
                  bd=1).pack(side='right')
        window._ident_listbox = listbox
        window._ident_count = count
        window._ident_addrs = []
        self._refresh_manage_window(window)
        return window

    # -------------------------------------------------- conversations

    def _collect_contact_convs(self):
        try:
            contacts = self.client.db.all_contacts()
        except Exception:
            contacts = []
        for contact in contacts:
            self._conv_meta.append(('contact', contact['address']))
            self._conv_labels.append(contact['label'] or contact['address'])

    def _collect_sub_convs(self):
        try:
            subs = self.client.db.all_subscriptions()
        except Exception:
            subs = []
        for sub in subs:
            addr = sub['address']
            if any(a == addr for _, a in self._conv_meta):
                continue
            self._conv_meta.append(('channel', addr))
            self._conv_labels.append(
                '# ' + ((sub.get('name') or sub.get('label')) or addr))

    def _collect_chan_convs(self):
        try:
            for ident in self.client.db.all_identities(enabled_only=False):
                if not ident.get('chan'):
                    continue
                addr = ident['address']
                if any(a == addr for _, a in self._conv_meta):
                    continue
                self._conv_meta.append(('channel', addr))
                self._conv_labels.append(
                    '# ' + (ident.get('chan_label') or ident.get('label') or addr))
        except Exception:
            pass

    def _refresh_conversations(self):
        self._conv_meta = []
        self._conv_labels = []
        self._collect_contact_convs()
        self._collect_sub_convs()
        self._collect_chan_convs()
        if self._conv_selected is not None and \
                self._conv_selected >= len(self._conv_meta):
            self._conv_selected = None
        self._draw_conversations()

    def _unread_for(self, address):
        rows = self.client.db.query(
            "SELECT COUNT(*) AS n FROM messages WHERE "
            "from_address=? AND status='received'", (address,))
        return rows[0]['n'] if rows else 0

    def _unread_counts(self):
        try:
            rows = self.client.db.query(
                "SELECT CASE WHEN to_address LIKE 'BM-%' AND from_address != to_address "
                "THEN to_address ELSE from_address END AS address, COUNT(*) AS n FROM "
                "messages WHERE status='received' GROUP BY address")
        except Exception:
            return {}
        try:
            return {r['address']: r['n'] for r in rows}
        except Exception:
            return {}

    def _last_message_row(self, address):
        try:
            rows = self.client.db.query(
                'SELECT body, timestamp FROM messages WHERE '
                'to_address=? OR from_address=? '
                'ORDER BY timestamp DESC, id DESC LIMIT 1',
                (address, address))
        except Exception:
            return None
        return rows[0] if rows else None

    def _last_message_for(self, address):
        last = self._last_message_row(address)
        if not last:
            return '', ''
        body = (last['body'] or '').replace('\n', ' ').strip()
        return body, _clock(last['timestamp'])

    def _measure_text_width(self, font, text):
        fm_cache = self._font_measure_cache
        mkey = (id(font), text)
        text_w = fm_cache.get(mkey)
        if text_w is None:
            text_w = font.measure(text)
            fm_cache[mkey] = text_w
            if len(fm_cache) > 2000:
                # Simple LRU: clear half
                for k in list(fm_cache.keys())[:1000]:
                    fm_cache.pop(k, None)
        return text_w

    def _ellipsis_for(self, font):
        # Cached ellipsis width per font
        ell_w = self._ellipsis_w.get(id(font))
        if ell_w is None:
            ell_w = font.measure('…')
            self._ellipsis_w[id(font)] = ell_w
        return ell_w

    def _fit_text(self, font, text, max_width, text_w):
        if text_w <= max_width:
            return text
        avail = max_width - self._ellipsis_for(font)
        count = len(text)
        if avail <= 0 or count == 0:
            return '…'
        avg = text_w / count
        cut = int(avail / avg) if avg > 0 else 0
        if cut < 0:
            cut = 0
        elif cut > count:
            cut = count
        return text[:cut] + '…'

    def _remember_fit(self, key, fitted):
        try:
            self._fit_cache[key] = fitted
            self._fit_order.append(key)
            while len(self._fit_order) > 300:
                old = self._fit_order.pop(0)
                self._fit_cache.pop(old, None)
        except Exception:
            pass

    def _fit_cached(self, font, text, max_width):
        """Elipse com cache FIFO (~300) + estimativa aritmética (1 measure).

        Acerto de cache: 0 measure. Erro: 1 measure do texto + '…' cached.
        Usa id(font) para chave estável (font.name pode variar).
        """
        try:
            key = (id(font), text, max_width)
        except Exception:
            return _fit_width(font, text, max_width)
        try:
            hit = self._fit_cache.get(key)
        except Exception:
            hit = None
        if hit is not None:
            return hit
        try:
            fitted = self._fit_text(
                font, text, max_width,
                self._measure_text_width(font, text))
        except Exception:
            return _fit_width(font, text, max_width)
        self._remember_fit(key, fitted)
        return fitted

    def _preview_map(self):
        """Preview da última mensagem de cada conversa em 1 query (item 3).

        Um GROUP BY sobre MAX(timestamp) por par + join busca corpo/timestamp
        das mensagens mais recentes de todas as conversas de uma vez (sem
        N×LIMIT 1). Empates de timestamp usam o maior id — a mesma semântica
        de _last_message_row (ORDER BY timestamp DESC, id DESC LIMIT 1).
        Retorna {address: (preview, clock)} com o mesmo formato de
        _last_message_for.
        """
        addresses = [address for _kind, address in self._conv_meta]
        if not addresses:
            return {}
        try:
            addrset = set(addresses)
            marks = ','.join('?' for _ in addresses)
            peer_expr = ('CASE WHEN from_address IN (%s) THEN from_address '
                         'ELSE to_address END' % marks)
            rows = self.client.db.query(
                'SELECT m.from_address AS fa, m.to_address AS ta, '
                'm.body AS body, m.timestamp AS timestamp, m.id AS mid '
                'FROM messages m INNER JOIN ('
                'SELECT %s AS peer, MAX(timestamp) AS mts FROM messages '
                'WHERE from_address IN (%s) OR to_address IN (%s) '
                'GROUP BY peer) latest '
                'ON %s = latest.peer AND m.timestamp = latest.mts'
                % (peer_expr, marks, marks, peer_expr),
                tuple(addresses) * 4)
        except Exception:
            return {}
        try:
            best = {}
            for row in rows:
                peer = row['fa'] if row['fa'] in addrset else row['ta']
                if peer not in best or row['mid'] > best[peer]['mid']:
                    best[peer] = row
            result = {}
            for peer, row in best.items():
                body = (row['body'] or '').replace('\n', ' ').strip()
                result[peer] = (body, _clock(row['timestamp']))
        except Exception:
            return {}
        return result

    def _visible_rows(self):
        if not self._conv_filter:
            return list(range(len(self._conv_meta)))
        needle = self._conv_filter
        return [i for i, label in enumerate(self._conv_labels)
                if needle in label.lower()]

    def _draw_conversations(self):
        canvas = self.conv_canvas
        canvas.delete('all')
        width = canvas.winfo_width() or 300
        rows = self._visible_rows()
        unread_map = self._unread_counts()
        preview_map = self._preview_map()
        fit = self._fit_cached
        y = 0
        self._row_tops = []

        # Group by kind: contacts first, then channels
        contacts = [(i, self._conv_meta[i], self._conv_labels[i])
                    for i in rows if self._conv_meta[i][0] == 'contact']
        channels = [(i, self._conv_meta[i], self._conv_labels[i])
                    for i in rows if self._conv_meta[i][0] == 'channel']

        def draw_section(section_items, section_title):
            nonlocal y
            if not section_items:
                return
            # Section header
            canvas.create_rectangle(0, y, width, y + 24, fill=PANEL_BG, outline=PANEL_BG)
            canvas.create_text(16, y + 12, anchor='w', text=section_title,
                               fill=TEXT_GRAY, font=self.small_font)
            y += 24
            for index, (kind, address), label in section_items:
                self._row_tops.append((y, index))
                preview, clock = preview_map.get(address, ('', ''))
                unread = unread_map.get(address, 0)
                selected = index == self._conv_selected
                hover = index == getattr(self, '_conv_hover_index', None)
                bg = ROW_SELECTED if selected else (
                    ROW_HOVER if hover else PANEL_BG)
                canvas.create_rectangle(0, y, width, y + ROW_H, fill=bg,
                                        outline=bg)
                # Avatar with different style for channels
                color = _avatar_color(address)
                is_channel = kind == 'channel'
                if is_channel:
                    # Channel: square-ish avatar with # symbol
                    x0 = 12
                    y0 = y + ROW_H / 2 - AVATAR_R
                    x1 = 12 + AVATAR_R * 2
                    y1 = y + ROW_H / 2 + AVATAR_R
                    canvas.create_oval(x0, y0, x1, y1, fill=color, outline=color)
                    canvas.create_text(12 + AVATAR_R, y + ROW_H / 2,
                                       text='#', fill='white',
                                       font=self.avatar_font)
                else:
                    # Contact: round avatar with initials
                    canvas.create_oval(12, y + ROW_H / 2 - AVATAR_R, 12 + AVATAR_R * 2,
                                       y + ROW_H / 2 + AVATAR_R, fill=color,
                                       outline=color)
                    canvas.create_text(12 + AVATAR_R, y + ROW_H / 2,
                                       text=_initials(label), fill='white',
                                       font=self.avatar_font)
                clock_w = self.small_font.measure(clock) if clock else 0
                name_w = width - 70 - clock_w - 16
                canvas.create_text(66, y + 10, anchor='nw',
                                   text=fit(self.name_font, label, name_w),
                                   fill=TEXT_INK, font=self.name_font)
                if clock:
                    canvas.create_text(width - 10, y + 10, anchor='ne',
                                       text=clock, fill=TIME_GRAY,
                                       font=self.small_font)
                # Show preview with sender indicator for incoming
                prev_w = width - 76 - (34 if unread else 0)
                preview_text = preview
                preview_color = TEXT_GRAY
                if preview and not is_channel:
                    # Try to determine if last message was incoming
                    pass
                canvas.create_text(66, y + 34, anchor='nw',
                                   text=fit(self.preview_font, preview_text,
                                            prev_w),
                                   fill=preview_color, font=self.preview_font)
                if unread:
                    badge = str(unread) if unread < 100 else '99+'
                    bw = max(22, self.small_font.measure(badge) + 12)
                    canvas.create_oval(width - 12 - bw, y + ROW_H - 30,
                                       width - 12, y + ROW_H - 8, fill=BADGE_BG,
                                       outline=BADGE_BG)
                    canvas.create_text(width - 12 - bw / 2, y + ROW_H - 19,
                                       text=badge, fill='white',
                                       font=self.small_font)
                y += ROW_H

        draw_section(contacts, 'Contatos')
        draw_section(channels, 'Canais')

        canvas.create_line(0, 0, 0, max(y, 1), fill=LINE)
        canvas.configure(scrollregion=(0, 0, width, y))

    def _conv_index_at(self, y):
        canvas_y = self.conv_canvas.canvasy(y)
        for top, index in getattr(self, '_row_tops', []):
            if top <= canvas_y < top + ROW_H:
                return index
        return None

    def _conv_click(self, event):
        index = self._conv_index_at(event.y)
        if index is None:
            return
        self._conv_selected = index
        self._draw_conversations()
        callback = self.conv_list._bindings.get('<<ListboxSelect>>')
        if callback is not None:
            callback(None)
        else:
            self._on_conv_select(None)

    def _conv_hover(self, event):
        try:
            index = self._conv_index_at(event.y)
        except Exception:
            return
        if index != getattr(self, '_conv_hover_index', None):
            self._conv_hover_index = index
            self._schedule_conv_redraw()

    def _cancel_hover_after(self):
        pending = getattr(self, '_conv_hover_after', None)
        if pending is None:
            return
        try:
            self.after_cancel(pending)
        except Exception:
            pass
        self._conv_hover_after = None

    def _apply_debounced_hover(self, y):
        self._conv_hover_after = None
        try:
            fake = type('E', (), {'y': y})()
            self._conv_hover(fake)
        except Exception:
            pass

    def _schedule_hover_apply(self, y):
        try:
            self._conv_hover_after = self.after(
                80, lambda: self._apply_debounced_hover(y))
        except Exception:
            self._conv_hover_after = None

    def _conv_hover_debounced(self, event):
        if getattr(self, '_closed', False):
            return
        self._cancel_hover_after()
        try:
            y = event.y
        except Exception:
            return
        self._schedule_hover_apply(y)

    def _schedule_conv_redraw(self):
        if getattr(self, '_closed', False):
            return
        pending = getattr(self, '_conv_draw_after', None)
        if pending is not None:
            try:
                self.after_cancel(pending)
            except Exception:
                pass
        try:
            self._conv_draw_after = self.after(80, self._do_conv_redraw)
        except Exception:
            self._conv_draw_after = None

    def _do_conv_redraw(self):
        self._conv_draw_after = None
        if getattr(self, '_closed', False):
            return
        try:
            self._draw_conversations()
        except Exception as exc:
            try:
                self.statusbar.config(
                    text='Erro ao desenhar conversas: %s' % exc)
            except Exception:
                pass

    def _conv_leave(self, _event):
        if getattr(self, '_conv_hover_index', None) is not None:
            self._conv_hover_index = None
            self._draw_conversations()

    def _conv_right_click(self, event):
        index = self._conv_index_at(event.y)
        if index is None:
            return
        self._conv_selected = index
        self._draw_conversations()
        kind, address = self._conv_meta[index]
        label = self._conv_labels[index] \
            if index < len(self._conv_labels) else address
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(
            label='Abrir',
            command=lambda: self._open_conversation(kind, address))
        menu.add_command(
            label='Copiar endereço',
            command=lambda: self._copy_address(address))
        menu.add_separator()
        menu.add_command(
            label='Excluir conversa',
            command=lambda: self._delete_conversation(kind, address, label))
        menu.add_command(
            label='Remover contato',
            command=lambda: self._remove_entry(kind, address, label))
        menu.tk_popup(event.x_root, event.y_root)
        self._track_menu(menu)

    def _delete_conversation(self, kind, address, label):
        ok = dialogs.confirm(
            self, 'Excluir conversa',
            'Apagar todas as mensagens com %s?\n'
            'O contato é mantido.' % label)
        if not ok:
            return
        self.client.db.delete_conversation(address)
        if getattr(self, 'current_address', None) == address:
            self._show_welcome()
        else:
            self._refresh_conversations()

    def _remove_entry(self, kind, address, label):
        if kind == 'channel':
            ok = dialogs.confirm(
                self, 'Remover',
                'Remover inscrição no canal %s e apagar a conversa?' % label)
            if not ok:
                return
            try:
                self.client.unsubscribe(address)
            except Exception:
                try:
                    self.client.db.delete_conversation(address)
                except Exception:
                    pass
        else:
            ok = dialogs.confirm(
                self, 'Remover',
                'Remover %s dos contatos e apagar a conversa?' % label)
            if not ok:
                return
            # Command Pattern: encapsula remoção
            cmd = DeleteContactCommand(self.client, address)
            status, error = self._command_history.execute(cmd)
            if status not in ('success',):
                dialogs.warn(self, 'Remover contato', error or status)
                return
        if getattr(self, 'current_address', None) == address:
            self._show_welcome()
        else:
            self._refresh_conversations()

    def _copy_address(self, address):
        self.clipboard_clear()
        self.clipboard_append(address)
        self._flash_status('Endereço copiado')

    def _on_conv_select(self, _event):
        selection = self.conv_list.curselection()
        if not selection:
            return
        index = selection[0]
        if not 0 <= index < len(self._conv_meta):
            return
        kind, address = self._conv_meta[index]
        self._open_conversation(kind, address)

    def _reset_chat_state(self):
        try:
            self._wrap_cache.clear()
            self._wrap_order.clear()
        except Exception:
            self._wrap_cache = {}
            self._wrap_order = []

    def _contact_header(self, address):
        row = self.client.db.get_contact(address)
        label = row['label'] if row else address
        # Bitmessage não tem presença: o único estado real que
        # conhecemos do contato é se já temos a chave pública dele.
        if self.client.has_pubkey(address):
            status = 'chave pública conhecida'
        else:
            status = 'aguardando chave pública…'
        return label, status

    def _channel_header(self, address):
        row = None
        try:
            row = self.client.db.get_subscription(address)
        except Exception:
            row = None
        if row:
            label = (row.get('name') or row.get('label')) or address
            return '# ' + label, 'canal Bitmessage (broadcast)'
        try:
            ident = self.client.db.get_identity(address)
        except Exception:
            ident = None
        if ident:
            label = '# ' + ((ident.get('chan_label') or ident.get('label')) or address)
        else:
            label = '# ' + address
        return label, 'canal Bitmessage (broadcast)'

    def _fallback_header(self, address):
        row = self.client.db.get_contact(address)
        label = (row['label'] if row else '') or address
        status = address[:18] + '…' if len(address) > 19 else address
        return label, status

    def _paint_chat_header(self, address, label, status):
        self.chat_title.config(text=label)
        self.chat_subtitle.config(text=status)
        color = _avatar_color(address)
        self.peer_avatar.delete('all')
        self.peer_avatar.create_oval(1, 1, 35, 35, fill=color, outline=color)
        self.peer_avatar.create_text(18, 18, text=_initials(label),
                                     fill='white', font=('', 11, 'bold'))

    def _open_conversation(self, kind, address):
        self.current_kind = kind
        self.current_address = address
        self.input_var.set('')
        self._set_placeholder()
        self._chat_limit = 200
        self._chat_has_more = False
        self._chat_pill = None
        self._reset_chat_state()
        self._set_input_enabled(True)
        if kind == 'contact':
            label, status = self._contact_header(address)
        elif kind == 'channel':
            label, status = self._channel_header(address)
        else:
            label, status = self._fallback_header(address)
        self._paint_chat_header(address, label, status)
        self.client.db.execute(
            "UPDATE messages SET status='read' WHERE "
            "(from_address=? OR to_address=?) AND status='received'",
            (address, address))
        self._stick_bottom = True
        self._reload_chat()
        self._refresh_conversations()
        self._update_triage_banner()
        try:
            self.input_entry.focus_set()
        except Exception:
            pass

    def _update_triage_banner(self):
        try:
            if getattr(self, 'current_address', None) == SUPPORT_ADDRESS:
                self.triage_banner.grid()
            else:
                self.triage_banner.grid_remove()
        except Exception:
            pass

    # -------------------------------------------------- chat canvas

    def _schedule_chat_redraw(self):
        # Item 6: nada após o fechamento.
        if getattr(self, '_closed', False):
            return
        # Item 4: <Configure> sem mudança de largura não precisa de relayout
        # (o layout das bolhas só depende da largura). Chamadas diretas via
        # _reload_chat continuam redesenhando sempre.
        try:
            width_now = self.chat_canvas.winfo_width()
        except Exception:
            width_now = None
        if width_now and width_now == getattr(self, '_last_chat_w', None):
            return
        if self._redraw_after is not None:
            try:
                self.after_cancel(self._redraw_after)
            except Exception:
                pass
        try:
            self._redraw_after = self.after(120, self._redraw_chat)
        except Exception:
            self._redraw_after = None

    def _chat_yview(self, *args):
        self.chat_canvas.yview(*args)
        # Virtual scroll: re-render on scroll to show new items
        if len(args) >= 1 and args[0] == 'moveto':
            self._schedule_chat_redraw()
        elif len(args) >= 2 and args[0] == 'scroll':
            self._schedule_chat_redraw()

    def _chat_yscroll(self, first, last):
        self.chat_scroll.set(first, last)
        try:
            at_bottom = float(last) >= 0.999
        except Exception:
            at_bottom = True
        self._stick_bottom = at_bottom
        if at_bottom:
            self.jump_btn.place_forget()
        else:
            self.jump_btn.place(relx=1.0, rely=1.0, x=-44, y=-44,
                                anchor='center')
            self.jump_btn.lift()

    def _cached_wrap(self, body, inner_w):
        key = (body or '', inner_w)
        try:
            hit = self._wrap_cache.get(key)
        except Exception:
            hit = None
        if hit is not None:
            return hit
        lines = _wrap_lines_cached(self.msg_font, body or '(vazio)', inner_w, self._font_measure_cache)
        try:
            self._wrap_cache[key] = lines
            self._wrap_order.append(key)
            if len(self._wrap_order) > 500:
                old = self._wrap_order.pop(0)
                self._wrap_cache.pop(old, None)
        except Exception:
            pass
        return lines

    def _chat_click(self, event):
        pill = getattr(self, '_chat_pill', None)
        if pill and getattr(self, '_chat_has_more', False):
            try:
                x = self.chat_canvas.canvasx(event.x)
                y = self.chat_canvas.canvasy(event.y)
                x0, y0, x1, y1 = pill
                if x0 <= x <= x1 and y0 <= y <= y1:
                    self._chat_limit = int(
                        getattr(self, '_chat_limit', 200)) + 200
                    self._stick_bottom = False
                    self._reload_chat()
                    return
            except Exception:
                pass

    def _reload_chat(self):
        if getattr(self, 'current_address', None):
            limit = int(getattr(self, '_chat_limit', 200) or 200)
            try:
                self._chat_rows = self.client.db.messages_for_conversation(
                    self.current_address, limit=limit)
            except TypeError:
                rows = self.client.db.messages_for_conversation(
                    self.current_address)
                self._chat_rows = rows[-limit:]
            try:
                cnt = self.client.db.query(
                    'SELECT COUNT(*) AS n FROM messages WHERE '
                    'to_address=? OR from_address=?',
                    (self.current_address, self.current_address))
                total = cnt[0]['n'] if cnt else len(self._chat_rows)
            except Exception:
                total = len(self._chat_rows)
            self._chat_has_more = total > len(self._chat_rows)
        else:
            self._chat_rows = []
            self._chat_has_more = False
            self._chat_pill = None
        self.chat_text._plain = '\n\n'.join(
            (r['body'] or '') for r in self._chat_rows)
        self.chat_text._tags = {'meta', 'self', 'other'}
        self._redraw_chat()

    def _sender_label(self, row):
        return ''

    def _draw_welcome(self, canvas, width, height):
        canvas.create_rectangle(0, 0, width, height, fill=CHAT_BG,
                                outline=CHAT_BG)
        addresses = list(self.client.identities.keys())
        mine = self._current_identity() if addresses else ''
        title_font = getattr(self, 'welcome_title_font', None) or getattr(
            self, 'title_font', None) or self.msg_font
        lines = [
            ('Bem-vindo ao bmchat', title_font, TEXT_INK),
            ('Minha identidade — envie este endereço aos seus contatos:',
             self.preview_font, TEXT_GRAY),
        ]
        addr_lines = _wrap_lines(self.sender_font, mine, 380) if mine else \
            ['(crie uma identidade no menu ☰)']
        for line in addr_lines:
            lines.append((line, self.sender_font, HEADER_BG))
        lines.append(('Copie o endereço e envie por qualquer meio: e-mail, '
                      'mensagem, papel.', self.preview_font, TEXT_GRAY))
        connected = self.client.net.connection_count
        proxy = self.client.net.proxy.describe() \
            if self.client.net.proxy else 'Direto'
        lines.append(('Rede: %d conexões | Proxy: %s' % (connected, proxy),
                      self.small_font, TEXT_GRAY))
        line_h = self.preview_font.metrics('linespace')
        title_h = title_font.metrics('linespace')
        addr_h = self.sender_font.metrics('linespace')
        small_h = self.small_font.metrics('linespace')
        heights = [title_h + 10 if i == 0 else
                   (addr_h + 4 if f is self.sender_font else
                    (small_h + 4 if f is self.small_font else line_h + 4))
                   for i, (_t, f, _c) in enumerate(lines)]
        card_h = sum(heights) + 32
        card_w = min(480, width - 40)
        x0 = (width - card_w) / 2
        y0 = 48
        self._bubble(canvas, x0, y0, x0 + card_w, y0 + card_h, BUBBLE_IN,
                     False, tail=False)
        cy = y0 + 16
        for i, (text, font, color) in enumerate(lines):
            canvas.create_text(x0 + 20, cy, anchor='nw', text=text,
                               fill=color, font=font)
            cy += heights[i]
        canvas.configure(scrollregion=(0, 0, width, y0 + card_h + 80))
        if mine:
            self.welcome_copy_btn.place(x=width / 2, y=y0 + card_h + 28,
                                        anchor='center')

    def _support(self):
        # Item 5: casca aparece já; corpo em after_idle.
        window = self._dialog_shell('Suporte')
        window.resizable(False, False)
        try:
            window.after_idle(lambda: self._fill_support(window))
        except Exception:
            pass

    def _fill_support(self, window):
        try:
            alive = bool(window.winfo_exists())
        except Exception:
            return
        if not alive or getattr(self, '_closed', False):
            return
        frame = tk.Frame(window, bg=PANEL_BG)
        frame.pack(padx=16, pady=16, fill='both', expand=True)
        tk.Label(frame, text='Suporte do bmchat', bg=PANEL_BG, fg=TEXT_INK,
                 font=self.title_font).pack(anchor='w')
        tk.Label(
            frame,
            text=('Dúvidas, problemas ou sugestões? Fale com o suporte pelo '
                  'endereço oficial abaixo. A conversa é cifrada pelo '
                  'protocolo Bitmessage; a resposta pode levar minutos, '
                  'pois cada mensagem exige prova de trabalho nos dois '
                  'lados. Se pedirem, envie junto o conteúdo de Ver log e '
                  'do Diagnóstico de rede (ambos têm botão de copiar).'),
            bg=PANEL_BG, fg=TEXT_GRAY, font=self.preview_font,
            wraplength=420, justify='left').pack(anchor='w', pady=(8, 4))
        addr_box = tk.Frame(frame, bg=PANEL_BG)
        addr_box.pack(fill='x', pady=4)
        tk.Label(addr_box, text=SUPPORT_ADDRESS, bg='#eef2f5', fg=TEXT_INK,
                 font=self.sender_font, padx=8, pady=6).pack(
                     side='left', fill='x', expand=True)
        tk.Button(addr_box, text='Copiar',
                  command=lambda: self._clipboard_text(SUPPORT_ADDRESS),
                  bg=PANEL_BG, fg=TEXT_INK, relief='solid',
                  bd=1).pack(side='left', padx=(8, 0))
        buttons = tk.Frame(frame, bg=PANEL_BG)
        buttons.pack(fill='x', pady=(12, 0))
        tk.Button(buttons, text='Conversar agora',
                  command=lambda: self._talk_to_support(window),
                  bg=FAB_BG, fg='white', relief='flat').pack(side='left')
        tk.Button(buttons, text='Enviar diagnóstico',
                  command=self._open_diagnostics_preview,
                  bg=PANEL_BG, fg=TEXT_INK, relief='solid',
                  bd=1).pack(side='left', padx=(8, 0))
        tk.Button(buttons, text='Fechar', command=window.destroy,
                  bg=PANEL_BG, fg=TEXT_INK, relief='solid',
                  bd=1).pack(side='right')

    def _send_diagnostics(self):
        if getattr(self, 'current_address', None) != SUPPORT_ADDRESS:
            return
        self._open_diagnostics_preview()

    def _open_diagnostics_preview(self):
        # Item 5: casca aparece já; relatório (pesado) + Text em after_idle.
        window = self._dialog_shell('Enviar diagnóstico ao suporte',
                                    '620x520')
        try:
            window.after_idle(
                lambda: self._fill_diagnostics_preview(window))
        except Exception:
            pass

    def _fill_diagnostics_preview(self, window):
        try:
            alive = bool(window.winfo_exists())
        except Exception:
            return
        if not alive or getattr(self, '_closed', False):
            return
        try:
            report = _build_support_report(self.client)
        except Exception as exc:
            report = '(erro ao gerar relatório: %s)' % exc
        tk.Label(
            window,
            text=('Confira exatamente o que será enviado. Nada sai deste '
                  'computador sem o seu clique em Enviar. Não incluído: '
                  'chaves privadas e conteúdo das mensagens.'),
            bg=PANEL_BG, fg=TEXT_GRAY, font=self.small_font, wraplength=580,
            justify='left').pack(fill='x', padx=12, pady=(10, 4))
        buttons = tk.Frame(window, bg=PANEL_BG)
        buttons.pack(side='bottom', fill='x', padx=12, pady=10)
        send_btn = tk.Button(buttons, text='Enviar ao suporte',
                             command=lambda: self._do_send_diagnostics(
                                 window, report),
                             bg=FAB_BG, fg='white', relief='flat',
                             state='disabled')
        send_btn.pack(side='left')
        tk.Button(buttons, text='Copiar',
                  command=lambda: self._clipboard_text(report),
                  bg=PANEL_BG, fg=TEXT_INK, relief='solid',
                  bd=1).pack(side='left', padx=(8, 0))
        tk.Button(buttons, text='Cancelar', command=window.destroy,
                  bg=PANEL_BG, fg=TEXT_INK, relief='solid',
                  bd=1).pack(side='right')
        consent_var = tk.IntVar(value=0)
        tk.Checkbutton(
            window, text='Li o relatório acima e autorizo o envio ao suporte.',
            variable=consent_var, bg=PANEL_BG, fg=TEXT_INK,
            activebackground=PANEL_BG, font=self.preview_font,
            wraplength=580, justify='left',
            command=lambda: send_btn.config(
                state='normal' if consent_var.get() else 'disabled')).pack(
                    side='bottom', fill='x', padx=12, pady=(0, 4))
        text = tk.Text(window, wrap='word', font=self.preview_font,
                       bg=PANEL_BG, fg=TEXT_INK, highlightthickness=0, bd=0,
                       padx=12, pady=8)
        text.pack(fill='both', expand=True)
        text.insert('1.0', report)
        text.config(state='disabled')

    def _do_send_diagnostics(self, window, report):
        identity = self._current_identity()
        if not identity:
            dialogs.warn(self, 'Identidade ausente',
                         'Crie uma identidade antes de enviar.')
            return
        status, error = self.client.send_message(
            identity, SUPPORT_ADDRESS, '', report)
        if status != 'success':
            dialogs.warn(self, 'Erro', error or status)
            return
        try:
            window.destroy()
        except Exception:
            pass
        self._flash_status('Diagnóstico enviado ao suporte')

    def _talk_to_support(self, window):
        try:
            if self.client.db.get_contact(SUPPORT_ADDRESS) is None:
                self.client.add_contact(SUPPORT_ADDRESS, SUPPORT_LABEL)
        except Exception:
            pass
        self._refresh_conversations()
        self._open_conversation('contact', SUPPORT_ADDRESS)
        try:
            window.destroy()
        except Exception:
            pass

    def _copy_my_address(self):
        addresses = list(self.client.identities.keys())
        if not addresses:
            dialogs.warn(self, 'Minha identidade',
                         'Crie uma identidade primeiro (menu ☰).')
            return
        mine = self._current_identity()
        if mine not in addresses:
            mine = addresses[0]
        self.clipboard_clear()
        self.clipboard_append(mine)
        dialogs.info(self, 'Minha identidade',
                     'Endereço copiado, envie a um contato:\n%s' % mine)

    def _show_welcome(self):
        self.current_kind = None
        self.current_address = None
        self._conv_selected = None
        self.input_var.set('')
        self._set_placeholder()
        self._chat_has_more = False
        self._chat_pill = None
        try:
            self._wrap_cache.clear()
            self._wrap_order.clear()
        except Exception:
            pass
        self._set_input_enabled(False)
        self.chat_title.config(text='Selecione uma conversa')
        self.chat_subtitle.config(text='')
        self.peer_avatar.delete('all')
        self._stick_bottom = True
        self._reload_chat()
        self._draw_conversations()
        self._update_triage_banner()

    def _ticks(self, row):
        status = row['status']
        if status == 'ackreceived':
            return '✓✓', READ_BLUE
        if status == 'sent':
            return '✓✓', TIME_GRAY
        # M5: ack-failed com ícone próprio (antes caía no relógio).
        if status == 'ack-failed':
            return '⚠', '#c0392b'
        return 'clock', TIME_GRAY

    def _status_text(self, row):
        status = row['status']
        if row['direction'] == 'in':
            if status == 'read':
                return 'Recebida e lida'
            return 'Recebida'
        if status == 'awaiting-pubkey':
            return ('Aguardando chave pública do destinatário — '
                    'a mensagem ainda não foi publicada na rede')
        if status == 'sending':
            return ('Enviando — calculando a prova de trabalho e '
                    'publicando na rede')
        if status == 'sent':
            return ('Publicada na rede — aguardando a confirmação (ACK) '
                    'do destinatário')
        if status == 'ackreceived':
            return 'Entregue — confirmação (ACK) recebida do destinatário'
        if status == 'ack-failed':
            return ('Sem confirmação (ACK não recebido antes da expiração) — '
                    'o destinatário pode não ter recebido. '
                    'Clique com o botão direito → Reenviar (até 3 tentativas).')
        if status == 'sending':
            return 'Enviando — calculando prova de trabalho (PoW)…'
        return str(status)

    @staticmethod
    def _decode_layout_bytes(data):
        """ADV helper: b64->bytes com tetos (300k b64, 8MB raw). None se mal."""
        import base64
        if isinstance(data, str) and len(data) > 300_000:
            return None
        try:
            raw = base64.b64decode(data)
        except Exception:
            return None
        if len(raw) > 8 * 1024 * 1024:
            return None
        return raw

    @staticmethod
    def _scaled_height_for_width(img, max_width):
        """ADV helper: altura com teto 300px (igual ao render)."""
        max_img_w = min(300, max_width - 2 * PAD_X)
        if img.width > max_img_w or img.height > 300:
            ratio = min(max_img_w / max(1, img.width),
                        300 / max(1, img.height))
            return int(img.height * ratio) + 8
        return img.height + 8

    @staticmethod
    def _open_image_for_layout(img_data):
        """ADV helper: open+pixel-check+load. Retorna Image ou None."""
        from io import BytesIO
        from PIL import Image
        Image.MAX_IMAGE_PIXELS = 89430912
        try:
            img = Image.open(BytesIO(img_data))
        except Exception:
            return None
        try:
            if img.format not in ALLOWED_PREVIEW_FORMATS:
                return None
            if img.width * img.height > Image.MAX_IMAGE_PIXELS:
                return None
        except Exception:
            return None
        try:
            img.load()
        except Exception:
            return None
        return img

    def _calc_attachment_height(self, attachment, max_width, out):
        """Calculate height needed for an attachment."""
        if not attachment.get('mime', '').startswith('image/'):
            return 48  # file icon box height
        try:
            from PIL import Image
            Image.MAX_IMAGE_PIXELS = 89430912
            raw = self._decode_layout_bytes(attachment.get('data', ''))
            if raw is None:
                return 48
            img = self._open_image_for_layout(raw)
            if img is None:
                return 48
            return self._scaled_height_for_width(img, max_width)
        except Exception:
            return 48  # fallback

    @staticmethod
    def _sanitize_attachment_filename(name):
        """ADV: `:` e `]` quebram o marcador `[attachment:nome:mime:dados]`
        (`[^:]+`/`[^\\]]+` no parse). `:` é comum em nomes, então o parse
        aceita `:` no nome (greedy) e aqui só neutralizamos `]`/`[`/quebras,
        preservando o nome visível."""
        try:
            text = str(name or 'anexo')
        except Exception:
            text = 'anexo'
        return text.replace('[', '_').replace(']', '_').replace(
            '\n', '_').replace('\r', '_') or 'anexo'

    def _parse_attachments(self, body: str):
        """Parse attachment markers from message body.

        Returns (clean_body, attachments_list) where attachments_list contains
        dicts with filename, mime, data (base64).
        """
        import re
        attachments = []
        # ADV: nome pode conter `:` (ex. "meu:arquivo.txt") — primeiro grupo
        # greedy captura até os últimos `:mime:dados`. Mime nunca tem `:`.
        pattern = r'\[attachment:(.+):([^:\]]+):([^\]]+)\]'

        def replace(match):
            filename = match.group(1)
            mime = match.group(2)
            data = match.group(3)
            attachments.append({'filename': filename, 'mime': mime, 'data': data})
            return ''  # Remove marker from display body

        clean_body = re.sub(pattern, replace, body)
        return clean_body, attachments

    @staticmethod
    def _attachment_icon(mime):
        if mime.startswith('image/'):
            return '🖼'
        if mime.startswith('video/'):
            return '🎬'
        if mime.startswith('audio/'):
            return '🎵'
        if mime.startswith('text/'):
            return '📝'
        if mime == 'application/pdf':
            return '📕'
        return '📄'

    @staticmethod
    def _open_image_for_render(img_data):
        """ADV helper: open+pixel-check+load para render. None se mal."""
        from io import BytesIO
        from PIL import Image
        Image.MAX_IMAGE_PIXELS = 89430912
        if len(img_data) > 8 * 1024 * 1024:
            return None
        try:
            img = Image.open(BytesIO(img_data))
        except Exception:
            return None
        try:
            if img.format not in ALLOWED_PREVIEW_FORMATS:
                return None
            if img.width * img.height > Image.MAX_IMAGE_PIXELS:
                return None
        except Exception:
            return None
        try:
            img.load()
        except Exception:
            return None
        return img

    @staticmethod
    def _fit_image_to_bubble(img, max_width):
        """ADV helper: thumbnail in-place para caber na bolha."""
        from PIL import Image
        max_img_w = min(300, max_width - 2 * PAD_X)
        if img.width > max_img_w or img.height > 300:
            ratio = min(max_img_w / max(1, img.width),
                        300 / max(1, img.height))
            new_size = (max(1, int(img.width * ratio)),
                        max(1, int(img.height * ratio)))
            try:
                img.thumbnail(new_size, Image.LANCZOS)
            except Exception:
                img = img.resize(new_size, Image.LANCZOS)
        return img

    def _render_image_attachment(self, canvas, x, y, img_data, max_width):
        """Draw inline image; return height, or None to use file icon."""
        try:
            from PIL import ImageTk
            img = self._open_image_for_render(img_data)
            if img is None:
                return None
            img = self._fit_image_to_bubble(img, max_width)
            photo = ImageTk.PhotoImage(img)
            # Store reference to prevent GC (reconstruída a cada redraw).
            if not hasattr(self, '_chat_images'):
                self._chat_images = []
            self._chat_images.append(photo)
            # Create image on canvas
            canvas.create_image(x + PAD_X, y, anchor='nw', image=photo)
            return img.height + 8
        except Exception:
            return None  # Fall back to file icon

    def _render_attachment(self, canvas, x, y, attachment, max_width, out):
        """Render an attachment inline in the chat bubble."""
        filename = attachment['filename']
        mime = attachment['mime']
        data = attachment['data']

        import base64
        # A13: marcador gigante não deve alocar sem limite no redraw.
        if isinstance(data, str) and len(data) > 300_000:
            img_data = None
        else:
            try:
                # Decode base64 data
                img_data = base64.b64decode(data)
            except Exception:
                img_data = None

        height = None
        if mime.startswith('image/') and img_data is not None:
            # Try to create PhotoImage for inline display
            height = self._render_image_attachment(
                canvas, x, y, img_data, max_width)
        if height is not None:
            return height

        # File icon fallback
        icon = self._attachment_icon(mime)

        # Draw file preview box
        box_h = 40
        canvas.create_rectangle(x, y, x + max_width, y + box_h,
                                fill=BUBBLE_IN if not out else BUBBLE_OUT,
                                outline=DATE_BG)
        canvas.create_text(x + 10, y + box_h // 2, anchor='w',
                           text=f'{icon} {filename}', fill=TEXT_INK,
                           font=self.msg_font)
        return box_h + 8

    def _collect_chat_items(self):
        items = []
        last_day = None
        for row in self._chat_rows:
            day = _day_key(row['timestamp'])
            if day != last_day:
                items.append(('day', _day_label(day)))
                last_day = day
            items.append(('msg', row))
        return items

    def _layout_more_pill(self, layouts, y, width):
        if not getattr(self, '_chat_has_more', False):
            return y
        pill_text = 'carregar mensagens anteriores'
        pill_w = self.small_font.measure(pill_text) + 26
        px0 = width / 2 - pill_w / 2
        px1 = width / 2 + pill_w / 2
        self._chat_pill = (px0, y, px1, y + 22)
        layouts.append(('more', y, 22, pill_text))  # kind, top, height, text
        return y + 30

    def _message_stamp(self, row, out):
        stamp = _clock(row['timestamp'])
        if not out:
            return stamp, self.small_font.measure(stamp) + 6, False
        ticks, _color = self._ticks(row)
        if ticks == 'clock':
            return stamp, self.small_font.measure(stamp) + 8 + 16, True
        stamp_text = '%s %s' % (stamp, ticks)
        return stamp_text, self.small_font.measure(stamp_text) + 6, False

    def _layout_message_item(self, layout_ctx, item, layouts, y, msg_idx):
        max_bubble, line_h, small_h = layout_ctx
        row = item[1]
        out = row['direction'] == 'out'
        sender = '' if out else self._sender_label(row)
        inner_w = max_bubble - 2 * PAD_X
        # Parse attachments from body
        clean_body, attachments = self._parse_attachments(row['body'])
        lines = self._cached_wrap(clean_body, inner_w)
        text_w = 0
        for line in lines:
            text_w = max(text_w, self.msg_font.measure(line))
        # Calculate attachment heights
        attach_h = 0
        for att in attachments:
            attach_h += self._calc_attachment_height(att, inner_w, out)
        stamp_text, stamp_w, pending = self._message_stamp(row, out)
        needed = text_w
        last_w = self.msg_font.measure(lines[-1]) if lines else 0
        extra_row = last_w + 10 + stamp_w > inner_w
        if sender:
            sender_w = self.sender_font.measure(sender)
            needed = max(needed, sender_w)
        bubble_w = min(max_bubble, needed + 2 * PAD_X)
        item_h = 8 + len(lines) * line_h + 4 + attach_h
        if sender:
            item_h += small_h + 4
        if extra_row:
            item_h += small_h + 2
        else:
            bubble_w = min(max_bubble,
                           max(bubble_w, last_w + 10 + stamp_w +
                               2 * PAD_X))
        layouts.append(('msg', y, item_h, row, sender, lines,
                        stamp_text, out, bubble_w, extra_row,
                        pending, msg_idx, attachments))
        return y + item_h + 6, msg_idx + 1

    def _layout_all_items(self, layout_ctx, items, layouts, y):
        msg_idx = 0
        for item in items:
            if item[0] == 'day':
                layouts.append(('day', y, 30, item[1]))  # kind, top, height, label
                y += 30
                continue
            y, msg_idx = self._layout_message_item(
                layout_ctx, item, layouts, y, msg_idx)
        return y, msg_idx

    def _layout_chat(self, width):
        # VIRTUAL SCROLL: compute layout for all items but only RENDER visible ones
        max_bubble = int(width * 0.62)
        line_h = self.msg_font.metrics('linespace')
        small_h = self.small_font.metrics('linespace')
        items = self._collect_chat_items()
        layouts = []
        y = 14
        self._chat_pill = None
        y = self._layout_more_pill(layouts, y, width)
        y, _msg_idx = self._layout_all_items(
            (max_bubble, line_h, small_h), items, layouts, y)
        return layouts, y + 10

    def _visible_layout_range(self, canvas, layouts, view_h):
        # VIRTUAL SCROLL: find visible range
        # Canvas scroll position
        try:
            scroll_top = canvas.canvasy(0)
        except Exception:
            scroll_top = 0
        scroll_bottom = scroll_top + view_h
        buffer = 100  # px buffer above/below viewport
        first_vis = 0
        last_vis = len(layouts) - 1
        for i, lay in enumerate(layouts):
            if lay[1] + lay[2] >= scroll_top - buffer:
                first_vis = i
                break
        for i in range(len(layouts) - 1, -1, -1):
            if layouts[i][1] <= scroll_bottom + buffer:
                last_vis = i
                break
        self._chat_first_visible = first_vis
        self._chat_last_visible = last_vis
        return first_vis, last_vis

    def _draw_chat_background(self, canvas, width, total, view_h):
        doodle_h = min(total, view_h + 240)
        canvas.create_rectangle(0, 0, width, total, fill=CHAT_BG,
                                outline=CHAT_BG)
        glyphs = ['✈', '☁', '★', '♫', '✉', '☎', '⚓', '✿']
        gx, gi = 20, 0
        gy = 20
        step = 110 if total <= 3000 else 180
        while gy < doodle_h:
            while gx < width:
                canvas.create_text(gx, gy, text=glyphs[gi % len(glyphs)],
                                   fill=DOODLE, font=('', 22))
                gi += 1
                gx += step
            gx = 20 + (gi % 3) * 30
            gy += step

    def _draw_more_pill(self, canvas, layout, width):
        _kind, top, _h, label = layout
        x0, y0, x1, y1 = self._chat_pill
        canvas.create_oval(x0, y0, x1, y1, fill=DATE_BG,
                           outline=DATE_BG)
        canvas.create_text(width / 2, top + 11, text=label,
                           fill='white', font=self.small_font)

    def _draw_day_pill(self, canvas, layout, width):
        _kind, top, _h, label = layout
        pill_w = self.small_font.measure(label) + 26
        canvas.create_oval(width / 2 - pill_w / 2, top,
                           width / 2 + pill_w / 2, top + 22,
                           fill=DATE_BG, outline=DATE_BG)
        canvas.create_text(width / 2, top + 11, text=label,
                           fill='white', font=self.small_font)

    def _draw_message_layout(self, canvas, layout, width, line_h,
                             small_h):
        (_, top, height, row, sender, lines, stamp_text, out,
         bubble_w, _extra_row, pending, _msg_idx, attachments) = layout
        if out:
            x1 = width - 12
            x0 = x1 - bubble_w
        else:
            x0 = 12
            x1 = x0 + bubble_w
        self._bubble(canvas, x0, top, x1, top + height,
                     BUBBLE_OUT if out else BUBBLE_IN, out)
        cy = top + 8
        if sender:
            canvas.create_text(x0 + PAD_X, cy, anchor='nw', text=sender,
                               fill=_avatar_color(row['from_address']),
                               font=self.sender_font)
            cy += small_h + 4
        for line in lines:
            canvas.create_text(x0 + PAD_X, cy, anchor='nw', text=line,
                               fill=TEXT_INK, font=self.msg_font)
            cy += line_h
        # Render attachments
        for att in attachments:
            att_h = self._render_attachment(canvas, x0, cy, att, bubble_w - 2 * PAD_X, out)
            cy += att_h
        if out and pending:
            canvas.create_text(x1 - 26, top + height - 5, anchor='se',
                               text=stamp_text, fill=TIME_GRAY,
                               font=self.small_font)
            self._draw_clock(canvas, x1 - 13, top + height - 11, 6,
                             TIME_GRAY)
        else:
            _tick_marks, tick_color = self._ticks(row) \
                if out else ('', TIME_GRAY)
            canvas.create_text(x1 - 8, top + height - 5, anchor='se',
                               text=stamp_text,
                               fill=tick_color if out else TIME_GRAY,
                               font=self.small_font)

    def _draw_visible_layouts(self, canvas, layouts, first_vis,
                              last_vis, width):
        line_h = self.msg_font.metrics('linespace')
        small_h = self.small_font.metrics('linespace')
        # RENDER ONLY VISIBLE ITEMS
        for i in range(first_vis, last_vis + 1):
            layout = layouts[i]
            kind = layout[0]
            if kind == 'more':
                self._draw_more_pill(canvas, layout, width)
                continue
            if kind == 'day':
                self._draw_day_pill(canvas, layout, width)
                continue
            self._draw_message_layout(canvas, layout, width, line_h,
                                      small_h)

    def _redraw_chat(self):
        self._redraw_after = None
        if getattr(self, '_closed', False):
            return
        canvas = self.chat_canvas
        canvas.delete('all')
        # A13: reconstrói a lista a cada redraw (só visíveis retêm refs).
        try:
            self._chat_images = []
        except Exception:
            pass
        width = canvas.winfo_width() or 600
        height = canvas.winfo_height() or 400
        # Item 4: base do skip de <Configure> (ver _schedule_chat_redraw).
        self._last_chat_w = width
        view_h = height
        self._chat_viewport_height = view_h
        self.welcome_copy_btn.place_forget()
        if not getattr(self, 'current_address', None):
            self._draw_welcome(canvas, width, height)
            return
        layouts, total = self._layout_chat(width)
        first_vis, last_vis = self._visible_layout_range(
            canvas, layouts, view_h)
        self._chat_layouts = [
            (layout[1], layout[2], layout[3])  # top, height, row
            for layout in layouts if layout[0] == 'msg']
        self._draw_chat_background(canvas, width, total, view_h)
        self._draw_visible_layouts(
            canvas, layouts, first_vis, last_vis, width)
        canvas.configure(scrollregion=(0, 0, width, total))
        if self._stick_bottom:
            canvas.yview_moveto(1.0)

    def _bubble(self, canvas, x0, y0, x1, y1, fill, out, tail=True):
        radius = 10
        canvas.create_rectangle(x0 + radius, y0, x1 - radius, y1, fill=fill,
                                outline=fill)
        canvas.create_rectangle(x0, y0 + radius, x1, y1 - radius, fill=fill,
                                outline=fill)
        for corner_x, corner_y in ((x0 + radius, y0 + radius),
                                   (x1 - radius, y0 + radius),
                                   (x0 + radius, y1 - radius),
                                   (x1 - radius, y1 - radius)):
            canvas.create_oval(corner_x - radius, corner_y - radius,
                               corner_x + radius, corner_y + radius,
                               fill=fill, outline=fill)
        if not tail:
            return
        if out:
            canvas.create_polygon(x1 - 2, y0 + 4, x1 + 9, y0 + 10, x1 - 2,
                                  y0 + 18, fill=fill, outline=fill)
        else:
            canvas.create_polygon(x0 + 2, y0 + 4, x0 - 9, y0 + 10, x0 + 2,
                                  y0 + 18, fill=fill, outline=fill)

    def _draw_clock(self, canvas, cx, cy, radius, color):
        canvas.create_oval(cx - radius, cy - radius, cx + radius, cy + radius,
                           outline=color, width=1)
        canvas.create_line(cx, cy, cx, cy - radius + 2, fill=color, width=1)
        canvas.create_line(cx, cy, cx + radius - 3, cy + 1, fill=color,
                           width=1)

    # -------------------------------------------------- send

    def _chat_right_click(self, event):
        y = self.chat_canvas.canvasy(event.y)
        for top, height, row in getattr(self, '_chat_layouts', []):
            if top <= y < top + height:
                menu = tk.Menu(self, tearoff=0)
                menu.add_command(
                    label='Copiar texto',
                    command=lambda: self._copy_message_text(row))
                menu.add_command(
                    label='Responder',
                    command=lambda: self._reply_to_message(row))
                menu.add_command(
                    label='Encaminhar',
                    command=lambda: self._forward_message(row))
                menu.add_command(
                    label='Excluir mensagem',
                    command=lambda: self._delete_message(row))
                # M5: reenvio manual de ack-failed (retry limitado no core).
                try:
                    if row.get('direction') == 'out' and row.get('status') in (
                            'ack-failed', 'sending', 'awaiting-pubkey'):
                        menu.add_command(
                            label='Reenviar',
                            command=lambda: self._resend_message(row))
                except Exception:
                    pass
                menu.add_separator()
                menu.add_command(
                    label='Detalhes',
                    command=lambda: self._message_details(row))
                menu.tk_popup(event.x_root, event.y_root)
                self._track_menu(menu)
                return

    def _resend_message(self, row):
        """M5: reenvia mensagem com falha via Client.resend_message."""
        try:
            message_id = row.get('id')
        except Exception:
            message_id = None
        if message_id is None:
            return
        try:
            status, error = self.client.resend_message(message_id)
        except Exception as exc:
            dialogs.warn(self, 'Reenviar', 'Falha ao reenviar: %s' % exc)
            return
        if status != 'success':
            dialogs.warn(self, 'Reenviar', error or status)
        else:
            self._flash_status('Reenviando mensagem…')
            self._schedule_refresh()

    def _reply_to_message(self, row):
        """Quote the message and focus input for reply."""
        if not getattr(self, 'current_address', None):
            return
        body = row.get('body', '')
        # Clean body for quoting
        clean_body = body.split('[attachment:')[0].strip()
        if not clean_body:
            return
        # Truncate if too long
        if len(clean_body) > 200:
            clean_body = clean_body[:200] + '…'
        quote = f'> {clean_body.replace(chr(10), chr(10) + "> ")}'
        self._clear_placeholder()
        self.input_var.set(quote + '\n\n')
        self.input_entry.focus_set()
        self._flash_status('Respondendo...')

    def _forward_message(self, row):
        """Forward message to another contact."""
        if not getattr(self, 'current_address', None):
            return
        body = row.get('body', '')
        # Clean body for forwarding
        clean_body = body.split('[attachment:')[0].strip()
        if not clean_body:
            return
        forward_text = f'[Encaminhada]\n{clean_body}'
        self._clear_placeholder()
        self.input_var.set(forward_text)
        self.input_entry.focus_set()
        self._flash_status('Mensagem pronta para encaminhar. Selecione o destinatário.')

    def _copy_message_text(self, row):
        self.clipboard_clear()
        self.clipboard_append(row.get('body', '') if hasattr(row, 'get')
                              else '')
        self._flash_status('Texto copiado')

    @staticmethod
    def _take_message_id(row):
        try:
            return row.get('id') if hasattr(row, 'get') else None
        except Exception:
            return None

    def _redraw_after_message_delete(self):
        for action in (self._reload_chat, self._refresh_conversations):
            try:
                action()
            except Exception:
                pass

    def _delete_message(self, row):
        """Exclui uma mensagem individual (confirma; redesenha a conversa)."""
        message_id = self._take_message_id(row)
        if message_id is None:
            return
        ok = dialogs.confirm(
            self, 'Excluir mensagem',
            'Apagar esta mensagem?\n'
            'Só apaga neste dispositivo; quem já recebeu mantém a cópia.')
        if not ok:
            return
        try:
            self.client.db.delete_message(message_id)
        except Exception as exc:
            dialogs.warn(self, 'Excluir mensagem',
                         'Não foi possível excluir: %r' % exc)
            return
        self._flash_status('Mensagem excluída')
        self._redraw_after_message_delete()

    def _message_details(self, row):
        # Item 5: casca aparece já; campos em after_idle.
        window = self._dialog_shell('Detalhes da mensagem')
        window.resizable(False, False)
        try:
            window.after_idle(lambda: self._fill_message_details(window, row))
        except Exception:
            pass

    def _fill_message_details(self, window, row):
        try:
            alive = bool(window.winfo_exists())
        except Exception:
            return
        if not alive or getattr(self, '_closed', False):
            return
        frame = tk.Frame(window, bg=PANEL_BG)
        frame.pack(padx=16, pady=16, fill='both', expand=True)
        raw_hash = row.get('obj_hash') if hasattr(row, 'get') else None
        try:
            if isinstance(raw_hash, memoryview):
                raw_hash = raw_hash.tobytes()
            hash_text = bytes(raw_hash).hex() if raw_hash else '—'
        except Exception:
            hash_text = '—'
        fields = [
            ('Estado', self._status_text(row)),
            ('De', row['from_address']),
            ('Para', row['to_address']),
            ('Data/hora', _format_time(row['timestamp'])),
            ('Expira em', self._format_expiry(row)),
            ('Hash', hash_text),
        ]
        for number, (name, value) in enumerate(fields):
            tk.Label(frame, text=name + ':', bg=PANEL_BG, fg=TEXT_GRAY,
                     font=self.small_font).grid(row=number, column=0,
                                                sticky='nw', pady=3)
            text = tk.Label(frame, text=str(value), bg=PANEL_BG, fg=TEXT_INK,
                            font=self.preview_font, wraplength=420,
                            justify='left')
            text.grid(row=number, column=1, sticky='w', pady=3, padx=(10, 0))
        tk.Button(frame, text='Fechar', command=window.destroy, bg=FAB_BG,
                  fg='white', relief='flat', width=12).grid(
                      row=len(fields), column=0, columnspan=2, pady=(12, 0))

    @staticmethod
    def _format_expiry(row):
        """Texto de expiração p/ Detalhes: 'Expira em X', 'expirada' ou '—'."""
        try:
            expires = row.get('expires') if hasattr(row, 'get') else None
        except Exception:
            return '—'
        if not expires:
            return '—'
        try:
            remaining = int(expires) - int(time.time())
        except (TypeError, ValueError):
            return '—'
        if remaining <= 0:
            return 'expirada'
        return 'Expira em %s' % format_ttl_pt(remaining)

    def _confirmation_legend(self):
        dialogs.info(
            self, 'Confirmações de mensagem',
            'Relógio  Enviando/aguardando: a mensagem ainda não foi '
            'publicada na rede (ou a chave pública ainda não chegou).\n\n'
            '✓✓  Publicada na rede: os nós estão retransmitindo; ainda sem '
            'confirmação do destinatário.\n\n'
            '✓✓  Entregue: o destinatário recebeu e a rede devolveu o ACK.\n\n'
            'O Bitmessage não tem "online" nem "visto por último": a única '
            'confirmação real é a da mensagem, via ACK.')

    @staticmethod
    def _parse_ttl_hours(text):
        """Horas (texto livre, vírgula ou ponto) → segundos; None se inválido."""
        try:
            hours = float(str(text or '').strip().replace(',', '.'))
        except (TypeError, ValueError):
            return None
        if hours <= 0:
            return None
        return int(hours * 3600)

    def _msg_ttl_current(self):
        try:
            return int(self.client.get_msg_ttl())
        except Exception:
            return MSG_TTL_DEFAULT

    def _apply_msg_ttl_seconds(self, seconds):
        """Salva o TTL global e avisa em status; retorna (efetivo, clampado)."""
        try:
            effective, clamped = self.client.set_msg_ttl(seconds)
        except Exception as exc:
            dialogs.warn(self, 'Tempo de vida',
                         'Não foi possível salvar: %r' % exc)
            return None
        if clamped:
            self._flash_status(
                'TTL ajustado para %s (a rede só aceita de %s a %s).'
                % (format_ttl_pt(effective), format_ttl_pt(MSG_TTL_MIN),
                   format_ttl_pt(MSG_TTL_MAX)))
        else:
            self._flash_status(
                'Tempo de vida das mensagens: %s. '
                'Vale para as próximas mensagens.' % format_ttl_pt(effective))
        return effective, clamped

    def _msg_ttl_dialog(self):
        current = self._msg_ttl_current()
        window = self._dialog_shell('Tempo de vida das mensagens')
        try:
            self._fill_msg_ttl_dialog(window, current)
        except Exception:
            try:
                window.destroy()
            except Exception:
                pass
            return None
        return window

    def _fill_msg_ttl_dialog(self, window, current):
        frame = tk.Frame(window, bg=PANEL_BG)
        frame.pack(padx=16, pady=16, fill='both', expand=True)
        tk.Label(
            frame, bg=PANEL_BG, fg=TEXT_GRAY, font=self.preview_font,
            wraplength=420, justify='left',
            text='Quanto tempo cada mensagem vive na rede antes de expirar.\n'
                 'Vale para todas as mensagens de todos os contatos e canais, '
                 'a partir do próximo envio.\n'
                 'A rede descarta objetos fora da janela (de %s a '
                 '%s): TTL maior dá mais chance de entrega, '
                 'mas exige mais prova de trabalho.'
                 % (format_ttl_pt(MSG_TTL_MIN),
                    format_ttl_pt(MSG_TTL_MAX))).pack(anchor='w')
        tk.Label(frame, bg=PANEL_BG, fg=TEXT_INK, font=self.preview_font,
                 text='Atual: %s' % format_ttl_pt(current)).pack(
                     anchor='w', pady=(10, 2))
        choice = tk.IntVar(value=current if self._is_ttl_preset(current)
                           else -1)
        for value, label in MSG_TTL_PRESETS:
            tk.Radiobutton(frame, text=label, variable=choice, value=value,
                           bg=PANEL_BG, fg=TEXT_INK,
                           activebackground=PANEL_BG,
                           selectcolor=PANEL_BG).pack(anchor='w')
        custom_row = tk.Frame(frame, bg=PANEL_BG)
        custom_row.pack(anchor='w', pady=(8, 0))
        tk.Radiobutton(custom_row, text='Outro:', variable=choice, value=-1,
                       bg=PANEL_BG, fg=TEXT_INK,
                       activebackground=PANEL_BG,
                       selectcolor=PANEL_BG).pack(side='left')
        hours = tk.StringVar(value=self._ttl_hours_text(current))
        entry = tk.Entry(custom_row, textvariable=hours, width=10,
                         bg='#f1f3f5', fg=TEXT_INK,
                         insertbackground=TEXT_INK)
        entry.pack(side='left', padx=(6, 4))
        tk.Label(custom_row, text='horas', bg=PANEL_BG, fg=TEXT_GRAY,
                 font=self.preview_font).pack(side='left')
        buttons = tk.Frame(frame, bg=PANEL_BG)
        buttons.pack(pady=(14, 0))
        tk.Button(buttons, text='Salvar',
                  command=lambda: self._save_msg_ttl_dialog(
                      window, choice, hours),
                  bg=FAB_BG, fg='white', relief='flat', width=10).pack(
                      side='left', padx=6)
        tk.Button(buttons, text='Cancelar', command=window.destroy,
                  bg='#e6ebf0', fg=TEXT_INK, relief='flat',
                  width=10).pack(side='left', padx=6)

    @staticmethod
    def _is_ttl_preset(value):
        try:
            number = int(value)
        except (TypeError, ValueError):
            return False
        return any(number == preset for preset, _label in MSG_TTL_PRESETS)

    @staticmethod
    def _ttl_hours_text(current):
        try:
            hours = int(current) / 3600.0
        except (TypeError, ValueError):
            return ''
        if hours == int(hours):
            return str(int(hours))
        return ('%.2f' % hours).rstrip('0').rstrip('.')

    def _save_msg_ttl_dialog(self, window, choice, hours):
        try:
            selected = int(choice.get())
        except Exception:
            selected = -1
        if selected < 0:
            try:
                raw = hours.get()
            except Exception:
                raw = ''
            seconds = self._parse_ttl_hours(raw)
            if seconds is None:
                dialogs.warn(self, 'Tempo de vida',
                             'Informe as horas (número maior que zero) ou '
                             'escolha um valor pronto.')
                return
        else:
            seconds = selected
        result = self._apply_msg_ttl_seconds(seconds)
        if result is None:
            return
        try:
            window.destroy()
        except Exception:
            pass

    @staticmethod
    def _attach_max_raw():
        try:
            from ..protocol.const import MAX_WIRE_BODY_BYTES
        except Exception:
            MAX_WIRE_BODY_BYTES = 200_000
        return MAX_WIRE_BODY_BYTES * 3 // 4 - 4096

    def _attach_current_text(self):
        try:
            text = '' if self._placeholder_on else \
                self.input_var.get().strip()
            return '' if text.startswith('[Anexo:') else text
        except Exception:
            return ''

    def _attach_wire_ok(self, current_text, marker):
        try:
            from ..protocol.const import MAX_WIRE_BODY_BYTES as _wmax
        except Exception:
            _wmax = 200_000
        try:
            wire = (current_text + marker) if current_text else marker
            return len(wire.encode('utf-8')) <= _wmax
        except Exception:
            return False

    def _store_pending_attachment(self, file_path, mime, b64, size):
        import os
        # ADV: sanitiza `]`/`[` (quebram o `]` final do marcador).
        safe_name = self._sanitize_attachment_filename(
            os.path.basename(file_path))
        self._pending_attachment = {
            'filename': safe_name,
            'mime': mime,
            'data': b64,
            'size': size,
        }
        self._clear_placeholder()
        preview = '[Anexo: %s (%dKB)]' % (safe_name, size // 1024)
        self.input_var.set(preview)
        self.input_entry.config(fg=_c('input_fg'))
        self._placeholder_on = False
        self._flash_status('Anexo pronto. Digite uma mensagem opcional e envie.')

    def _attach_file(self):
        """Open file dialog and prepare attachment."""
        import base64
        import mimetypes
        import os
        try:
            file_path = filedialog.askopenfilename(
                parent=self,
                title='Selecionar arquivo para anexar',
                filetypes=[
                    ('Imagens', '*.png *.jpg *.jpeg *.gif *.bmp *.webp'),
                    ('Todos os arquivos', '*.*'),
                ])
            if not file_path:
                return
            max_raw = self._attach_max_raw()
            # C3: getsize ANTES de ler (evita OOM com arquivo gigante).
            try:
                size_on_disk = os.path.getsize(file_path)
            except Exception as exc:
                dialogs.warn(self, 'Erro no anexo', repr(exc))
                return
            if size_on_disk > max_raw:
                dialogs.warn(self, 'Arquivo grande',
                             'Arquivo excede o limite do wire (~%d KB de '
                             'arquivo para 200 KB no wire). Escolha um '
                             'arquivo menor.' % (max_raw // 1024))
                return
            with open(file_path, 'rb') as handle:
                data = handle.read()
            if len(data) > max_raw:
                dialogs.warn(self, 'Arquivo grande',
                             'Arquivo excede o limite do wire (~%d KB).'
                             % (max_raw // 1024))
                return
            b64 = base64.b64encode(data).decode('ascii')
            mime, _ = mimetypes.guess_type(file_path)
            mime = mime or 'application/octet-stream'
            # ADV: nome sanitizado (ver _sanitize_attachment_filename).
            safe_name = self._sanitize_attachment_filename(
                os.path.basename(file_path))
            marker = '\n\n[attachment:%s:%s:%s]' % (
                safe_name, mime, b64)
            if not self._attach_wire_ok(self._attach_current_text(), marker):
                dialogs.warn(self, 'Arquivo grande',
                             'Texto + anexo excede 200 KB no wire. '
                             'Encurte o texto ou use arquivo menor.')
                return
            self._store_pending_attachment(file_path, mime, b64, len(data))
        except Exception as exc:
            dialogs.warn(self, 'Erro no anexo', repr(exc))

    def _merge_pending_attachment(self, body):
        attachment = getattr(self, '_pending_attachment', None)
        if attachment:
            # Include attachment marker in body
            attach_marker = f'\n\n[attachment:{attachment["filename"]}:{attachment["mime"]}:{attachment["data"]}]'
            body = body + attach_marker if body else attach_marker
            # Clear pending attachment
            self._pending_attachment = None
        return body

    def _wire_body_too_large(self, body):
        """C3: teto único no wire (b64+overhead ≤ 200k). True se exceder."""
        try:
            from ..protocol.const import MAX_WIRE_BODY_BYTES
        except Exception:
            MAX_WIRE_BODY_BYTES = 200_000
        try:
            return len((body or '').encode('utf-8')) > MAX_WIRE_BODY_BYTES
        except Exception:
            return True

    def _take_send_body(self):
        """Read input + pending attachment; None when nothing to send."""
        if not getattr(self, 'current_address', None):
            dialogs.warn(self, 'Nenhuma conversa',
                         'Selecione uma conversa antes de enviar.')
            return None
        if self._placeholder_on:
            self._flash_status('Digite uma mensagem antes de enviar.')
            return None
        body = self._merge_pending_attachment(self.input_var.get().strip())
        if not body:
            self._flash_status('Digite uma mensagem antes de enviar.')
            return None
        # C3: teto único no wire checado ANTES do PoW (DM e canal).
        if self._wire_body_too_large(body):
            try:
                self._pending_attachment = None
            except Exception:
                pass
            dialogs.warn(self, 'Mensagem grande demais',
                         'Texto + anexo excede o limite de 200 KB no wire '
                         '(~150 KB de arquivo). Encurte ou use arquivo menor.')
            return None
        return body

    def _ensure_send_identity(self):
        identity = self._current_identity()
        if not identity or identity not in self.client.identities:
            dialogs.warn(self, 'Identidade ausente',
                         'Crie ou selecione uma identidade válida antes '
                         'de enviar.')
            self._refresh_identity_menu()
            return None
        return identity

    def _send_to_channel(self, body):
        try:
            sub = self.client.db.get_subscription(self.current_address)
        except Exception:
            sub = None
        if sub is None:
            dialogs.warn(self, 'Canal ausente',
                         'Inscrição do canal não encontrada.')
            self._refresh_conversations()
            return
        self.input_var.set('')
        self._set_placeholder()
        status, error = self.client.broadcast_chan(
            self.current_address, body)
        if status != 'success':
            dialogs.warn(self, 'Canal', error or status)

    def _send_to_contact(self, identity, body):
        if self.client.db.get_contact(self.current_address) is None:
            dialogs.warn(self, 'Conversa encerrada',
                         'Este contato foi removido. Selecione outra '
                         'conversa.')
            self._refresh_conversations()
            self._show_welcome()
            return
        self.input_var.set('')
        self._set_placeholder()
        # Command Pattern: encapsula envio em objeto Command
        cmd = SendMessageCommand(self.client, identity, self.current_address, body)
        status, error = self._command_history.execute(cmd)
        if status != 'success':
            dialogs.warn(self, 'Erro', error or status)

    def _send(self):
        try:
            body = self._take_send_body()
            if body is None:
                return
            identity = self._ensure_send_identity()
            if identity is None:
                return
            if getattr(self, 'current_kind', 'contact') == 'channel':
                self._send_to_channel(body)
            else:
                self._send_to_contact(identity, body)
        except Exception as exc:
            dialogs.warn(self, 'Erro ao enviar', repr(exc))

    def _ask_schedule_time(self):
        """Ask for date/time; return future datetime or None."""
        result = dialogs.ask_simple(
            self, 'Agendar mensagem',
            ['date', 'time'],
            {'date': datetime.date.today().strftime('%d/%m/%Y'),
             'time': '12:00'},
            labels={'date': 'Data (DD/MM/AAAA)', 'time': 'Hora (HH:MM)'})
        if not result:
            return None
        try:
            dt_str = f"{result['date']} {result['time']}"
            scheduled = datetime.datetime.strptime(dt_str, '%d/%m/%Y %H:%M')
        except ValueError:
            dialogs.warn(self, 'Data/hora inválida',
                         'Use o formato DD/MM/AAAA HH:MM')
            return None
        if scheduled <= datetime.datetime.now():
            dialogs.warn(self, 'Horário passado',
                         'A data/hora deve ser futura.')
            return None
        return scheduled

    def _ensure_schedule_identity(self):
        identity = self._current_identity()
        if not identity or identity not in self.client.identities:
            dialogs.warn(self, 'Identidade ausente',
                         'Crie ou selecione uma identidade válida.')
            return None
        return identity

    def _store_scheduled_message(self, identity, body, scheduled):
        # Store scheduled message in database
        try:
            self.client.db.add_scheduled_message(
                identity, self.current_address, body, int(scheduled.timestamp()))
        except Exception as exc:
            dialogs.warn(self, 'Erro ao agendar', repr(exc))
            return False
        return True

    def _schedule_message(self):
        """Open dialog to schedule message for later sending."""
        if not getattr(self, 'current_address', None):
            dialogs.warn(self, 'Nenhuma conversa',
                         'Selecione uma conversa antes de agendar.')
            return
        if self._placeholder_on or not self.input_var.get().strip():
            dialogs.warn(self, 'Mensagem vazia',
                         'Digite a mensagem antes de agendar.')
            return
        scheduled = self._ask_schedule_time()
        if scheduled is None:
            return
        body = self._merge_pending_attachment(self.input_var.get().strip())
        # C3: agendada também respeita o teto único (antes do PoW futuro).
        if self._wire_body_too_large(body):
            try:
                self._pending_attachment = None
            except Exception:
                pass
            dialogs.warn(self, 'Mensagem grande demais',
                         'Texto + anexo excede o limite de 200 KB no wire.')
            return
        identity = self._ensure_schedule_identity()
        if identity is None:
            return
        if not self._store_scheduled_message(identity, body, scheduled):
            return
        self.input_var.set('')
        self._set_placeholder()
        self._flash_status(f'Mensagem agendada para {scheduled.strftime("%d/%m/%Y %H:%M")}')

    # -------------------------------------------------- actions

    def _new_identity(self):
        result = dialogs.ask_simple(
            self, 'Nova identidade',
            ['label', 'stream'],
            {'label': 'Nova identidade', 'stream': '1'})
        if not result:
            return
        try:
            stream = int(result.get('stream') or '1')
        except ValueError:
            stream = 1
        address = self.client.create_identity(
            result.get('label') or 'Nova identidade', stream)
        self._refresh_identity_menu()
        self._set_current_identity(address)
        dialogs.info(self, 'Identidade criada', address)

    def _new_contact(self):
        result = dialogs.ask_simple(self, 'Novo contato', ['label', 'address'])
        if not result or not result.get('address'):
            return
        status, _version = self.client.add_contact(
            result['address'], result.get('label') or None)
        if status == 'success':
            self.client.request_pubkey(result['address'])
            dialogs.info(self, 'Contato adicionado',
                         'Buscando a chave pública do contato...')
        elif status == 'checksumfailed':
            dialogs.warn(self, 'Endereço inválido',
                         'O checksum do endereço não confere.')
        else:
            dialogs.warn(self, 'Endereço inválido',
                         'Não foi possível interpretar o endereço.')

    def _backup_identity(self):
        addresses = list(self.client.identities.keys())
        if not addresses:
            dialogs.warn(self, 'Backup',
                         'Crie uma identidade antes de fazer backup.')
            return
        options = [self._identity_display(a) for a in addresses]
        options.append('Importar identidade de um backup…')
        options.append('Exportar todas (keys.dat, PyBitmessage)…')
        options.append('Importar keys.dat…')
        index = dialogs.choose(self, 'Backup de identidade', options,
                               prompt='Escolha a identidade:')
        if index is None:
            return
        if index == len(addresses):
            self._import_identity()
            return
        if index == len(addresses) + 1:
            self._export_keys_dat_file()
            return
        if index == len(addresses) + 2:
            self._import_keys_dat_file()
            return
        address = addresses[index]
        # Command Pattern: backup via objeto Command
        cmd = BackupKeysCommand(self.client, address, format='wif')
        status, data = self._command_history.execute(cmd)
        if status != 'success' or data is None:
            dialogs.warn(self, 'Backup',
                         'Chaves indisponíveis para esta identidade.')
            return
        ok = dialogs.confirm(self, 'ATENÇÃO — chaves privadas',
                             BACKUP_WARNING % data['address'])
        if not ok:
            return
        self._show_backup_window(data)

    @staticmethod
    def _secret_write_text(path, text):
        """A7: cria segredo já com 0600 (os.open), sem janela 0644."""
        import os as _osbk
        data = text.encode('utf-8')
        directory = _osbk.path.dirname(_osbk.path.abspath(path)) or '.'
        fd = None
        tmp_path = ''
        try:
            import tempfile as _tf
            fd, tmp_path = _tf.mkstemp(dir=directory, prefix='.tmp-secret-')
            try:
                _osbk.fchmod(fd, 0o600)
            except Exception:
                pass
            with _osbk.fdopen(fd, 'wb') as handle:
                fd = None
                handle.write(data)
                try:
                    handle.flush()
                    _osbk.fsync(handle.fileno())
                except Exception:
                    pass
            try:
                _osbk.chmod(tmp_path, 0o600)
            except Exception:
                pass
            _osbk.replace(tmp_path, path)
            tmp_path = ''
            try:
                _osbk.chmod(path, 0o600)
            except Exception:
                pass
        finally:
            if fd is not None:
                try:
                    _osbk.close(fd)
                except Exception:
                    pass
            if tmp_path:
                try:
                    _osbk.unlink(tmp_path)
                except Exception:
                    pass

    @staticmethod
    def _password_long_enough(password):
        """M10: senha mínima de 8 chars para backup .enc."""
        return bool(password) and len(password) >= 8

    def _save_backup_file(self, window, body):
        path = filedialog.asksaveasfilename(
            parent=window, title='Salvar backup',
            defaultextension='.txt',
            filetypes=[('Texto', '*.txt'), ('Todos', '*.*')],
            initialfile='bmchat-backup.txt')
        if not path:
            return
        try:
            self._secret_write_text(
                path,
                'BACKUP DE IDENTIDADE BMCHAT\n'
                'Guarde em lugar seguro. Se perder, é impossível '
                'recuperar.\n\n' + body + '\n')
        except Exception as exc:
            dialogs.warn(window, 'Backup', 'Falha ao salvar: %s' % exc)
            return
        dialogs.info(window, 'Backup', 'Backup salvo em:\n%s' % path)

    @staticmethod
    def _copy_backup_keys(window, body):
        window.clipboard_clear()
        window.clipboard_append(body)
        dialogs.info(window, 'Backup', 'Chaves copiadas.')

    def _show_backup_window(self, data):
        # Item 5: casca aparece já; Text com as chaves em after_idle.
        window = self._dialog_shell(
            'Backup — %s' % data['address'][:20], '560x430')
        try:
            window.after_idle(lambda: self._fill_backup_window(window, data))
        except Exception:
            pass

    def _fill_backup_window(self, window, data):
        try:
            alive = bool(window.winfo_exists())
        except Exception:
            return
        if not alive or getattr(self, '_closed', False):
            return
        body = (
            'IDENTIDADE BMCHAT — GUARDE EM LUGAR SEGURO\n'
            'Endereço: %s\nRótulo: %s\nStream: %s\n\n'
            'Chave privada de assinatura (WIF):\n%s\n\n'
            'Chave privada de criptografia (WIF):\n%s\n\n'
            'Quem tiver essas chaves controla esta identidade. '
            'Se perdê-las, é IMPOSSÍVEL recuperar.'
            % (data['address'], data['label'], data['stream'],
               data['signing_wif'], data['encryption_wif']))
        buttons = tk.Frame(window, bg=PANEL_BG)
        buttons.pack(side='bottom', fill='x', padx=12, pady=10)

        def save():
            self._save_backup_file(window, body)

        def copy():
            self._copy_backup_keys(window, body)

        tk.Button(buttons, text='Salvar em arquivo…', command=save,
                  bg=FAB_BG, fg='white', relief='flat').pack(
                      side='left', padx=(0, 8))
        tk.Button(buttons, text='Copiar chaves', command=copy,
                  bg=PANEL_BG, fg=TEXT_INK, relief='solid',
                  bd=1).pack(side='left')
        tk.Button(buttons, text='Fechar', command=window.destroy,
                  bg=PANEL_BG, fg=TEXT_INK, relief='solid',
                  bd=1).pack(side='right')
        text = tk.Text(window, wrap='word', font=self.preview_font,
                       bg=PANEL_BG, fg=TEXT_INK, highlightthickness=0, bd=0,
                       padx=12, pady=12)
        text.pack(fill='both', expand=True)
        text.insert('1.0', body)
        text.config(state='disabled')

    def _export_keys_dat_file(self):
        data = self.client.export_keys_dat()
        if not data.strip():
            dialogs.warn(self, 'keys.dat', 'Nenhuma identidade para exportar.')
            return
        path = filedialog.asksaveasfilename(
            parent=self, title='Exportar keys.dat',
            defaultextension='.dat',
            filetypes=[('keys.dat', '*.dat'), ('Todos', '*.*')],
            initialfile='keys.dat')
        if not path:
            return
        try:
            # A7: 0600 desde a criação (antes: open() 0644 + chmod depois).
            self._secret_write_text(path, data)
        except Exception as exc:
            dialogs.warn(self, 'keys.dat', 'Falha ao salvar: %s' % exc)
            return
        count = data.count('privsigningkey')
        dialogs.info(self, 'keys.dat',
                     '%d identidade(s) exportadas.\n'
                     'Esse arquivo abre em outros clientes Bitmessage '
                     '(ex.: PyBitmessage). Guarde em lugar seguro.'
                     % count)

    def _import_keys_dat_file(self):
        path = filedialog.askopenfilename(
            parent=self, title='Importar keys.dat',
            filetypes=[('keys.dat', '*.dat'), ('Todos', '*.*')])
        if not path:
            return
        try:
            with open(path, 'r') as handle:
                text = handle.read()
        except Exception as exc:
            dialogs.warn(self, 'keys.dat', 'Falha ao ler: %s' % exc)
            return
        result = self.client.import_keys_dat(text)
        if result['imported']:
            self._refresh_identity_menu()
            self._refresh_conversations()
        dialogs.info(
            self, 'keys.dat',
            'Importadas: %d\nJá existiam: %d\nCom erro: %d' % (
                result['imported'], result['skipped'], result['errors']))

    def _import_identity(self):
        result = dialogs.ask_simple(
            self, 'Importar identidade',
            ['signing_wif', 'encryption_wif', 'label', 'stream'],
            {'label': 'Identidade importada', 'stream': '1'})
        if not result:
            return
        if not result.get('signing_wif') or not result.get('encryption_wif'):
            dialogs.warn(self, 'Importar',
                         'Informe as duas chaves WIF do backup.')
            return
        status, info = self.client.import_identity(
            result['signing_wif'], result['encryption_wif'],
            result.get('label'), result.get('stream') or '1')
        if status == 'success':
            self._refresh_identity_menu()
            self.identity_var.set(self._identity_display(info))
            self._refresh_conversations()
            dialogs.info(self, 'Identidade importada',
                         'Endereço restaurado:\n%s' % info)
        else:
            dialogs.warn(self, 'Importar', info)

    def _encrypted_backup(self):
        """Export encrypted database backup."""
        if not hasattr(self.client.db, 'path'):
            dialogs.warn(self, 'Backup', 'Banco de dados não disponível.')
            return
        path = filedialog.asksaveasfilename(
            parent=self, title='Backup criptografado',
            defaultextension='.enc',
            filetypes=[('Backup criptografado', '*.enc'), ('Todos', '*.*')],
            initialfile='bmchat-backup.enc')
        if not path:
            return
        password_result = dialogs.ask_simple(
            self, 'Senha do backup',
            ['password', 'confirm'],
            {'password': '', 'confirm': ''},
            labels={'password': 'Senha', 'confirm': 'Confirme a senha'},
            password=True)
        if not password_result or not password_result.get('password'):
            return
        if password_result['password'] != password_result['confirm']:
            dialogs.warn(self, 'Senha', 'As senhas não conferem.')
            return
        # M10: senha mínima de 8 chars no backup .enc.
        if not self._password_long_enough(password_result.get('password')):
            dialogs.warn(self, 'Senha',
                         'Use ao menos 8 caracteres para o backup.')
            return
        try:
            export_encrypted_backup(self.client.db.path, path, password_result['password'])
            dialogs.info(self, 'Backup criptografado',
                         f'Backup salvo em:\n{path}\n\n'
                         'Guarde a senha! Sem ela é impossível restaurar.')
        except Exception as exc:
            dialogs.warn(self, 'Erro no backup', repr(exc))

    def _ask_restore_password(self):
        password_result = dialogs.ask_simple(
            self, 'Senha do backup',
            ['password'],
            {'password': ''},
            labels={'password': 'Senha'},
            password=True)
        if not password_result or not password_result.get('password'):
            return None
        return password_result['password']

    def _swap_restored_db(self, temp_path):
        import shutil
        try:
            shutil.copy2(self.client.db.path,
                         self.client.db.path + '.bak')
            try:
                os.chmod(self.client.db.path + '.bak', 0o600)
            except Exception:
                pass
        except Exception:
            pass
        os.replace(temp_path, self.client.db.path)
        try:
            os.chmod(self.client.db.path, 0o600)
        except Exception:
            pass

    def _cleanup_temp(self, temp_path):
        # ADV: limpa também o .bak órfão do temp (import cria .bak do
        # arquivo vazio do mkstemp no caminho de sucesso).
        for candidate in (temp_path, (temp_path + '.bak') if temp_path else ''):
            try:
                if candidate and os.path.exists(candidate):
                    os.unlink(candidate)
            except Exception:
                pass

    def _do_restore_swap(self, path, password, temp_path):
        import_encrypted_backup(path, temp_path, password)
        try:
            os.chmod(temp_path, 0o600)
        except Exception:
            pass
        self.client.stop()
        self._swap_restored_db(temp_path)
        self.client.start()
        self._refresh_identity_menu()
        self._refresh_conversations()

    def _restore_encrypted_backup(self):
        """Import encrypted database backup (atômico, sem vazar tmp)."""
        path = filedialog.askopenfilename(
            parent=self, title='Restaurar backup criptografado',
            filetypes=[('Backup criptografado', '*.enc'), ('Todos', '*.*')])
        if not path:
            return
        password = self._ask_restore_password()
        if not password:
            return
        if not dialogs.confirm(self, 'Restaurar backup',
                               'Isso substituirá TODOS os dados atuais '
                               '(identidades, contatos, mensagens). Continuar?'):
            return
        # A6: tmp+fsync+os.replace, finally: unlink, .bak do original.
        import tempfile
        temp_path = ''
        try:
            directory = os.path.dirname(
                os.path.abspath(self.client.db.path)) or '.'
            fd, temp_path = tempfile.mkstemp(dir=directory, suffix='.db')
            os.close(fd)
            # ADV: o mkstemp deixa um arquivo vazio que faria o import criar
            # um `.bak` órfão dele (vazio) no sucesso. Remove antes para o
            # import não ver arquivo existente.
            try:
                os.unlink(temp_path)
            except Exception:
                pass
            self._do_restore_swap(path, password, temp_path)
            temp_path = ''
            dialogs.info(self, 'Backup restaurado',
                         'Dados restaurados com sucesso.')
        except Exception as exc:
            dialogs.warn(self, 'Erro ao restaurar', repr(exc))
            self._cleanup_temp(temp_path)
            temp_path = ''
            self._ensure_client_running()
        finally:
            self._cleanup_temp(temp_path)

    def _ensure_client_running(self):
        try:
            if not getattr(self.client, 'started', False):
                self.client.start()
        except Exception:
            pass

    def _encrypt_database(self):
        """C5: o DB segue EM CLARO (0700/0600); sem criptografia integral.

        Não há VFS/página cifrada: a proteção real é o "Backup
        criptografado" (.enc). Este diálogo declara isso em vez de
        sugerir integração futura falsa.
        """
        if is_encrypted(self.client.db.path):
            dialogs.info(self, 'Criptografia', 'O banco de dados já está criptografado.')
            return
        password_result = dialogs.ask_simple(
            self, 'Criptografar banco de dados',
            ['password', 'confirm'],
            {'password': '', 'confirm': ''},
            labels={'password': 'Nova senha', 'confirm': 'Confirme a senha'},
            password=True)
        if not password_result or not password_result.get('password'):
            return
        if password_result['password'] != password_result['confirm']:
            dialogs.warn(self, 'Senha', 'As senhas não conferem.')
            return
        # M10: mínima também aqui (quando a cifragem integral existir).
        if not self._password_long_enough(password_result.get('password')):
            dialogs.warn(self, 'Senha',
                         'Use ao menos 8 caracteres.')
            return
        if not dialogs.confirm(self, 'Criptografar banco',
                               'O banco de dados segue EM CLARO neste '
                               'dispositivo (protegido só por permissões '
                               '0700/0600). Para levar os dados com '
                               'segurança, use "Backup criptografado" (.enc). '
                               'Continuar vendo como proteger?'):
            return
        try:
            dialogs.info(self, 'Criptografia',
                         'Este dispositivo guarda o banco EM CLARO com '
                         'permissões 0700/0600. Não há criptografia integral '
                         'do banco em uso. Use "Backup criptografado" (.enc, '
                         'senha com 8+ caracteres) para proteger cópias e '
                         'transporte.')
        except Exception as exc:
            dialogs.warn(self, 'Erro', repr(exc))

    def _change_db_password(self):
        """Change database encryption password."""
        if not is_encrypted(self.client.db.path):
            dialogs.info(self, 'Senha', 'O banco de dados não está criptografado.')
            return
        password_result = dialogs.ask_simple(
            self, 'Alterar senha do banco',
            ['old_password', 'new_password', 'confirm'],
            {'old_password': '', 'new_password': '', 'confirm': ''},
            labels={'old_password': 'Senha atual', 'new_password': 'Nova senha', 'confirm': 'Confirme nova senha'},
            password=True)
        if not password_result or not password_result.get('old_password'):
            return
        if password_result['new_password'] != password_result['confirm']:
            dialogs.warn(self, 'Senha', 'As novas senhas não conferem.')
            return
        # M10: nova senha também com mínimo de 8 chars.
        if not self._password_long_enough(password_result.get('new_password')):
            dialogs.warn(self, 'Senha',
                         'A nova senha precisa de ao menos 8 caracteres.')
            return
        try:
            change_password(self.client.db.path,
                            password_result['old_password'],
                            password_result['new_password'])
            dialogs.info(self, 'Senha alterada', 'Senha do banco alterada com sucesso.')
        except Exception as exc:
            dialogs.warn(self, 'Erro', f'Senha atual incorreta ou erro: {exc}')

    def _show_log(self):
        # Item 5: casca aparece já; Text + primeira leitura em after_idle.
        window = self._dialog_shell('Log de rede e mensagens', '660x420')
        try:
            window.after_idle(lambda: self._fill_log(window))
        except Exception:
            pass

    def _fill_log(self, window):
        try:
            alive = bool(window.winfo_exists())
        except Exception:
            return
        if not alive or getattr(self, '_closed', False):
            return
        buttons = tk.Frame(window, bg=PANEL_BG)
        buttons.pack(side='bottom', fill='x', padx=12, pady=10)
        tk.Button(buttons, text='Copiar log',
                  command=lambda: self._copy_log(text),
                  bg=PANEL_BG, fg=TEXT_INK, relief='solid',
                  bd=1).pack(side='left')
        tk.Button(buttons, text='Fechar', command=window.destroy,
                  bg=FAB_BG, fg='white', relief='flat').pack(side='right')
        text = tk.Text(window, wrap='word', font=self.preview_font,
                       bg=PANEL_BG, fg=TEXT_INK, highlightthickness=0, bd=0,
                       padx=12, pady=12, state='disabled')
        text.pack(fill='both', expand=True)
        text.bind('<Button-3>',
                  lambda event: self._log_right_click(event, text))
        # Tinta inicial sempre (ainda pode não estar mapeada: o MapNotify
        # chega depois do after_idle); o pulo por "oculta" vale só p/ o ciclo.
        self._refresh_log(window, text, force=True)

    def _defer_hidden_window(self, window, reschedule):
        # Item 7: janela oculta → pula o trabalho, reagenda longo.
        try:
            window._refresh_after = window.after(5000, reschedule)
        except Exception:
            pass
        return False

    def _refresh_window_visible(self, window, reschedule):
        """True when a dialog window should be repainted right now.

        Dead/closed windows return False. Hidden windows are rescheduled
        through the given callback (None forces immediate paint) and
        return False.
        """
        try:
            alive = bool(window.winfo_exists())
        except Exception:
            return False
        if not alive:
            return False
        if getattr(self, '_closed', False):
            return False
        if reschedule is None:
            return True
        try:
            mapped = bool(window.winfo_ismapped())
        except Exception:
            mapped = True
        if not mapped:
            return self._defer_hidden_window(window, reschedule)
        return True

    @staticmethod
    def _paint_text_window(window, text, content, reschedule,
                           see_end=False):
        try:
            text.config(state='normal')
            text.delete('1.0', 'end')
            text.insert('1.0', content)
            text.config(state='disabled')
            if see_end:
                text.see('end')
        except Exception:
            return
        try:
            window._refresh_after = window.after(5000, reschedule)
        except Exception:
            pass

    def _refresh_log(self, window, text, force=False):
        try:
            reschedule = None if force else \
                lambda: self._refresh_log(window, text)
            if not self._refresh_window_visible(window, reschedule):
                return
            try:
                lines = self.client.recent_logs(200)
            except Exception as exc:
                lines = ['(erro ao ler log: %s)' % exc]
            self._paint_text_window(
                window, text, '\n'.join(lines) or '(sem eventos ainda)',
                lambda: self._refresh_log(window, text), see_end=True)
        except Exception:
            pass

    def _copy_log(self, text):
        self.clipboard_clear()
        self.clipboard_append(text.get('1.0', 'end').strip())
        dialogs.info(self, 'Log', 'Log copiado.')

    def _log_right_click(self, event, text):
        menu = tk.Menu(self, tearoff=0)
        try:
            selected = text.get('sel.first', 'sel.last')
        except Exception:
            selected = ''
        if selected:
            menu.add_command(
                label='Copiar seleção',
                command=lambda: self._clipboard_text(selected))
        menu.add_command(
            label='Copiar tudo',
            command=lambda: self._clipboard_text(
                text.get('1.0', 'end').strip()))
        menu.tk_popup(event.x_root, event.y_root)
        self._track_menu(menu)

    def _clipboard_text(self, content):
        self.clipboard_clear()
        self.clipboard_append(content)

    def _network_diagnostics(self):
        # Item 5: casca aparece já; Text + relatório em after_idle.
        window = self._dialog_shell('Diagnóstico de rede', '660x500')
        try:
            window.after_idle(lambda: self._fill_diagnostics(window))
        except Exception:
            pass

    def _fill_diagnostics(self, window):
        try:
            alive = bool(window.winfo_exists())
        except Exception:
            return
        if not alive or getattr(self, '_closed', False):
            return
        buttons = tk.Frame(window, bg=PANEL_BG)
        buttons.pack(side='bottom', fill='x', padx=12, pady=10)
        tk.Button(buttons, text='Copiar relatório',
                  command=lambda: self._copy_diagnostics(text),
                  bg=PANEL_BG, fg=TEXT_INK, relief='solid',
                  bd=1).pack(side='left')
        tk.Button(buttons, text='Apagar objetos…',
                  command=self._wipe_objects,
                  bg=PANEL_BG, fg='#b00020', relief='solid',
                  bd=1).pack(side='left', padx=(8, 0))
        tk.Button(buttons, text='Fechar', command=window.destroy,
                  bg=FAB_BG, fg='white', relief='flat').pack(side='right')
        text = tk.Text(window, wrap='word', font=self.preview_font,
                       bg=PANEL_BG, fg=TEXT_INK, highlightthickness=0, bd=0,
                       padx=12, pady=12, state='disabled')
        text.pack(fill='both', expand=True)
        # Tinta inicial sempre (ver comentário em _fill_log).
        self._refresh_diagnostics(window, text, force=True)

    def _refresh_diagnostics(self, window, text, force=False):
        try:
            reschedule = None if force else \
                lambda: self._refresh_diagnostics(window, text)
            if not self._refresh_window_visible(window, reschedule):
                return
            try:
                report = _diagnostics_report(self.client.net.snapshot())
            except Exception as exc:
                report = '(erro ao gerar diagnóstico: %s)' % exc
            self._paint_text_window(
                window, text, report,
                lambda: self._refresh_diagnostics(window, text))
        except Exception:
            pass

    def _wipe_objects(self):
        try:
            rows = self.client.db.query('SELECT COUNT(*) AS n FROM objects')
            total = rows[0]['n'] if rows else 0
        except Exception:
            total = 0
        ok = dialogs.confirm(
            self, 'Apagar objetos',
            'Apagar todos os %d objetos guardados?\n\n'
            '• O histórico de conversas é preservado.\n'
            '• Os objetos serão baixados novamente dos pares, '
            'aos poucos — pode levar vários minutos.\n'
            '• Só volta o que ainda não expirou e o que os pares '
            'ainda guardam.' % total)
        if not ok:
            return
        # wipe_objects limpa banco/memória e já derruba as conexões
        # para forçar re-sync (ver NetworkManager.wipe_objects); o
        # DELETE é único e rápido, e a reconexão roda em thread no
        # manager, então a UI não trava.
        removed = self.client.net.wipe_objects()
        dialogs.info(
            self, 'Objetos',
            '%d objetos apagados. Baixando tudo de novo… '
            'acompanhe o progresso na barra de status.' % removed)

    def _copy_diagnostics(self, text):
        self.clipboard_clear()
        self.clipboard_append(text.get('1.0', 'end').strip())
        dialogs.info(self, 'Diagnóstico', 'Relatório copiado.')

    def _network_settings(self):
        db = self.client.db
        try:
            from .. import update as updater
            auto_current = str(db.get_int(updater.AUTO_UPDATE_KEY, updater.AUTO_UPDATE_DEFAULT))
            interval_current = str(db.get_setting(updater.UPDATE_INTERVAL_KEY, str(updater.UPDATE_INTERVAL_DEFAULT_H)))
        except Exception:
            auto_current, interval_current = '1', '6'
        result = dialogs.ask_simple(
            self, 'Configurações de rede',
            ['connect_timeout', 'recv_timeout', 'max_connections',
             'maintenance_interval', 'auto_update', 'update_interval_h'],
            {'connect_timeout': str(db.get_int('connect_timeout', 30)),
             'recv_timeout': str(db.get_int('recv_timeout', 30)),  # noqa: E127
             'max_connections': str(db.get_int('max_connections', 8)),
             'maintenance_interval': str(
                 db.get_int('maintenance_interval', 5)),
             'auto_update': auto_current,
             'update_interval_h': interval_current})
        if not result:
            return
        try:
            connect_timeout = max(
                5, min(300, int(result.get('connect_timeout') or 30)))
            recv_timeout = max(
                10, min(600, int(result.get('recv_timeout') or 30)))
            max_connections = max(
                1, min(50, int(result.get('max_connections') or 8)))
            interval = max(
                2, min(120, int(result.get('maintenance_interval') or 5)))
            raw_auto = str(result.get('auto_update') or '').strip()
            if raw_auto not in ('0', '1'):
                raise ValueError('auto_update: use 0 ou 1')
            auto_update = int(raw_auto)
            raw_interval = str(result.get('update_interval_h') or '6').strip().replace(',', '.')
            interval_h = float(raw_interval)
            if interval_h < 0 or interval_h > 168:
                raise ValueError('update_interval_h: use 0 a 168')
        except ValueError:
            dialogs.warn(self, 'Configurações',
                         'Use números válidos (auto_update: 0 ou 1; '
                         'update_interval_h: 0 a 168).')
            return
        db.set_setting('connect_timeout', connect_timeout)
        db.set_setting('recv_timeout', recv_timeout)
        db.set_setting('max_connections', max_connections)
        db.set_setting('maintenance_interval', interval)
        db.set_setting('auto_update', auto_update)
        db.set_setting('update_interval_h', '%g' % interval_h)
        try:
            self._schedule_periodic_update_check()
        except Exception:
            pass
        dialogs.info(
            self, 'Configurações',
            'Aplicadas: timeout de conexão %ds, timeout de leitura %ds, '
            'máximo %d conexões, manutenção a cada %ds.\n'
            'Atualização automática: %s; verificação a cada %sh '
            '(0 desliga só o periódico; o check de startup continua).'
            % (connect_timeout, recv_timeout, max_connections, interval,
               'ligada' if auto_update else 'desligada', '%g' % interval_h))

    def _proxy_dialog(self):
        names = [p.describe() for p in DARKNET_PRESETS]
        names.insert(0, 'Conexão direta')
        index = dialogs.choose(
            self, 'Proxy / Darknet', names,
            prompt='Escolha o proxy de saída:')
        if index is None:
            return
        if index == 0:
            profile = ProxyProfile('Direto')
        else:
            profile = DARKNET_PRESETS[index - 1]
        self.client.net.set_proxy(profile)
        # M3: stop() dá join com timeout e incrementa a geração; o start()
        # seguinte invalida threads de manutenção órfãs do perfil antigo.
        self.client.net.stop()
        self.client.net.start(self.client._participating_streams())
        dialogs.info(self, 'Proxy atualizado',
                     'Usando %s. Reconectando...' % profile.describe())

    def _show_pows(self):
        window = self._dialog_shell('Gerenciar POW', '640x420')
        try:
            window.after_idle(lambda: self._fill_pow_window(window))
        except Exception:
            pass
        return window

    @staticmethod
    def _pow_short_dest(dest):
        if not dest:
            return '—'
        text = str(dest)
        return text if len(text) <= 24 else text[:21] + '…'

    @staticmethod
    def _pow_row_text(task):
        try:
            token = task.get('token')
            dest = App._pow_short_dest(task.get('dest'))
            preview = str(task.get('preview') or '').replace(
                '\n', ' ').strip()
            if len(preview) > 32:
                preview = preview[:31] + '…'
            tried = int(task.get('tried') or 0)
            rate = float(task.get('rate') or 0.0)
            elapsed = int(task.get('elapsed') or 0)
            status = 'cancelando…' if task.get('cancelling') \
                else 'calculando'
            label = '#%s · %s' % (token, dest)
            if preview:
                label += ' · “%s”' % preview
            return '%s · %d tent. · %.0f H/s · %ds · %s' % (
                label, tried, rate, elapsed, status)
        except Exception:
            return '#? · — · calculando'

    def _fill_pow_window(self, window):
        try:
            alive = bool(window.winfo_exists())
        except Exception:
            return
        if not alive or getattr(self, '_closed', False):
            return
        header = tk.Frame(window, bg=PANEL_BG)
        header.pack(fill='x', padx=12, pady=(10, 4))
        count = tk.Label(header, text='…', bg=PANEL_BG, fg=TEXT_GRAY,
                         font=self.small_font)
        count.pack(side='left')
        body = tk.Frame(window, bg=PANEL_BG)
        body.pack(fill='both', expand=True, padx=12)
        scrollbar = tk.Scrollbar(body, orient='vertical')
        listbox = tk.Listbox(body, bg='#f1f3f5', fg=TEXT_INK,
                             selectbackground=FAB_BG,
                             selectforeground='white', height=12,
                             yscrollcommand=scrollbar.set,
                             exportselection=False, activestyle='none',
                             highlightthickness=0, bd=0,
                             font=self.preview_font)
        scrollbar.config(command=listbox.yview)
        listbox.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        empty = tk.Label(window, text='Nenhum cálculo em andamento',
                         bg=PANEL_BG, fg=TEXT_GRAY, font=self.preview_font)
        buttons = tk.Frame(window, bg=PANEL_BG)
        buttons.pack(side='bottom', fill='x', padx=12, pady=10)
        tk.Button(buttons, text='Cancelar selecionado',
                  command=lambda: self._cancel_selected_pow(window),
                  bg=PANEL_BG, fg=TEXT_INK, relief='solid',
                  bd=1).pack(side='left')
        tk.Button(buttons, text='Cancelar todos',
                  command=lambda: self._cancel_all_pows_ui(window),
                  bg=PANEL_BG, fg='#b00020', relief='solid',
                  bd=1).pack(side='left', padx=(8, 0))
        tk.Button(buttons, text='Fechar', command=window.destroy,
                  bg=FAB_BG, fg='white', relief='flat').pack(side='right')
        window._pow_listbox = listbox
        window._pow_empty = empty
        window._pow_count = count
        window._pow_tokens = []
        self._refresh_pow_window(window, force=True)

    def _refresh_pow_window(self, window, force=False):
        try:
            reschedule = None if force else \
                lambda: self._refresh_pow_window(window)
            if not self._refresh_window_visible(window, reschedule):
                return
            try:
                tasks = self.client.list_pow_tasks()
            except Exception:
                tasks = []
            self._render_pow_tasks(window, tasks)
        except Exception:
            pass
        try:
            window._refresh_after = window.after(
                1000, lambda: self._refresh_pow_window(window))
        except Exception:
            pass

    def _render_pow_tasks(self, window, tasks):
        try:
            listbox = window._pow_listbox
        except Exception:
            return
        try:
            window._pow_tokens = [task.get('token') for task in tasks]
            listbox.delete(0, 'end')
            for task in tasks:
                listbox.insert('end', self._pow_row_text(task))
        except Exception:
            return
        self._render_pow_state(window, tasks)

    def _render_pow_state(self, window, tasks):
        try:
            empty = window._pow_empty
            count = window._pow_count
        except Exception:
            return
        if tasks:
            self._render_pow_busy(window, count, empty, len(tasks))
        else:
            self._render_pow_empty(window, count, empty)

    def _render_pow_busy(self, window, count, empty, total):
        try:
            count.config(text='%d cálculo(s) em andamento' % total)
        except Exception:
            pass
        try:
            if empty.winfo_manager():
                empty.pack_forget()
        except Exception:
            pass

    def _render_pow_empty(self, window, count, empty):
        try:
            count.config(text='Nenhum cálculo em andamento')
        except Exception:
            pass
        try:
            if not empty.winfo_manager():
                empty.pack(pady=8)
        except Exception:
            pass

    def _pow_selected_token(self, window):
        try:
            listbox = window._pow_listbox
            selection = listbox.curselection()
        except Exception:
            return None
        if not selection:
            return None
        try:
            return window._pow_tokens[selection[0]]
        except Exception:
            return None

    def _cancel_selected_pow(self, window):
        token = self._pow_selected_token(window)
        if token is None:
            self._flash_status('Selecione um POW para cancelar')
            return
        try:
            self.client.cancel_pow(token)
        except Exception:
            pass
        self._flash_status('POW %s: cancelamento pedido' % token)
        try:
            self._refresh_pow_window(window, force=True)
        except Exception:
            pass

    def _cancel_all_pows_ui(self, window):
        try:
            tasks = self.client.list_pow_tasks()
        except Exception:
            tasks = []
        if not tasks:
            return
        try:
            self.client.cancel_all_pow()
        except Exception:
            pass
        self._flash_status('Cancelando %d POW(s)…' % len(tasks))
        try:
            self._refresh_pow_window(window, force=True)
        except Exception:
            pass

    def _auto_update_enabled(self):
        try:
            from .. import update as updater
            raw = self.client.db.get_setting(updater.AUTO_UPDATE_KEY, str(updater.AUTO_UPDATE_DEFAULT))
            return bool(updater.parse_auto_update(raw))
        except Exception:
            return True

    def _update_interval_h(self):
        try:
            from .. import update as updater
            raw = self.client.db.get_setting(updater.UPDATE_INTERVAL_KEY, str(updater.UPDATE_INTERVAL_DEFAULT_H))
            return float(updater.parse_update_interval_h(raw))
        except Exception:
            return 6.0

    def _cancel_periodic_update_check(self):
        pending = getattr(self, '_update_timer_after', None)
        if pending is None:
            return
        try:
            self.after_cancel(pending)
        except Exception:
            pass
        try:
            self._update_timer_after = None
        except Exception:
            pass

    def _schedule_periodic_update_check(self):
        self._cancel_periodic_update_check()
        try:
            interval = float(self._update_interval_h())
        except Exception:
            interval = 6.0
        if not interval or interval <= 0:
            return
        delay = int(interval * 3600 * 1000)
        if delay <= 0:
            return
        try:
            self._update_timer_after = self.after(min(delay, 2 ** 31 - 1), self._periodic_update_fire)
        except Exception:
            pass

    def _periodic_update_fire(self):
        self._update_timer_after = None
        if getattr(self, '_closed', False):
            return
        try:
            self._schedule_periodic_update_check()
        except Exception:
            pass
        if getattr(self, '_closed', False):
            return
        try:
            threading.Thread(target=self._auto_update_check, daemon=True,
                             name='update-check-periodic').start()
        except Exception:
            pass

    def _update_progress_from_worker(self, phase):
        try:
            if phase == 'merge':
                self.client._log('update', 'Aplicando…')
            elif phase == 'fetch':
                self.client._log('update', 'Baixando atualização…')
        except Exception:
            pass

    @staticmethod
    def _result_behind(result):
        try:
            return int(result.get('behind', 0) or 0)
        except Exception:
            return 0

    def _safe_auto_enabled(self):
        try:
            return bool(self._auto_update_enabled())
        except Exception:
            return True

    def _safe_tree_clean(self):
        try:
            from .. import update as updater
            return bool(updater.is_tree_clean())
        except Exception:
            return False

    def _queue_ui_event(self, event):
        try:
            self.client.ui_queue.put(event)
        except Exception:
            pass

    def _log_auto_check_issue(self, result, status):
        if status == 'up-to-date':
            return
        try:
            from .. import update as updater
            self.client._log('update', updater.describe_update_result(result))
        except Exception:
            pass

    def _notify_dirty_hold_once(self, behind):
        if getattr(self, '_update_dirty_notified', False):
            return
        self._update_dirty_notified = True
        try:
            from .. import update as updater
            self.client._log('update', updater.describe_dirty_hold(behind))
        except Exception:
            pass

    def _handle_auto_check_result(self, result):
        try:
            status = result.get('status')
        except Exception:
            return
        if status != 'update-available':
            self._log_auto_check_issue(result, status)
            return
        behind = self._result_behind(result)
        if not self._safe_auto_enabled():
            self._queue_ui_event(('update-available', behind))
            return
        if not self._safe_tree_clean():
            self._notify_dirty_hold_once(behind)
            return
        if getattr(self, '_closed', False) or _get_update_flag(self, '_update_applying', False):
            return
        _set_update_flag(self, '_update_applying', True)
        _set_update_flag(self, '_update_auto', True)
        try:
            self._do_update()
        except Exception:
            _set_update_flag(self, '_update_applying', False)
            _set_update_flag(self, '_update_auto', False)

    def _auto_update_check(self):
        if getattr(self, '_closed', False) or _get_update_flag(self, '_update_checking', False):
            return
        if _get_update_flag(self, '_update_applying', False):
            return
        _set_update_flag(self, '_update_checking', True)
        try:
            from .. import update as updater
            result = updater.check_for_updates()
        except Exception as exc:
            result = {'status': 'error', 'error': repr(exc)}
        finally:
            _set_update_flag(self, '_update_checking', False)
            self._update_last_check = time.time()
        if result is None or getattr(self, '_closed', False):
            return
        self._handle_auto_check_result(result)

    def _check_updates_manual(self):
        if _get_update_flag(self, '_update_checking', False) or _get_update_flag(self, '_update_applying', False):
            self._flash_status('Verificação em andamento…')
            return
        now = time.time()
        last = float(getattr(self, '_update_last_manual', 0.0) or 0.0)
        if now - last < 10.0:
            self._flash_status('Verificação feita há pouco; aguarde…')
            return
        _set_update_flag(self, '_update_checking', True)
        self._flash_status('Verificando atualizações…')

        def worker():
            try:
                from .. import update as updater
                result = updater.check_for_updates()
            except Exception as exc:
                result = {'status': 'error', 'error': repr(exc)}
            finally:
                _set_update_flag(self, '_update_checking', False)
                self._update_last_check = time.time()
                self._update_last_manual = time.time()
            try:
                self.client.ui_queue.put(('update-check-result', result))
            except Exception:
                pass
        threading.Thread(target=worker, daemon=True,
                         name='update-check-manual').start()

    def _show_update_check(self, result):
        from .. import update as updater
        status = result.get('status')
        try:
            if isinstance(result, dict) and result.get('upstream_fixed'):
                self._flash_status('Ramo ligado às atualizações automáticas…')
        except Exception:
            pass
        if status == 'update-available':
            self._offer_update(result.get('behind', 0), result)
            return
        if status == 'up-to-date':
            dialogs.info(self, 'Atualização', updater.describe_update_result(result))
        elif status == 'no-upstream':
            # Irresolúvel: texto sem jargão de terminal (ver describe).
            dialogs.warn(self, 'Atualização', updater.describe_update_result(result))
        else:
            dialogs.warn(self, 'Atualização', updater.describe_update_result(result))

    def _update_offer_text(self, count, result):
        # M8: declara sem verify-commit e sem pin (mantém o aviso).
        lines = ['Há atualização disponível (%d commit(s) novo(s)).' % count]
        if isinstance(result, dict):
            upstream = result.get('upstream')
            local_short = result.get('local_short')
            remote_short = result.get('remote_short')
            if upstream:
                lines.append('Ramo: %s' % upstream)
            if local_short and remote_short:
                lines.append('Versão: %s → %s' % (local_short, remote_short))
            commits = result.get('commits') or []
            if commits:
                lines.append('')
                lines.extend('• %s' % line for line in commits[:10])
        lines.append('')
        lines.append('SEM verificação de assinatura de commit '
                     '(verify-commit) e SEM pin de commit: o código remoto '
                     'será executado ao reiniciar; atualize só a partir de '
                     'fontes confiáveis. '
                     'Alterações locais cancelam a atualização (proteção).')
        lines.append('Atualizar e reiniciar agora?')
        return '\n'.join(lines)

    def _offer_update(self, behind, result=None):
        if _get_update_flag(self, '_update_applying', False):
            self._flash_status('Atualização em andamento…')
            return
        try:
            count = int(behind)
        except (TypeError, ValueError):
            count = 0
        if result is None:
            try:
                from .. import update as updater
                result = updater.get_update_preview()
                count = int(result.get('behind', count))
            except Exception:
                result = None
        ok = dialogs.confirm(
            self, 'Atualização disponível',
            self._update_offer_text(count, result))
        if ok:
            _set_update_flag(self, '_update_applying', True)
            self._flash_status('Baixando atualização…')
            threading.Thread(target=self._do_update, daemon=True,
                             name='update-apply').start()

    def _do_update(self, progress=None):
        if progress is None:
            try:
                progress = self._update_progress_from_worker
            except Exception:
                progress = None
        try:
            from .. import update as updater
            ok, message = updater.perform_update(progress=progress)
        except Exception as exc:
            ok, message = False, 'falha na atualização (%s). Tente de novo' % exc
        try:
            self.client.ui_queue.put(('update-result', ok, message))
        except Exception:
            pass

    def _restart_after_update(self):
        # Item 6: o after(800) pode disparar após o fechamento.
        if getattr(self, '_closed', False):
            return
        try:
            self._save_pending_draft()
        except Exception:
            pass
        try:
            from .. import update as updater
            updater.restart_program(pre_exec=self._shutdown_client)
        except Exception as exc:
            dialogs.warn(self, 'Atualização',
                         'Atualizado, mas reinicie à mão: %s' % exc)

    def _save_pending_draft(self):
        try:
            from .. import update as updater
            try:
                text = self.input_var.get()
            except Exception:
                text = ''
            kind = getattr(self, 'current_kind', None)
            address = getattr(self, 'current_address', None)
            updater.save_pending_draft(self.client.db, text, kind, address)
        except Exception:
            pass

    def _take_pending_draft(self):
        try:
            from .. import update as updater
            draft = updater.load_pending_draft(self.client.db)
            if not draft:
                return None
            updater.clear_pending_draft(self.client.db)
            return draft
        except Exception:
            return None

    @staticmethod
    def _scan_draft_meta(meta, address, kind, strict):
        for pos, item in enumerate(meta):
            try:
                item_kind, item_address = item
            except Exception:
                continue
            if item_address != address:
                continue
            if not strict or kind is None or item_kind == kind:
                return pos, item_kind
        return None

    @staticmethod
    def _find_pending_conversation(meta, kind, address):
        found = App._scan_draft_meta(meta, address, kind, True)
        if found is None:
            found = App._scan_draft_meta(meta, address, kind, False)
        return found

    def _pending_meta(self):
        try:
            return list(getattr(self, '_conv_meta', None) or [])
        except Exception:
            return []

    def _apply_pending_draft(self, index, kind, address, text):
        try:
            self._conv_selected = index
            self._open_conversation(kind, address)
        except Exception:
            return
        try:
            self._clear_placeholder()
            self.input_var.set(text)
            self._placeholder_on = False
        except Exception:
            pass

    def _restore_pending_draft(self):
        draft = self._take_pending_draft()
        if not draft:
            return
        try:
            address = draft.get('address')
            kind = draft.get('kind')
            text = draft.get('text')
        except Exception:
            return
        if not address or not text:
            return
        found = self._find_pending_conversation(self._pending_meta(), kind, address)
        if found is None:
            return
        index, kind = found
        self._apply_pending_draft(index, kind, address, text)

    def _about(self):
        dialogs.info(
            self, 'Sobre o bmchat',
            ('bmchat %s\nChat estilo Telegram usando o protocolo '
             'Bitmessage (somente Bitmessage).\n'
             'Suporta contatos, canais, proxy e redes darknet (Tor/I2P).')
            % BMCHAT_VERSION)

    # -------------------------------------------------- higiene de after (item 6)

    def _dialog_shell(self, title, geometry=None):
        """Casca de Toplevel próprio: aparece já; recheio vai em after_idle.

        Usado pelos diálogos próprios (itens 2 e 5). O fill usa
        ``window.after_idle`` (cancelado sozinho se a janela for destruída).
        """
        window = tk.Toplevel(self)
        try:
            window.transient(self)
        except Exception:
            pass
        try:
            window.title(title)
        except Exception:
            pass
        if geometry:
            try:
                window.geometry(geometry)
            except Exception:
                pass
        self._bind_destroy_cancel(window)
        try:
            window.deiconify()
        except Exception:
            pass
        return window

    def _bind_destroy_cancel(self, window):
        try:
            window.bind('<Destroy>', self._cancel_window_afters, add='+')
        except Exception:
            pass

    def _cancel_window_afters(self, event):
        try:
            window = event.widget
            pending = getattr(window, '_refresh_after', None)
            if pending is not None:
                try:
                    window.after_cancel(pending)
                except Exception:
                    pass
                try:
                    window._refresh_after = None
                except Exception:
                    pass
        except Exception:
            pass

    def _close_current_dialog(self):
        """Close the currently open dialog/popup."""
        for child in self.winfo_children():
            if isinstance(child, tk.Toplevel):
                try:
                    child.destroy()
                except Exception:
                    pass

    def _handle_escape(self):
        """Handle Escape key - close dialogs or clear search."""
        # Close any open dialog first
        dialog_closed = False
        for child in self.winfo_children():
            if isinstance(child, tk.Toplevel):
                try:
                    child.destroy()
                    dialog_closed = True
                except Exception:
                    pass
        # If no dialog was open, clear search
        if not dialog_closed:
            if self.search_frame.winfo_manager():
                self.search_var.set('')
                self._conv_filter = ''
                self._draw_conversations()
                self.search_frame.pack_forget()

    def _cancel_after(self, attr):
        try:
            pending = getattr(self, attr, None)
        except Exception:
            pending = None
        if pending is not None:
            try:
                self.after_cancel(pending)
            except Exception:
                pass
        try:
            setattr(self, attr, None)
        except Exception:
            pass

    def _shutdown_client(self):
        try:
            self.client.stop()
        except Exception:
            pass

    def _on_close(self):
        # Item 6: flag + cancela poll/tick/redraws/debounces/startup para
        # zerar os erros pós-destroy ("invalid command name ... destroyed").
        self._closed = True
        for attr in ('_startup_after', '_poll_after', '_tick_after',
                     '_redraw_after', '_conv_hover_after', '_conv_draw_after',
                     '_refresh_after'):
            self._cancel_after(attr)
        self._shutdown_client()
        try:
            self.destroy()
        except Exception:
            pass


def main(data_dir, client=None):
    """Entry point com Dependency Injection.

    Args:
        data_dir: diretório de dados
        client: Client opcional injetado (para testes / DI manual)
    """
    app = App(data_dir, client=client)
    app.mainloop()
