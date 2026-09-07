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
from .notification import notify, get_notification_manager
from .. import SUPPORT_ADDRESS, SUPPORT_LABEL
from ..core.client import Client
from ..core.database import Database
from ..crypto.encrypted_db import (
    is_encrypted, export_encrypted_backup, import_encrypted_backup,
    change_password, enable_encryption
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
    lines.append('')
    lines.append('== Config ==')
    for key, default in (('connect_timeout', 30), ('recv_timeout', 60),
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
    lines.append('')
    lines.append('== Log recente ==')
    try:
        logs = client.recent_logs(50)
    except Exception:
        logs = []
    lines.extend(logs or ['(vazio)'])
    lines.append('')
    lines.append('NAO incluido: chaves privadas, conteudo das mensagens.')
    return '\n'.join(lines)


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
            '%s' % (conn['host'], conn['port'], state, version, streams,
                    conn['services'], conn.get('rating', 0), clock))
        lines.append(
            '  ↑ %s  ↓ %s  há %ds' % (
                _fmt_bytes(conn['bytes_sent']),
                _fmt_bytes(conn['bytes_received']), conn['age']))
    return '\n'.join(lines)


def _avatar_color(key):
    return SENDER_COLORS[abs(hash(key)) % len(SENDER_COLORS)]


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
            wkey = (fid, word)
            word_w = measure_cache.get(wkey)
            if word_w is None:
                word_w = font.measure(word)
                measure_cache[wkey] = word_w
                if len(measure_cache) > 5000:
                    for k in list(measure_cache.keys())[:2500]:
                        measure_cache.pop(k, None)
            trial_w = word_w if not current else current_w + space_w + word_w
            if trial_w <= max_width:
                current = word if not current else current + ' ' + word
                current_w = trial_w
            else:
                if current:
                    lines.append(current)
                while word and word_w > max_width:
                    cut = _fit_long_word(font, word, max_width)
                    lines.append(word[:cut])
                    word = word[cut:]
                    wkey = (fid, word)
                    word_w = measure_cache.get(wkey)
                    if word_w is None:
                        word_w = font.measure(word)
                        measure_cache[wkey] = word_w
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

    def __init__(self, data_dir):
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
        self.client = Client(data_dir)
        # Startup: rede/DB pesado roda em thread; a janela pinta antes.
        self._client_started = False
        self._client_start_error = None
        try:
            threading.Thread(target=self._start_client_bg, daemon=True,
                             name='client-start').start()
        except Exception:
            try:
                self.client.start()
                self._client_started = True
            except Exception as exc:
                self._client_start_error = exc

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

        self.conv_list = _ConvListAdapter(self)
        self.chat_text = _ChatTextAdapter()
        self._identity_map = {}
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
        try:
            self._startup_after = self.after_idle(self._startup_step_build)
        except Exception:
            self._startup_after = None

    # -------------------------------------------------- startup diferido (item 1)

    def _start_client_bg(self):
        try:
            self.client.start()
            self._client_started = True
        except Exception as exc:
            self._client_start_error = exc

    def _startup_step_build(self):
        self._startup_after = None
        if getattr(self, '_closed', False):
            return
        try:
            self._build_widgets_left()
        except Exception:
            pass
        if getattr(self, '_closed', False):
            return
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
        try:
            # after(ms) em vez de after_idle: dá chance de paint entre fatias
            # (idle callbacks esgotariam no mesmo update()).
            self._startup_after = self.after(30, self._startup_step_build_left_b)
        except Exception:
            self._startup_after = None

    def _startup_step_build_left_b(self):
        self._startup_after = None
        if getattr(self, '_closed', False):
            return
        try:
            self._build_widgets_left_b()
        except Exception:
            pass
        if getattr(self, '_closed', False):
            return
        try:
            try:
                self.update_idletasks()
            except Exception:
                pass
            self._startup_after = self.after(30, self._startup_step_build_right)
        except Exception:
            self._startup_after = None

    def _startup_step_build_right(self):
        self._startup_after = None
        if getattr(self, '_closed', False):
            return
        try:
            self._build_widgets_right()
        except Exception:
            pass
        if getattr(self, '_closed', False):
            return
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
        try:
            self._startup_after = self.after_idle(self._startup_step_data)
        except Exception:
            self._startup_after = None

    def _startup_step_data(self):
        self._startup_after = None
        if getattr(self, '_closed', False):
            return
        if not getattr(self, '_client_started', False):
            if getattr(self, '_client_start_error', None) is not None:
                try:
                    boot = getattr(self, '_boot_label', None)
                    if boot is not None:
                        boot.config(text='Falha ao iniciar rede local; tentando…')
                except Exception:
                    pass
            else:
                try:
                    self._startup_after = self.after(100, self._startup_step_data)
                except Exception:
                    self._startup_after = None
                return
        try:
            if not self.client.identities:
                self.client.create_identity('Minha identidade')
        except Exception:
            pass
        try:
            self._refresh_identity_menu()
        except Exception:
            pass
        try:
            self._refresh_conversations()
        except Exception:
            pass
        if getattr(self, '_closed', False):
            return
        try:
            self._startup_after = self.after_idle(self._startup_step_live)
        except Exception:
            self._startup_after = None

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
        inner.pack(fill='x', padx=8, pady=6)
        tk.Label(inner, text='Enviar como:', bg=PANEL_BG, fg=TEXT_GRAY,
                 font=self.small_font).pack(side='left')
        self.identity_var = tk.StringVar()
        self.identity_menu = tk.OptionMenu(inner, self.identity_var, '')
        self.identity_menu.configure(bg=PANEL_BG, fg=TEXT_INK, relief='flat',
                                     highlightthickness=0, activebackground=ROW_HOVER,
                                     font=self.preview_font)
        self.identity_menu['menu'].configure(bg=PANEL_BG, fg=TEXT_INK)
        self.identity_menu.pack(side='left', padx=4, fill='x', expand=True)
        ToolTip(self.identity_menu, 'Selecionar identidade')
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
        self.input_frame.columnconfigure(1, weight=1)
        tk.Frame(self.input_frame, bg=LINE, height=1).grid(
            row=0, column=0, columnspan=4, sticky='ew')
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
        self.input_entry = tk.Entry(
            self.input_frame, textvariable=self.input_var, relief='flat',
            bd=0, highlightthickness=0, font=self.msg_font, fg=TEXT_INK)
        self.input_entry.grid(row=1, column=2, sticky='ew', padx=4)
        self.input_frame.columnconfigure(2, weight=1)
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

    def _dismiss_open_menu(self, event=None):
        menu = self._open_menu
        if menu is None:
            return
        widget = getattr(event, 'widget', None)
        if widget is not None:
            try:
                is_menu = widget is menu or \
                    widget.winfo_class() == 'Menu'
            except Exception:
                is_menu = False
            if is_menu:
                return
        if time.time() - self._menu_opened_at < 0.05:
            return
        self._open_menu = None
        try:
            menu.unpost()
        except Exception:
            pass
        try:
            menu.grab_release()
        except Exception:
            pass

    def _popup(self, menu, widget):
        menu.tk_popup(widget.winfo_rootx(), widget.winfo_rooty() +
                      widget.winfo_height())
        self._track_menu(menu)

    def _hamburger_menu(self):
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label='Minha identidade', command=self._show_welcome)
        menu.add_command(label='Suporte…', command=self._support)
        menu.add_separator()
        menu.add_command(label='Nova identidade', command=self._new_identity)
        menu.add_command(label='Novo contato', command=self._new_contact)
        menu.add_separator()
        menu.add_command(label='Backup de identidade…',
                         command=self._backup_identity)
        menu.add_command(label='Backup criptografado…',
                         command=self._encrypted_backup)
        menu.add_command(label='Restaurar backup criptografado…',
                         command=self._restore_encrypted_backup)
        menu.add_separator()
        menu.add_command(label='Criptografar banco de dados…',
                         command=self._encrypt_database)
        menu.add_command(label='Alterar senha do banco…',
                         command=self._change_db_password)
        menu.add_separator()
        menu.add_command(label='Diagnóstico de rede…',
                         command=self._network_diagnostics)
        menu.add_command(label='Ver log…', command=self._show_log)
        menu.add_command(label='Configurações de rede…',
                         command=self._network_settings)
        menu.add_command(label='Apagar objetos…', command=self._wipe_objects)
        menu.add_command(label='Proxy / Darknet...', command=self._proxy_dialog)
        menu.add_command(label='Verificar POW ativos', command=self._show_pows)
        menu.add_command(label='Verificar atualizações',
                         command=self._check_updates_manual)
        menu.add_separator()
        # Theme submenu
        theme_menu = tk.Menu(menu, tearoff=0)
        theme_menu.add_command(label='☀️  Claro', command=lambda: self._set_theme('light'))
        theme_menu.add_command(label='🌙  Escuro', command=lambda: self._set_theme('dark'))
        menu.add_cascade(label='Tema', menu=theme_menu)
        menu.add_command(label='Legenda de confirmações',
                         command=self._confirmation_legend)
        menu.add_command(label='Sobre', command=self._about)
        self._popup(menu, self.left_header)

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
                self.input_entry.config(fg=TEXT_GRAY)
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
            if hasattr(self, 'left') and self.left.winfo_exists():
                self.left.configure(bg=PANEL_BG)
            if hasattr(self, 'right') and self.right.winfo_exists():
                self.right.configure(bg=CHAT_BG)
            if hasattr(self, 'left_header') and self.left_header.winfo_exists():
                self.left_header.configure(bg=HEADER_BG)
            if hasattr(self, 'chat_frame') and self.chat_frame.winfo_exists():
                self.chat_frame.configure(bg=CHAT_BG)
            if hasattr(self, 'input_frame') and self.input_frame.winfo_exists():
                self.input_frame.configure(bg=PANEL_BG)
            if hasattr(self, 'search_frame') and self.search_frame.winfo_exists():
                self.search_frame.configure(bg=PANEL_BG)
            if hasattr(self, 'conv_canvas') and self.conv_canvas.winfo_exists():
                self.conv_canvas.configure(bg=PANEL_BG)
            if hasattr(self, 'chat_canvas') and self.chat_canvas.winfo_exists():
                self.chat_canvas.configure(bg=CHAT_BG)
            if hasattr(self, 'welcome_copy_btn') and self.welcome_copy_btn.winfo_exists():
                self.welcome_copy_btn.configure(bg=FAB_BG, activebackground=_c('accent_hover'))
            if hasattr(self, 'jump_btn') and self.jump_btn.winfo_exists():
                self.jump_btn.configure(bg=PANEL_BG, fg=_c('text_secondary'))
            if hasattr(self, 'send_btn') and self.send_btn.winfo_exists():
                self.send_btn.configure(bg=PANEL_BG)
            if hasattr(self, 'input_entry') and self.input_entry.winfo_exists():
                self.input_entry.configure(bg=_c('input_bg'), fg=_c('input_fg'),
                                           insertbackground=_c('input_fg'))
            if hasattr(self, 'left_header') and self.left_header.winfo_exists():
                for btn in self.left_header.winfo_children():
                    if isinstance(btn, tk.Button):
                        btn.configure(bg=HEADER_BG, activebackground=HEADER_BG_DARK, fg=HEADER_FG)
        except Exception:
            pass

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
        self.input_var.set('Mensagem')
        self.input_entry.config(fg=TEXT_GRAY)
        self._placeholder_on = True

    def _clear_placeholder(self, _event=None):
        if self._placeholder_on:
            self.input_var.set('')
            self.input_entry.config(fg=TEXT_INK)
            self._placeholder_on = False

    def _restore_placeholder(self, _event=None):
        if not self._placeholder_on and not self.input_var.get().strip():
            if getattr(self, '_input_enabled', False):
                self._set_placeholder()

    def _set_input_enabled(self, enabled):
        self._input_enabled = enabled
        try:
            self.input_entry.config(
                state='normal' if enabled else 'disabled')
        except Exception:
            pass
        try:
            color = FAB_BG if enabled else '#c3ccd4'
            fg = 'white' if enabled else '#eef1f4'
            self.send_btn.itemconfig(self._send_oval, fill=color,
                                     outline=color)
            self.send_btn.itemconfig(self._send_arrow, fill=fg)
        except Exception:
            pass
        if enabled:
            if self._placeholder_on:
                self._set_placeholder()
        elif self._placeholder_on or not self.input_var.get().strip():
            self.input_var.set('Selecione uma conversa para começar')
            try:
                self.input_entry.config(fg=TEXT_GRAY)
            except Exception:
                pass
            self._placeholder_on = True

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
            emoji = emojis[index]
            try:
                tk.Button(popup, text=emoji, font=('', 14), relief='flat',
                          bd=0,
                          command=lambda e=emoji: (
                              self._clear_placeholder(),
                              self.input_entry.insert('insert', e),
                              self.input_entry.focus_set(),
                              popup.destroy())).grid(
                                  row=index // 6, column=index % 6,
                                  padx=2, pady=2)
            except Exception:
                return
        if start + 6 < len(emojis):
            try:
                popup.after_idle(
                    lambda: self._fill_emoji(popup, emojis, start + 6))
            except Exception:
                pass

    # -------------------------------------------------- events

    _KNOWN_UI_EVENTS = frozenset([
        'log', 'message', 'broadcast', 'pubkey', 'status',
        'identity-created', 'contact-added', 'contact-removed', 'subscribed',
        'channel-created', 'broadcast-sent', 'pow-progress',
        'pow-cancelled', 'ack', 'update-available', 'update-check-result',
        'update-result',
    ])

    def _poll(self):
        # Item 6: não reagenda nada após _on_close.
        if getattr(self, '_closed', False):
            self._poll_after = None
            return
        try:
            while True:
                try:
                    event = self.client.ui_queue.get_nowait()
                except queue.Empty:
                    break
                try:
                    kind = event[0]
                except Exception:
                    continue
                try:
                    self._handle_event(event)
                except Exception as exc:
                    if kind not in self._KNOWN_UI_EVENTS:
                        continue
                    try:
                        self.statusbar.config(
                            text='Erro interno: %s' % exc)
                    except Exception:
                        pass
        except Exception as exc:
            try:
                self.statusbar.config(text='Erro: %s' % exc)
            except Exception:
                pass
        finally:
            if getattr(self, '_closed', False):
                self._poll_after = None
            else:
                try:
                    self._poll_after = self.after(250, self._poll)
                except Exception:
                    self._poll_after = None

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

    def _handle_event(self, event):
        kind = event[0]
        if kind == 'log':
            self._flash_status(event[2])
        elif kind == 'message':
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
        elif kind == 'broadcast':
            self._flash_status('Nova postagem no canal')
            self._schedule_refresh()
            try:
                notify('Novo post no canal', 'Nova mensagem em canal inscrito')
            except Exception:
                pass
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
            self._refresh_conversations()
        elif kind in ('contact-added', 'contact-removed', 'subscribed', 'channel-created'):
            self._refresh_conversations()
        elif kind == 'broadcast-sent':
            self._reload_chat()
        elif kind == 'pow-progress':
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
        elif kind == 'pow-cancelled':
            self.statusbar.config(text='POW cancelado')
        elif kind == 'update-available':
            _, behind = event
            self._offer_update(behind)
        elif kind == 'update-check-result':
            _, result = event
            self._show_update_check(result)
        elif kind == 'update-result':
            _, ok, message = event
            if ok:
                self._flash_status('Atualizado! Reiniciando…')
                self.after(800, self._restart_after_update)
            else:
                dialogs.warn(self, 'Atualização', message)

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

    def _current_identity(self):
        value = self.identity_var.get()
        return self._identity_map.get(value, value)

    def _refresh_identity_menu(self):
        menu = self.identity_menu['menu']
        menu.delete(0, 'end')
        addresses = list(self.client.identities.keys())
        if not addresses:
            return
        self._identity_map = {}
        for address in addresses:
            display = self._identity_display(address)
            self._identity_map[display] = address
            menu.add_command(
                label=display,
                command=lambda disp=display: self.identity_var.set(disp))
        if self.identity_var.get() not in self._identity_map:
            self.identity_var.set(self._identity_display(addresses[0]))

    # -------------------------------------------------- conversations

    def _refresh_conversations(self):
        self._conv_meta = []
        self._conv_labels = []
        try:
            contacts = self.client.db.all_contacts()
        except Exception:
            contacts = []
        for contact in contacts:
            self._conv_meta.append(('contact', contact['address']))
            self._conv_labels.append(contact['label'] or contact['address'])
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
            # Cached font.measure
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

            if text_w <= max_width:
                fitted = text
            else:
                # Cached ellipsis width per font
                ell_w = self._ellipsis_w.get(id(font))
                if ell_w is None:
                    ell_w = font.measure('…')
                    self._ellipsis_w[id(font)] = ell_w
                avail = max_width - ell_w
                count = len(text)
                if avail <= 0 or count == 0:
                    fitted = '…'
                else:
                    avg = text_w / count
                    cut = int(avail / avg) if avg > 0 else 0
                    if cut < 0:
                        cut = 0
                    elif cut > count:
                        cut = count
                    fitted = text[:cut] + '…'
        except Exception:
            return _fit_width(font, text, max_width)
        try:
            self._fit_cache[key] = fitted
            self._fit_order.append(key)
            while len(self._fit_order) > 300:
                old = self._fit_order.pop(0)
                self._fit_cache.pop(old, None)
        except Exception:
            pass
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

    def _conv_hover_debounced(self, event):
        if getattr(self, '_closed', False):
            return
        pending = getattr(self, '_conv_hover_after', None)
        if pending is not None:
            try:
                self.after_cancel(pending)
            except Exception:
                pass
            self._conv_hover_after = None
        try:
            y = event.y
        except Exception:
            return

        def _apply():
            self._conv_hover_after = None
            try:
                fake = type('E', (), {'y': y})()
                self._conv_hover(fake)
            except Exception:
                pass
        try:
            self._conv_hover_after = self.after(80, _apply)
        except Exception:
            self._conv_hover_after = None

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
            self.client.remove_contact(address)
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

    def _open_conversation(self, kind, address):
        self.current_kind = kind
        self.current_address = address
        self.input_var.set('')
        self._set_placeholder()
        self._chat_limit = 200
        self._chat_has_more = False
        self._chat_pill = None
        try:
            self._wrap_cache.clear()
            self._wrap_order.clear()
        except Exception:
            self._wrap_cache = {}
            self._wrap_order = []
        self._set_input_enabled(True)
        if kind == 'contact':
            row = self.client.db.get_contact(address)
            label = row['label'] if row else address
            # Bitmessage não tem presença: o único estado real que
            # conhecemos do contato é se já temos a chave pública dele.
            if self.client.has_pubkey(address):
                status = 'chave pública conhecida'
            else:
                status = 'aguardando chave pública…'
        elif kind == 'channel':
            row = None
            try:
                row = self.client.db.get_subscription(address)
            except Exception:
                row = None
            if row:
                label = (row.get('name') or row.get('label')) or address
                label = '# ' + label
            else:
                try:
                    ident = self.client.db.get_identity(address)
                except Exception:
                    ident = None
                if ident:
                    label = '# ' + ((ident.get('chan_label') or ident.get('label')) or address)
                else:
                    label = '# ' + address
            status = 'canal Bitmessage (broadcast)'
        else:
            row = self.client.db.get_contact(address)
            label = (row['label'] if row else '') or address
            status = address[:18] + '…' if len(address) > 19 else address
        self.chat_title.config(text=label)
        self.chat_subtitle.config(text=status)
        color = _avatar_color(address)
        self.peer_avatar.delete('all')
        self.peer_avatar.create_oval(1, 1, 35, 35, fill=color, outline=color)
        self.peer_avatar.create_text(18, 18, text=_initials(label),
                                     fill='white', font=('', 11, 'bold'))
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
        if status == 'sent':
            return ('Publicada na rede — aguardando a confirmação (ACK) '
                    'do destinatário')
        if status == 'ackreceived':
            return 'Entregue — confirmação (ACK) recebida do destinatário'
        return str(status)

    def _calc_attachment_height(self, attachment, max_width, out):
        """Calculate height needed for an attachment."""
        mime = attachment['mime']
        is_image = mime.startswith('image/')
        if is_image:
            # Try to get image dimensions
            try:
                import base64
                from io import BytesIO
                from PIL import Image
                img_data = base64.b64decode(attachment['data'])
                img = Image.open(BytesIO(img_data))
                max_img_w = min(300, max_width - 2 * PAD_X)
                if img.width > max_img_w:
                    ratio = max_img_w / img.width
                    return int(img.height * ratio) + 8
                return img.height + 8
            except Exception:
                return 48  # fallback
        return 48  # file icon box height

    def _parse_attachments(self, body: str):
        """Parse attachment markers from message body.
        
        Returns (clean_body, attachments_list) where attachments_list contains
        dicts with filename, mime, data (base64).
        """
        import re
        attachments = []
        # Pattern: [attachment:filename:mime:base64data]
        pattern = r'\[attachment:([^:]+):([^:]+):([^\]]+)\]'
        
        def replace(match):
            filename = match.group(1)
            mime = match.group(2)
            data = match.group(3)
            attachments.append({'filename': filename, 'mime': mime, 'data': data})
            return ''  # Remove marker from display body
        
        clean_body = re.sub(pattern, replace, body)
        return clean_body, attachments

    def _render_attachment(self, canvas, x, y, attachment, max_width, out):
        """Render an attachment inline in the chat bubble."""
        filename = attachment['filename']
        mime = attachment['mime']
        data = attachment['data']
        
        import base64
        try:
            # Decode base64 data
            img_data = base64.b64decode(data)
        except Exception:
            img_data = None
        
        is_image = mime.startswith('image/') and img_data is not None
        
        if is_image:
            # Try to create PhotoImage for inline display
            try:
                from io import BytesIO
                from PIL import Image, ImageTk
                img = Image.open(BytesIO(img_data))
                # Resize to fit in bubble (max 300px width)
                max_img_w = min(300, max_width - 2 * PAD_X)
                if img.width > max_img_w:
                    ratio = max_img_w / img.width
                    new_h = int(img.height * ratio)
                    img = img.resize((max_img_w, new_h), Image.LANCZOS)
                photo = ImageTk.PhotoImage(img)
                # Store reference to prevent GC
                if not hasattr(self, '_chat_images'):
                    self._chat_images = []
                self._chat_images.append(photo)
                # Create image on canvas
                canvas.create_image(x + PAD_X, y, anchor='nw', image=photo)
                return img.height + 8
            except Exception:
                pass  # Fall back to file icon
        
        # File icon fallback
        icon = '📄'
        if mime.startswith('image/'):
            icon = '🖼'
        elif mime.startswith('video/'):
            icon = '🎬'
        elif mime.startswith('audio/'):
            icon = '🎵'
        elif mime.startswith('text/'):
            icon = '📝'
        elif mime == 'application/pdf':
            icon = '📕'
        
        # Draw file preview box
        box_h = 40
        canvas.create_rectangle(x, y, x + max_width, y + box_h,
                                fill=BUBBLE_IN if not out else BUBBLE_OUT,
                                outline=DATE_BG)
        canvas.create_text(x + 10, y + box_h // 2, anchor='w',
                           text=f'{icon} {filename}', fill=TEXT_INK,
                           font=self.msg_font)
        return box_h + 8

    def _redraw_chat(self):
        self._redraw_after = None
        if getattr(self, '_closed', False):
            return
        canvas = self.chat_canvas
        canvas.delete('all')
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
        max_bubble = int(width * 0.62)
        line_h = self.msg_font.metrics('linespace')
        small_h = self.small_font.metrics('linespace')

        items = []
        last_day = None
        for row in self._chat_rows:
            day = _day_key(row['timestamp'])
            if day != last_day:
                items.append(('day', _day_label(day)))
                last_day = day
            items.append(('msg', row))

        # VIRTUAL SCROLL: compute layout for all items but only RENDER visible ones
        layouts = []
        y = 14
        self._chat_pill = None
        if getattr(self, '_chat_has_more', False):
            pill_text = 'carregar mensagens anteriores'
            pill_w = self.small_font.measure(pill_text) + 26
            px0 = width / 2 - pill_w / 2
            px1 = width / 2 + pill_w / 2
            self._chat_pill = (px0, y, px1, y + 22)
            layouts.append(('more', pill_text, y, 0, 22))  # kind, text, top, idx, height
            y += 30
        msg_idx = 0
        for item in items:
            if item[0] == 'day':
                layouts.append(('day', item[1], y, msg_idx, 30))
                y += 30
                continue
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
            stamp = _clock(row['timestamp'])
            pending = False
            if out:
                ticks, _color = self._ticks(row)
                if ticks == 'clock':
                    pending = True
                    stamp_text = stamp
                    stamp_w = self.small_font.measure(stamp) + 8 + 16
                else:
                    stamp_text = '%s %s' % (stamp, ticks)
                    stamp_w = self.small_font.measure(stamp_text) + 6
            else:
                stamp_text = stamp
                stamp_w = self.small_font.measure(stamp_text) + 6
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
            layouts.append(('msg', row, sender, lines, stamp_text, out,
                            bubble_w, item_h, y, extra_row, pending, msg_idx, attachments))
            y += item_h + 6
            msg_idx += 1
        total = y + 10

        # VIRTUAL SCROLL: find visible range
        # Canvas scroll position
        try:
            scroll_top = canvas.canvasy(0)
        except Exception:
            scroll_top = 0
        scroll_bottom = scroll_top + view_h
        BUFFER = 100  # px buffer above/below viewport
        first_vis = 0
        last_vis = len(layouts) - 1
        for i, lay in enumerate(layouts):
            lay_top = lay[2]
            lay_h = lay[3]
            if lay_top + lay_h >= scroll_top - BUFFER:
                first_vis = i
                break
        for i in range(len(layouts) - 1, -1, -1):
            lay = layouts[i]
            lay_top = lay[2]
            if lay_top <= scroll_bottom + BUFFER:
                last_vis = i
                break
        self._chat_first_visible = first_vis
        self._chat_last_visible = last_vis

        self._chat_layouts = [
            (layout[7], layout[6], layout[1])  # top, height, row
            for layout in layouts if layout[0] == 'msg']

        # Draw background (only viewport + buffer)
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

        # RENDER ONLY VISIBLE ITEMS
        for i in range(first_vis, last_vis + 1):
            layout = layouts[i]
            kind = layout[0]
            if kind == 'more':
                _kind, label, top, _idx, _h = layout
                x0, y0, x1, y1 = self._chat_pill
                canvas.create_oval(x0, y0, x1, y1, fill=DATE_BG,
                                   outline=DATE_BG)
                canvas.create_text(width / 2, top + 11, text=label,
                                   fill='white', font=self.small_font)
                continue
            if kind == 'day':
                _kind, label, top, _idx, _h = layout
                pill_w = self.small_font.measure(label) + 26
                canvas.create_oval(width / 2 - pill_w / 2, top,
                                   width / 2 + pill_w / 2, top + 22,
                                   fill=DATE_BG, outline=DATE_BG)
                canvas.create_text(width / 2, top + 11, text=label,
                                   fill='white', font=self.small_font)
                continue
            (_, row, sender, lines, stamp_text, out, bubble_w, height,
             top, extra_row, pending, _msg_idx, attachments) = layout
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
                menu.add_separator()
                menu.add_command(
                    label='Detalhes',
                    command=lambda: self._message_details(row))
                menu.tk_popup(event.x_root, event.y_root)
                self._track_menu(menu)
                return

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

    def _attach_file(self):
        """Open file dialog and prepare attachment."""
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
            # Read file and encode as base64
            import base64
            import os
            with open(file_path, 'rb') as f:
                data = f.read()
            # Limit attachment size (Bitmessage max object size ~2MB)
            max_size = 1024 * 1024  # 1MB
            if len(data) > max_size:
                dialogs.warn(self, 'Arquivo grande',
                             f'O arquivo excede {max_size//1024}KB. '
                             'O Bitmessage tem limite de ~2MB por mensagem.')
                return
            b64 = base64.b64encode(data).decode('ascii')
            # Determine MIME type
            import mimetypes
            mime, _ = mimetypes.guess_type(file_path)
            if not mime:
                mime = 'application/octet-stream'
            # Store attachment info for sending
            self._pending_attachment = {
                'filename': os.path.basename(file_path),
                'mime': mime,
                'data': b64,
                'size': len(data),
            }
            # Show attachment preview in input
            self._clear_placeholder()
            preview = f'[Anexo: {os.path.basename(file_path)} ({len(data)//1024}KB)]'
            self.input_var.set(preview)
            self.input_entry.config(fg=TEXT_INK)
            self._placeholder_on = False
            self._flash_status('Anexo pronto. Digite uma mensagem opcional e envie.')
        except Exception as exc:
            dialogs.warn(self, 'Erro no anexo', repr(exc))

    def _send(self):
        try:
            if not getattr(self, 'current_address', None):
                dialogs.warn(self, 'Nenhuma conversa',
                             'Selecione uma conversa antes de enviar.')
                return
            if self._placeholder_on:
                self._flash_status('Digite uma mensagem antes de enviar.')
                return
            body = self.input_var.get().strip()
            # Handle pending attachment
            attachment = getattr(self, '_pending_attachment', None)
            if attachment:
                # Include attachment marker in body
                attach_marker = f'\n\n[attachment:{attachment["filename"]}:{attachment["mime"]}:{attachment["data"]}]'
                body = body + attach_marker if body else attach_marker
                # Clear pending attachment
                self._pending_attachment = None
            if not body:
                self._flash_status('Digite uma mensagem antes de enviar.')
                return
            if len(body.encode('utf-8')) > 5000:
                dialogs.warn(self, 'Mensagem longa',
                             'Mensagem acima de 5000 caracteres; encurte antes de enviar.')
                return
            identity = self._current_identity()
            if not identity or identity not in self.client.identities:
                dialogs.warn(self, 'Identidade ausente',
                             'Crie ou selecione uma identidade válida antes '
                             'de enviar.')
                self._refresh_identity_menu()
                return
            if getattr(self, 'current_kind', 'contact') == 'channel':
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
                return
            if self.client.db.get_contact(self.current_address) is None:
                dialogs.warn(self, 'Conversa encerrada',
                             'Este contato foi removido. Selecione outra '
                             'conversa.')
                self._refresh_conversations()
                self._show_welcome()
                return
            self.input_var.set('')
            self._set_placeholder()
            status, error = self.client.send_message(
                identity, self.current_address, '', body)
            if status != 'success':
                dialogs.warn(self, 'Erro', error or status)
        except Exception as exc:
            dialogs.warn(self, 'Erro ao enviar', repr(exc))

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
        
        result = dialogs.ask_simple(
            self, 'Agendar mensagem',
            ['date', 'time'],
            {'date': datetime.date.today().strftime('%d/%m/%Y'),
             'time': '12:00'},
            labels={'date': 'Data (DD/MM/AAAA)', 'time': 'Hora (HH:MM)'})
        if not result:
            return
        
        try:
            dt_str = f"{result['date']} {result['time']}"
            scheduled = datetime.datetime.strptime(dt_str, '%d/%m/%Y %H:%M')
        except ValueError:
            dialogs.warn(self, 'Data/hora inválida',
                         'Use o formato DD/MM/AAAA HH:MM')
            return
        
        if scheduled <= datetime.datetime.now():
            dialogs.warn(self, 'Horário passado',
                         'A data/hora deve ser futura.')
            return
        
        body = self.input_var.get().strip()
        attachment = getattr(self, '_pending_attachment', None)
        if attachment:
            attach_marker = f'\n\n[attachment:{attachment["filename"]}:{attachment["mime"]}:{attachment["data"]}]'
            body = body + attach_marker if body else attach_marker
            self._pending_attachment = None
        
        identity = self._current_identity()
        if not identity or identity not in self.client.identities:
            dialogs.warn(self, 'Identidade ausente',
                         'Crie ou selecione uma identidade válida.')
            return
        
        # Store scheduled message in database
        try:
            self.client.db.add_scheduled_message(
                identity, self.current_address, body, int(scheduled.timestamp()))
        except Exception as exc:
            dialogs.warn(self, 'Erro ao agendar', repr(exc))
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
        self.identity_var.set(self._identity_display(address))
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
        data = self.client.export_identity(address)
        if data is None:
            dialogs.warn(self, 'Backup',
                         'Chaves indisponíveis para esta identidade.')
            return
        ok = dialogs.confirm(self, 'ATENÇÃO — chaves privadas',
                             BACKUP_WARNING % data['address'])
        if not ok:
            return
        self._show_backup_window(data)

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
            path = filedialog.asksaveasfilename(
                parent=window, title='Salvar backup',
                defaultextension='.txt',
                filetypes=[('Texto', '*.txt'), ('Todos', '*.*')],
                initialfile='bmchat-backup.txt')
            if not path:
                return
            try:
                with open(path, 'w', encoding='utf-8') as handle:
                    handle.write(
                        'BACKUP DE IDENTIDADE BMCHAT\n'
                        'Guarde em lugar seguro. Se perder, é impossível '
                        'recuperar.\n\n' + body + '\n')
                try:
                    import os as _osbk
                    _osbk.chmod(path, 0o600)
                except Exception:
                    pass
            except Exception as exc:
                dialogs.warn(window, 'Backup', 'Falha ao salvar: %s' % exc)
                return
            dialogs.info(window, 'Backup', 'Backup salvo em:\n%s' % path)

        def copy():
            window.clipboard_clear()
            window.clipboard_append(body)
            dialogs.info(window, 'Backup', 'Chaves copiadas.')

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
            with open(path, 'w') as handle:
                handle.write(data)
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
        try:
            export_encrypted_backup(self.client.db.path, path, password_result['password'])
            dialogs.info(self, 'Backup criptografado',
                         f'Backup salvo em:\n{path}\n\n'
                         'Guarde a senha! Sem ela é impossível restaurar.')
        except Exception as exc:
            dialogs.warn(self, 'Erro no backup', repr(exc))

    def _restore_encrypted_backup(self):
        """Import encrypted database backup."""
        path = filedialog.askopenfilename(
            parent=self, title='Restaurar backup criptografado',
            filetypes=[('Backup criptografado', '*.enc'), ('Todos', '*.*')])
        if not path:
            return
        password_result = dialogs.ask_simple(
            self, 'Senha do backup',
            ['password'],
            {'password': ''},
            labels={'password': 'Senha'},
            password=True)
        if not password_result or not password_result.get('password'):
            return
        # Confirm overwrite
        if not dialogs.confirm(self, 'Restaurar backup',
                               'Isso substituirá TODOS os dados atuais '
                               '(identidades, contatos, mensagens). Continuar?'):
            return
        try:
            # Import to temp file first
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as tmp:
                temp_path = tmp.name
            import_encrypted_backup(path, temp_path, password_result['password'])
            # Replace current DB
            self.client.stop()
            import shutil
            shutil.copy2(temp_path, self.client.db.path)
            os.unlink(temp_path)
            # Restart client
            self.client.start()
            self._refresh_identity_menu()
            self._refresh_conversations()
            dialogs.info(self, 'Backup restaurado',
                         'Dados restaurados com sucesso.')
        except Exception as exc:
            dialogs.warn(self, 'Erro ao restaurar', repr(exc))

    def _encrypt_database(self):
        """Enable encryption on current database."""
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
        if not dialogs.confirm(self, 'Criptografar banco',
                               'O banco de dados será criptografado. '
                               'Você precisará da senha a cada inicialização. '
                               'Guarde a senha! Sem ela, os dados são perdidos permanentemente.'):
            return
        try:
            # This is a simplified implementation
            dialogs.info(self, 'Criptografia',
                         'Recurso em desenvolvimento. '
                         'Use "Backup criptografado" para proteger seus dados por enquanto.')
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

    def _refresh_log(self, window, text, force=False):
        try:
            try:
                alive = bool(window.winfo_exists())
            except Exception:
                return
            if not alive:
                return
            if getattr(self, '_closed', False):
                return
            if not force:
                try:
                    mapped = bool(window.winfo_ismapped())
                except Exception:
                    mapped = True
                if not mapped:
                    # Item 7: janela oculta → pula o trabalho, reagenda longo.
                    try:
                        window._refresh_after = window.after(
                            5000, lambda: self._refresh_log(window, text))
                    except Exception:
                        pass
                    return
            try:
                lines = self.client.recent_logs(200)
            except Exception as exc:
                lines = ['(erro ao ler log: %s)' % exc]
            try:
                text.config(state='normal')
                text.delete('1.0', 'end')
                text.insert('1.0', '\n'.join(lines) or '(sem eventos ainda)')
                text.config(state='disabled')
                text.see('end')
            except Exception:
                return
            try:
                window._refresh_after = window.after(
                    5000, lambda: self._refresh_log(window, text))
            except Exception:
                pass
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
            try:
                alive = bool(window.winfo_exists())
            except Exception:
                return
            if not alive:
                return
            if getattr(self, '_closed', False):
                return
            if not force:
                try:
                    mapped = bool(window.winfo_ismapped())
                except Exception:
                    mapped = True
                if not mapped:
                    # Item 7: janela oculta → pula o trabalho, reagenda longo.
                    try:
                        window._refresh_after = window.after(
                            5000, lambda: self._refresh_diagnostics(
                                window, text))
                    except Exception:
                        pass
                    return
            try:
                report = _diagnostics_report(self.client.net.snapshot())
            except Exception as exc:
                report = '(erro ao gerar diagnóstico: %s)' % exc
            try:
                text.config(state='normal')
                text.delete('1.0', 'end')
                text.insert('1.0', report)
                text.config(state='disabled')
            except Exception:
                return
            try:
                window._refresh_after = window.after(
                    5000, lambda: self._refresh_diagnostics(window, text))
            except Exception:
                pass
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
            '• Os objetos serão baixados novamente dos pares.' % total)
        if not ok:
            return
        removed = self.client.net.wipe_objects()
        dialogs.info(self, 'Objetos', '%d objetos apagados.' % removed)

    def _copy_diagnostics(self, text):
        self.clipboard_clear()
        self.clipboard_append(text.get('1.0', 'end').strip())
        dialogs.info(self, 'Diagnóstico', 'Relatório copiado.')

    def _network_settings(self):
        db = self.client.db
        result = dialogs.ask_simple(
            self, 'Configurações de rede',
            ['connect_timeout', 'recv_timeout', 'max_connections',
             'maintenance_interval'],
            {'connect_timeout': str(db.get_int('connect_timeout', 30)),
             'recv_timeout': str(db.get_int('recv_timeout', 60)),
             'max_connections': str(db.get_int('max_connections', 8)),
             'maintenance_interval': str(
                 db.get_int('maintenance_interval', 5))})
        if not result:
            return
        try:
            connect_timeout = max(
                5, min(300, int(result.get('connect_timeout') or 30)))
            recv_timeout = max(
                10, min(600, int(result.get('recv_timeout') or 60)))
            max_connections = max(
                1, min(50, int(result.get('max_connections') or 8)))
            interval = max(
                2, min(120, int(result.get('maintenance_interval') or 5)))
        except ValueError:
            dialogs.warn(self, 'Configurações',
                         'Use apenas números inteiros.')
            return
        db.set_setting('connect_timeout', connect_timeout)
        db.set_setting('recv_timeout', recv_timeout)
        db.set_setting('max_connections', max_connections)
        db.set_setting('maintenance_interval', interval)
        dialogs.info(
            self, 'Configurações',
            'Aplicadas: timeout de conexão %ds, timeout de leitura %ds, '
            'máximo %d conexões, manutenção a cada %ds.\n'
            'Tempos valem para novas conexões; o intervalo, no próximo ciclo.'
            % (connect_timeout, recv_timeout, max_connections, interval))

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
        self.client.net.stop()
        self.client.net.running = False
        self.client.net.start(self.client._participating_streams())
        dialogs.info(self, 'Proxy atualizado',
                     'Usando %s. Reconectando...' % profile.describe())

    def _show_pows(self):
        try:
            total = self.client.net.connection_count
            established = self.client.net.established_count
        except Exception:
            total = established = 0
        dialogs.info(self, 'Rede',
                     'Conexões: %d estabelecidas de %d\nPOW em andamento: %d'
                     % (established, total, len(self.client._pow_stops)))

    def _auto_update_check(self):
        try:
            from .. import update as updater
            result = updater.check_for_updates()
        except Exception:
            return
        if result.get('status') == 'update-available':
            self.client.ui_queue.put(
                ('update-available', result.get('behind', 0)))

    def _check_updates_manual(self):
        def worker():
            try:
                from .. import update as updater
                result = updater.check_for_updates()
            except Exception as exc:
                result = {'status': 'error', 'error': repr(exc)}
            self.client.ui_queue.put(('update-check-result', result))
        threading.Thread(target=worker, daemon=True,
                         name='update-check-manual').start()

    def _show_update_check(self, result):
        status = result.get('status')
        if status == 'update-available':
            self._offer_update(result.get('behind', 0))
        elif status == 'up-to-date':
            dialogs.info(self, 'Atualização',
                         'Já está na versão mais nova.')
        elif status == 'no-repo':
            dialogs.warn(self, 'Atualização',
                         'Cópia sem git: atualização automática indisponível.')
        elif status == 'diverged':
            dialogs.warn(self, 'Atualização',
                         'Histórico local divergiu do remoto; atualize à mão '
                         'com git pull.')
        elif status == 'no-upstream':
            dialogs.warn(self, 'Atualização',
                         'Sem upstream configurado no git.')
        elif status == 'fetch-failed':
            dialogs.warn(self, 'Atualização',
                         'Falha de rede ao buscar a atualização.')
        else:
            detail = result.get('error') or result.get('status')
            text = 'Não foi possível verificar.'
            if detail:
                text += ' %s' % detail
            dialogs.warn(self, 'Atualização', text)

    def _offer_update(self, behind):
        try:
            count = int(behind)
        except (TypeError, ValueError):
            count = 0
        ok = dialogs.confirm(
            self, 'Atualização disponível',
            'Há atualização disponível (%d commit(s) novo(s)).\n'
            'Atualizar e reiniciar agora?' % count)
        if ok:
            self._flash_status('Baixando atualização…')
            threading.Thread(target=self._do_update, daemon=True,
                             name='update-apply').start()

    def _do_update(self):
        try:
            from .. import update as updater
            ok, message = updater.perform_update()
        except Exception as exc:
            ok, message = False, repr(exc)
        self.client.ui_queue.put(('update-result', ok, message))

    def _restart_after_update(self):
        # Item 6: o after(800) pode disparar após o fechamento.
        if getattr(self, '_closed', False):
            return
        try:
            from .. import update as updater
            updater.restart_program()
        except Exception as exc:
            dialogs.warn(self, 'Atualização',
                         'Atualizado, mas reinicie à mão: %s' % exc)

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

    def _on_close(self):
        # Item 6: flag + cancela poll/tick/redraws/debounces/startup para
        # zerar os erros pós-destroy ("invalid command name ... destroyed").
        self._closed = True
        for attr in ('_startup_after', '_poll_after', '_tick_after',
                     '_redraw_after', '_conv_hover_after', '_conv_draw_after',
                     '_refresh_after'):
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
        try:
            self.client.stop()
        except Exception:
            pass
        try:
            self.destroy()
        except Exception:
            pass


def main(data_dir):
    app = App(data_dir)
    app.mainloop()
