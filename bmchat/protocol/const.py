from ..version import user_agent_version

MAGIC = 0xE9BEB4D9

NODE_NETWORK = 1
NODE_SSL = 2
NODE_DANDELION = 8

BITFIELD_DOESACK = 1

OBJECT_GETPUBKEY = 0
OBJECT_PUBKEY = 1
OBJECT_MSG = 2
OBJECT_BROADCAST = 3
OBJECT_ONIONPEER = 0x746f72
OBJECT_ADDR = 0x61646472
OBJECT_I2P = 0x493250

MAX_ADDR_COUNT = 1000
MAX_MESSAGE_SIZE = 1600100
MAX_OBJECT_PAYLOAD_SIZE = 2 ** 18
MAX_OBJECT_COUNT = 50000
MAX_TIME_OFFSET = 3600
MAX_OBJECT_LENGTH = 2 ** 18

# Teto único do corpo no wire (texto + marcador base64 de anexos).
# Mantém o objeto final (após ECIES/assinatura) abaixo de
# MAX_OBJECT_LENGTH com folga. Checado ANTES do PoW nos caminhos
# DM (send_message) e canal (broadcast/broadcast_chan) e na GUI.
MAX_WIRE_BODY_BYTES = 200_000

# Faixa válida de dificuldade anunciada em pubkey (evita PoW infinito).
PUBKEY_NTPB_MIN = 1000
PUBKEY_NTPB_MAX = 1000000
PUBKEY_EB_MIN = 1000
PUBKEY_EB_MAX = 1000000

DEFAULT_PORT = 8444
PROTOCOL_VERSION = 3

BITMESSAGE_ENCODING_IGNORE = 0
BITMESSAGE_ENCODING_TRIVIAL = 1
BITMESSAGE_ENCODING_SIMPLE = 2
BITMESSAGE_ENCODING_EXTENDED = 3

MSG_TTL = 4 * 24 * 3600
PUBKEY_TTL = 28 * 24 * 3600
GETPUBKEY_TTL = 4 * 24 * 3600

# TTL global das mensagens (setting `msg_ttl_seconds`): vale para todas as
# mensagens de todos os contatos/canais. A rede descarta objetos com `expires`
# além da janela de aceitação, por isso o máximo é 21 dias (dentro de
# +28d+3h) e o mínimo é 1 hora.
MSG_TTL_DEFAULT = 86400
MSG_TTL_MIN = 3600
MSG_TTL_MAX = 1814400

MSG_TTL_PRESETS = (
    (3600, '1 hora'),
    (86400, '1 dia'),
    (604800, '7 dias'),
    (1814400, '21 dias'),
)


def format_ttl_pt(seconds):
    """Rótulo curto PT-BR para uma duração em segundos (TTL/expiração)."""
    try:
        total = int(seconds)
    except (TypeError, ValueError):
        return '—'
    for value, label in MSG_TTL_PRESETS:
        if total == value:
            return label
    if total < 60:
        return '%d s' % max(0, total)
    minutes = total // 60
    if minutes < 60:
        return '1 min' if minutes == 1 else '%d min' % minutes
    hours = total // 3600
    if hours < 24:
        return '1 hora' if hours == 1 else '%d horas' % hours
    days = total // 86400
    return '1 dia' if days == 1 else '%d dias' % days


USER_AGENT = '/bmchat:%s/' % user_agent_version()
