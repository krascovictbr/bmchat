"""Tipos de eventos do sistema — Observer Pattern.

Centraliza nomes de eventos para evitar strings mágicas espalhadas.
Compatível com o legado ui_queue (tuplas) mas com nomes tipados.
"""

# Mensagens
NEW_MESSAGE = "new_message"  # ('message', from, to, body, expires)
BROADCAST_RECEIVED = "broadcast_received"  # ('broadcast', ...)
ACK_RECEIVED = "ack_received"  # ('ack', message_id)
MESSAGE_STATUS = "message_status"  # ('status', message_id, status)

# PoW
POW_STARTED = "pow_started"
POW_PROGRESS = "pow_progress"  # ('pow-progress', token, tried, rate)
POW_COMPLETED = "pow_completed"
POW_CANCELLED = "pow_cancelled"  # ('pow-cancelled', token)

# Conexão / rede
CONNECTION_CHANGE = "connection_change"
PEER_CONNECTED = "peer_connected"
PEER_DISCONNECTED = "peer_disconnected"
INVENTORY_UPDATE = "inventory_update"

# Contatos / identidades
CONTACT_ADDED = "contact_added"  # ('contact-added', ...)
CONTACT_REMOVED = "contact_removed"
IDENTITY_CREATED = "identity_created"
IDENTITY_UPDATED = "identity_updated"
IDENTITY_REMOVED = "identity_removed"
SUBSCRIBED = "subscribed"

# Sistema
LOGGED = "log"  # ('log', level, message)
BROADCAST_SENT = "broadcast_sent"

# Mapeamento legado -> novo (para ponte ui_queue -> EventEmitter)
LEGACY_MAP = {
    "message": NEW_MESSAGE,
    "broadcast": BROADCAST_RECEIVED,
    "ack": ACK_RECEIVED,
    "status": MESSAGE_STATUS,
    "pow-progress": POW_PROGRESS,
    "pow-cancelled": POW_CANCELLED,
    "contact-added": CONTACT_ADDED,
    "contact-removed": CONTACT_REMOVED,
    "identity-created": IDENTITY_CREATED,
    "identity-updated": IDENTITY_UPDATED,
    "identity-removed": IDENTITY_REMOVED,
    "subscribed": SUBSCRIBED,
    "log": LOGGED,
    "broadcast-sent": BROADCAST_SENT,
}

__all__ = [
    "NEW_MESSAGE",
    "BROADCAST_RECEIVED",
    "ACK_RECEIVED",
    "MESSAGE_STATUS",
    "POW_STARTED",
    "POW_PROGRESS",
    "POW_COMPLETED",
    "POW_CANCELLED",
    "CONNECTION_CHANGE",
    "PEER_CONNECTED",
    "PEER_DISCONNECTED",
    "INVENTORY_UPDATE",
    "CONTACT_ADDED",
    "CONTACT_REMOVED",
    "IDENTITY_CREATED",
    "IDENTITY_UPDATED",
    "IDENTITY_REMOVED",
    "SUBSCRIBED",
    "LOGGED",
    "BROADCAST_SENT",
    "LEGACY_MAP",
]
