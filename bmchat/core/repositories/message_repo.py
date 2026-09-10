"""MessageRepository — Repository Pattern para mensagens."""

from .base import BaseRepository


class MessageRepository(BaseRepository):
    """Encapsula acesso a dados de mensagens.

    Substitui chamadas SQL diretas espalhadas no Client,
    centralizando CRUD e consultas específicas.
    """

    def add(
        self,
        obj_hash,
        from_address,
        to_address,
        subject,
        body,
        encoding,
        timestamp,
        direction,
        status,
        target_stream=None,
        ttl=None,
        expires=None,
    ) -> int:
        return self.db.add_message(
            obj_hash,
            from_address,
            to_address,
            subject,
            body,
            encoding,
            timestamp,
            direction,
            status,
            target_stream,
            ttl,
            expires,
        )

    def exists(self, obj_hash: bytes) -> bool:
        return self.db.message_exists(obj_hash)

    def get(self, message_id: int):
        return self.db.get_message(message_id)

    def get_by_hash(self, obj_hash: bytes):
        rows = self.query("SELECT * FROM messages WHERE obj_hash=?", (obj_hash,))
        return rows[0] if rows else None

    def for_address(self, address: str):
        return self.db.messages_for(address)

    def for_conversation(self, address: str, limit=None):
        return self.db.messages_for_conversation(address, limit=limit)

    def for_contact(self, contact_address: str, identity_address: str):
        return self.db.messages_for_contact(contact_address, identity_address)

    def for_dm(self, contact_address: str, identity_address: str, limit=None):
        """Conversa DM isolada (corrige vazamento self-chat/SUPORTE)."""
        try:
            return self.db.messages_for_dm(contact_address, identity_address, limit=limit)
        except AttributeError:
            # Fallback para DB antigo sem o método
            return self.db.messages_for_contact(contact_address, identity_address)

    def count_for_dm(self, contact_address: str, identity_address: str):
        try:
            return self.db.count_for_dm(contact_address, identity_address)
        except AttributeError:
            return len(self.for_dm(contact_address, identity_address))

    def last_for_dm(self, contact_address: str, identity_address: str):
        try:
            return self.db.last_message_for_dm(contact_address, identity_address)
        except AttributeError:
            rows = self.for_dm(contact_address, identity_address)
            return rows[-1] if rows else None

    def mark_dm_read(self, contact_address: str, identity_address: str):
        try:
            return self.db.mark_dm_read(contact_address, identity_address)
        except AttributeError:
            return self.db.mark_conversation_read(contact_address, identity_address)

    def delete_dm(self, contact_address: str, identity_address: str):
        try:
            return self.db.delete_dm_conversation(contact_address, identity_address)
        except AttributeError:
            return self.db.delete_conversation(contact_address)

    def set_status(self, message_id: int, status: str):
        return self.db.set_message_status(message_id, status)

    def set_expiry(self, message_id: int, expires: int):
        return self.db.set_message_expiry(message_id, expires)

    def delete(self, message_id: int):
        return self.db.delete_message(message_id)

    def delete_conversation(self, address: str):
        return self.db.delete_conversation(address)

    def unread_count(self) -> int:
        return self.db.unread_count()

    def mark_conversation_read(self, contact_address: str, identity_address: str):
        return self.db.mark_conversation_read(contact_address, identity_address)

    def recent(self, limit=200):
        return self.db.recent_messages(limit)

    # Consultas específicas antes espalhadas no Client

    def awaiting_pubkey_addresses(self, limit=20):
        rows = self.query(
            "SELECT DISTINCT to_address FROM messages WHERE direction='out' AND status='awaiting-pubkey' LIMIT ?",
            (limit,),
        )
        return [r["to_address"] for r in rows if r["to_address"]]

    def stuck_sending_before(self, cutoff: int):
        """Mensagens 'sending' presas há >10min."""
        return self.query(
            "SELECT id FROM messages WHERE direction='out' AND status='sending' AND timestamp < ?", (cutoff,)
        )

    def ack_failed(self, limit=5):
        return self.query(
            "SELECT id, to_address FROM messages WHERE direction='out' AND status='ack-failed' LIMIT ?", (limit,)
        )

    def update_stuck_to_awaiting(self, cutoff: int):
        return self.execute(
            "UPDATE messages SET status='awaiting-pubkey' WHERE direction='out' AND status='sending' AND timestamp < ?",
            (cutoff,),
        )

    def status_of(self, message_id: int):
        rows = self.query("SELECT status FROM messages WHERE id=?", (message_id,))
        return rows[0]["status"] if rows else None

    def ttl_of(self, message_id: int):
        rows = self.query("SELECT ttl FROM messages WHERE id=?", (message_id,))
        return rows[0].get("ttl") if rows else None

    def subject_of(self, message_id: int):
        rows = self.query("SELECT subject FROM messages WHERE id=?", (message_id,))
        return (rows[0]["subject"] if rows else "") or ""

    def all_awaiting_for(self, to_address: str, limit=5):
        return self.query(
            "SELECT * FROM messages WHERE to_address=? AND status='awaiting-pubkey' LIMIT ?", (to_address, limit)
        )

    def count_pending(self):
        rows = self.query("SELECT COUNT(*) as n FROM messages WHERE direction='out' AND status='awaiting-pubkey'")
        return rows[0]["n"] if rows else 0
