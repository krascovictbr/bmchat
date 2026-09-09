"""DeleteContactCommand — Command Pattern para remoção de contato."""
from .base import Command


class DeleteContactCommand(Command):
    """Encapsula remoção de contato + conversa associada.

    Permite undo recriando o contato (mensagens perdidas não voltam,
    mas o contato volta — limitação documentada).
    """

    def __init__(self, client, address: str):
        super().__init__(client)
        self.address = address
        self._backup_contact = None
        self._backup_messages = None

    def can_execute(self):
        if not self.address:
            return False, 'endereço vazio'
        try:
            row = self.client.db.get_contact(self.address)
            if row is None:
                return False, 'contato não encontrado'
        except Exception as exc:
            return False, str(exc)
        return True, None

    def execute(self):
        try:
            # Backup para undo (só contato; mensagens não são restauradas,
            # então evita carregar conversa inteira — seguro para self-chat)
            self._backup_contact = self.client.db.get_contact(self.address)
            self._backup_messages = []
        except Exception:
            pass
        try:
            self.client.remove_contact(self.address)
            self._executed = True
            return 'success', None
        except Exception as exc:
            self._error = str(exc)
            return 'error', str(exc)

    def undo(self):
        if not self._backup_contact:
            return 'unsupported', 'sem backup para restaurar'
        try:
            addr = self._backup_contact['address']
            label = self._backup_contact.get('label') or addr
            stream = self._backup_contact.get('stream') or 1
            self.client.db.add_contact(addr, label, stream=stream)
            # Mensagens não são restauradas automaticamente (decisão de design);
            # poderia re-inserir se necessário, mas perderiam IDs.
            self._executed = False
            return 'success', addr
        except Exception as exc:
            return 'error', str(exc)
