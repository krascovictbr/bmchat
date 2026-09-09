"""ContactRepository — Repository Pattern para contatos."""
from .base import BaseRepository


class ContactRepository(BaseRepository):
    """Encapsula acesso a contatos."""

    def add(self, address: str, label: str, stream: int = 1):
        return self.db.add_contact(address, label, stream)

    def all(self):
        return self.db.all_contacts()

    def get(self, address: str):
        return self.db.get_contact(address)

    def remove(self, address: str):
        return self.db.remove_contact(address)

    def exists(self, address: str) -> bool:
        return self.get(address) is not None
