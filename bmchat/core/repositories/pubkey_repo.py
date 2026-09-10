"""PubkeyRepository — Repository Pattern para chaves públicas."""
from .base import BaseRepository


class PubkeyRepository(BaseRepository):
    """Encapsula acesso a pubkeys."""

    def store(self, address: str, signing_public: bytes, encryption_public: bytes,
              noncetrials: int = 1000, extrabytes: int = 1000):
        return self.db.store_pubkey(address, signing_public, encryption_public,
                                    noncetrials, extrabytes)

    def get(self, address: str):
        return self.db.get_pubkey(address)

    def all(self):
        return self.db.all_pubkeys()

    def exists(self, address: str) -> bool:
        return self.get(address) is not None
