"""core.repositories — Repository Pattern.

Expõe repositórios que abstraem a camada de dados.
"""

from .base import BaseRepository
from .message_repo import MessageRepository
from .contact_repo import ContactRepository
from .pubkey_repo import PubkeyRepository

__all__ = ["BaseRepository", "MessageRepository", "ContactRepository", "PubkeyRepository"]
