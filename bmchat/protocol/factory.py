"""Factory Pattern para objetos de protocolo Bitmessage.

Centraliza criação de objetos (getpubkey, pubkey, msg, broadcast)
com validação de parâmetros, desacoplando Client da construção
manual via `objects.*`. Facilita testes e garante invariantes.
"""
import time

from . import objects
from .const import (
    GETPUBKEY_TTL, PUBKEY_TTL, MSG_TTL_MIN, MSG_TTL_MAX,
    MAX_WIRE_BODY_BYTES,
)


class ProtocolObjectFactory:
    """Factory para criar objetos de protocolo.

    Valida parâmetros na criação e delega à camada `objects`.
    Pode ser instanciada ou usada via métodos estáticos.
    """

    @staticmethod
    def _validate_expires(expires: int) -> int:
        now = int(time.time())
        if not isinstance(expires, int) or expires <= now:
            raise ValueError('expires deve ser timestamp futuro')
        # TTL dentro da janela da rede (até 28d+3h); tolera 21d max local
        if expires - now > 30 * 24 * 3600:
            raise ValueError('expires muito distante no futuro')
        return expires

    @staticmethod
    def _validate_stream(stream: int) -> int:
        if not isinstance(stream, int) or stream < 1:
            raise ValueError('stream deve ser inteiro >=1')
        return stream

    @staticmethod
    def _validate_tag(tag: bytes) -> bytes:
        if not isinstance(tag, (bytes, bytearray)) or len(tag) != 32:
            raise ValueError('tag deve ter 32 bytes')
        return bytes(tag)

    @staticmethod
    def _validate_ripe(ripe: bytes) -> bytes:
        if not isinstance(ripe, (bytes, bytearray)) or len(ripe) != 20:
            raise ValueError('ripe deve ter 20 bytes')
        return bytes(ripe)

    # -- creators --

    def create_getpubkey(self, expires: int, stream: int, tag: bytes) -> bytes:
        """Cria objeto getpubkey não-assinado (sem nonce)."""
        expires = self._validate_expires(expires)
        stream = self._validate_stream(stream)
        tag = self._validate_tag(tag)
        return objects.build_getpubkey_unsigned(expires, stream, 4, tag)

    def create_pubkey(self, expires: int, stream: int, identity) -> bytes:
        """Cria objeto pubkey não-assinado (com payload cifrado)."""
        expires = self._validate_expires(expires)
        stream = self._validate_stream(stream)
        if identity is None or not hasattr(identity, 'signing_private'):
            raise ValueError('identity inválida para pubkey')
        return objects.build_pubkey_unsigned(expires, stream, identity)

    def create_msg(
        self,
        expires: int,
        stream: int,
        identity,
        recipient_encryption_public: bytes,
        recipient_ripe: bytes,
        message: bytes,
        encoding: int = 1,
        ack_packet: bytes = b'',
    ) -> bytes:
        """Cria objeto msg não-assinado (cifrado + assinado)."""
        expires = self._validate_expires(expires)
        stream = self._validate_stream(stream)
        recipient_ripe = self._validate_ripe(recipient_ripe)
        if not isinstance(message, (bytes, bytearray)):
            raise ValueError('message deve ser bytes')
        if len(message) > MAX_WIRE_BODY_BYTES:
            raise ValueError('message excede MAX_WIRE_BODY_BYTES (%d)' % MAX_WIRE_BODY_BYTES)
        if not isinstance(recipient_encryption_public, (bytes, bytearray)):
            raise ValueError('recipient_encryption_public inválida')
        if len(recipient_encryption_public) not in (65, 64):
            raise ValueError('recipient_encryption_public deve ter 64 ou 65 bytes')
        if encoding not in (0, 1, 2, 3):
            raise ValueError('encoding inválido')
        if identity is None:
            raise ValueError('identity ausente')
        return objects.build_msg_unsigned(
            expires, stream, identity, recipient_encryption_public,
            recipient_ripe, message, encoding, ack_packet)

    def create_broadcast(self, expires: int, stream: int, identity,
                         message: bytes, encoding: int = 1) -> bytes:
        """Cria objeto broadcast não-assinado."""
        expires = self._validate_expires(expires)
        stream = self._validate_stream(stream)
        if not isinstance(message, (bytes, bytearray)):
            raise ValueError('message deve ser bytes')
        if len(message) > MAX_WIRE_BODY_BYTES:
            raise ValueError('message excede MAX_WIRE_BODY_BYTES (%d)' % MAX_WIRE_BODY_BYTES)
        if identity is None:
            raise ValueError('identity ausente')
        if encoding not in (0, 1, 2, 3):
            raise ValueError('encoding inválido')
        return objects.build_broadcast_unsigned(expires, stream, identity, message, encoding)

    def create_ack(self, expires: int, watch_data: bytes, stream: int = 1) -> bytes:
        """Cria objeto de ACK interno (msg v1 com watch)."""
        expires = self._validate_expires(expires)
        stream = self._validate_stream(stream)
        if not isinstance(watch_data, (bytes, bytearray)) or len(watch_data) != 32:
            raise ValueError('watch_data deve ter 32 bytes')
        return objects.build_ack_unsigned(expires, watch_data, stream)

    # -- conveniências com TTL --

    def create_getpubkey_with_ttl(self, stream: int, tag: bytes, ttl: int = GETPUBKEY_TTL) -> bytes:
        expires = int(time.time()) + ttl
        return self.create_getpubkey(expires, stream, tag)

    def create_pubkey_with_ttl(self, stream: int, identity, ttl: int = PUBKEY_TTL) -> bytes:
        expires = int(time.time()) + ttl
        return self.create_pubkey(expires, stream, identity)

    def create_msg_with_ttl(self, stream: int, identity, recipient_encryption_public,
                            recipient_ripe: bytes, message: bytes, encoding=1,
                            ack_packet: bytes = b'', ttl: int | None = None) -> bytes:
        # Usa TTL padrão se não informado; clamp igual ao Client.get_msg_ttl
        if ttl is None:
            ttl = 86400
        try:
            ttl = int(ttl)
        except Exception:
            ttl = 86400
        ttl = max(MSG_TTL_MIN, min(MSG_TTL_MAX, ttl))
        # Valida tamanho no wire antes de PoW (evita queimar CPU)
        if isinstance(message, (bytes, bytearray)) and len(message) > MAX_WIRE_BODY_BYTES:
            raise ValueError('message excede MAX_WIRE_BODY_BYTES (%d)' % MAX_WIRE_BODY_BYTES)
        expires = int(time.time()) + ttl
        return self.create_msg(expires, stream, identity, recipient_encryption_public,
                               recipient_ripe, message, encoding, ack_packet)

    # -- parsing --

    @staticmethod
    def parse(raw: bytes):
        """Faz parse de objeto bruto, delegando a ParsedObject."""
        return objects.ParsedObject(raw)

    @staticmethod
    def complete(unsigned: bytes, nonce: int) -> bytes:
        """Completa objeto com nonce."""
        return objects.complete_object(unsigned, nonce)


# Instância padrão (singleton leve) para conveniência
default_factory = ProtocolObjectFactory()
