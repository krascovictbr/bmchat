"""State Pattern — estados de mensagem.

Cada estado encapsula comportamento específico (ícone, transições,
ações). Facilita adicionar novos estados (Cancelled, Expired) sem
alterar lógica condicional espalhada.
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .message import Message


class MessageState(ABC):
    """Interface State para mensagens."""

    name: str = "unknown"
    display_icon: str = "❓"

    def __init__(self, message: "Message"):
        self.message = message

    @abstractmethod
    def send(self) -> tuple[str, str | None]:
        """Tenta enviar / reenviar. Retorna (status, error)."""
        raise NotImplementedError

    def check_status(self) -> str:
        """Retorna status atual (nome do estado)."""
        return self.name

    def get_display_icon(self) -> str:
        """Ícone para UI (relógio, checks, etc.)."""
        return self.display_icon

    def can_transition_to(self, target: str) -> bool:
        """Verifica se transição para target é válida."""
        return target in self.allowed_transitions()

    def allowed_transitions(self) -> set[str]:
        return set()

    def on_enter(self) -> None:
        """Hook chamado ao entrar no estado (opcional)."""
        pass

    def on_exit(self) -> None:
        """Hook chamado ao sair do estado (opcional)."""
        pass


class PendingState(MessageState):
    """Aguardando pubkey ou PoW em andamento."""

    name = "pending"
    display_icon = "🕐"  # relógio — ainda calculando / aguardando chave

    def send(self):
        # Já está pendente; tenta reenviar via client
        try:
            return self.message.client.resend_message(self.message.id)
        except Exception as exc:
            return "error", str(exc)

    def allowed_transitions(self):
        return {"published", "failed", "pending", "awaiting-pubkey", "sending", "sent", "ack-failed"}

    def get_display_icon(self):
        return "🕐"


class AwaitingPubkeyState(PendingState):
    name = "awaiting-pubkey"
    display_icon = "🕐"


class SendingState(PendingState):
    name = "sending"
    display_icon = "⏳"


class PublishedState(MessageState):
    """Publicado na rede (sent), aguardando ACK."""

    name = "published"
    # No BT spec, 'sent' é cinza
    display_icon = "✓✓"

    def send(self):
        return "already-sent", "mensagem já publicada"

    def allowed_transitions(self):
        return {"delivered", "failed", "ackreceived", "ack-failed", "read"}

    def get_display_icon(self):
        # Cinza — publicado
        return "✓✓"


class SentState(PublishedState):
    name = "sent"


class DeliveredState(MessageState):
    """Entregue — ACK recebido ou mensagem lida."""

    name = "delivered"
    display_icon = "✓✓✓"  # azul na UI (cor via tema)

    def send(self):
        return "already-delivered", "mensagem já entregue"

    def allowed_transitions(self):
        return {"read", "received", "ackreceived"}

    def get_display_icon(self):
        # Azul — entregue
        return "✓✓"


class AckReceivedState(DeliveredState):
    name = "ackreceived"


class ReceivedState(DeliveredState):
    name = "received"


class ReadState(DeliveredState):
    name = "read"


class FailedState(MessageState):
    """Falha — ack-failed ou erro de envio."""

    name = "failed"
    display_icon = "❌"

    def send(self):
        # Permite retry
        try:
            return self.message.client.resend_message(self.message.id)
        except Exception as exc:
            return "error", str(exc)

    def allowed_transitions(self):
        return {"pending", "awaiting-pubkey", "sending", "failed", "ack-failed"}

    def get_display_icon(self):
        return "❌"


class AckFailedState(FailedState):
    name = "ack-failed"


class CancelledState(MessageState):
    """Extensão futura: mensagem cancelada pelo usuário."""

    name = "cancelled"
    display_icon = "🚫"

    def send(self):
        return "cancelled", "mensagem cancelada não pode ser enviada"

    def allowed_transitions(self):
        return set()


class ExpiredState(MessageState):
    """Extensão futura: mensagem expirada (TTL)."""

    name = "expired"
    display_icon = "⌛"

    def send(self):
        return "expired", "mensagem expirada (TTL)"

    def allowed_transitions(self):
        return set()


# Registro de todos os estados
_STATE_MAP = {
    "pending": PendingState,
    "awaiting-pubkey": AwaitingPubkeyState,
    "sending": SendingState,
    "published": PublishedState,
    "sent": SentState,
    "delivered": DeliveredState,
    "ackreceived": AckReceivedState,
    "received": ReceivedState,
    "read": ReadState,
    "failed": FailedState,
    "ack-failed": AckFailedState,
    "cancelled": CancelledState,
    "expired": ExpiredState,
}


def get_state_class(name: str):
    return _STATE_MAP.get(name, PendingState)


def all_states():
    return dict(_STATE_MAP)
