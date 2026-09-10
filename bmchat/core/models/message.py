"""Model Message com State Pattern.

Encapsula dados da mensagem e delega comportamento ao estado atual.
"""
from typing import Any

from .states import MessageState, get_state_class


class Message:
    """Modelo de mensagem com State Pattern.

    Args:
        row: dict vindo do Database (messages)
        client: Client para delegar ações (send/retry)
    """

    def __init__(self, row: dict[str, Any], client=None):
        self._row = dict(row)
        self.client = client
        self.id: int | None = row.get('id')
        self.from_address: str | None = row.get('from_address')
        self.to_address: str | None = row.get('to_address')
        self.subject: str = row.get('subject') or ''
        self.body: str = row.get('body') or ''
        self.encoding: int = row.get('encoding') or 1
        self.timestamp: int = row.get('timestamp') or 0
        self.direction: str = row.get('direction') or 'out'
        self.status: str = row.get('status') or 'pending'
        self.expires: int | None = row.get('expires')
        self.ttl: int | None = row.get('ttl')
        # Instancia estado correspondente
        self._state: MessageState = get_state_class(self.status)(self)

    @property
    def state(self) -> MessageState:
        return self._state

    @property
    def state_name(self) -> str:
        return self._state.name

    def transition_to(self, new_status: str, persist: bool = False) -> bool:
        """Transita para novo estado se permitido (State Pattern).

        Valida transição via ``can_transition_to``; se inválida, não
        altera estado e retorna False (evita corrupção). Estados de
        extensão ``cancelled``/``expired`` podem ser forçados mesmo
        fora do fluxo normal.

        Args:
            new_status: nome do novo estado
            persist: se True, persiste no DB via client.message_repo

        Retorna True se transitou, False se bloqueado.
        """
        # Normaliza: permite transição para si mesmo (idempotente)
        if new_status == self.status:
            return True
        cls = get_state_class(new_status)
        # Verifica permissão; novos estados podem ser forçados
        allowed = self._state.can_transition_to(new_status) or new_status in ('cancelled', 'expired')
        if not allowed:
            # Transição inválida: não altera (previne corrupção)
            return False
        try:
            self._state.on_exit()
        except Exception:
            pass
        new_state = cls(self)
        self._state = new_state
        self.status = new_status
        self._row['status'] = new_status
        try:
            new_state.on_enter()
        except Exception:
            pass
        if persist and self.client is not None and self.id is not None:
            try:
                # Persiste via repositório se disponível, senão via db direto
                repo = getattr(self.client, 'message_repo', None)
                if repo is not None:
                    repo.set_status(self.id, new_status)
                else:
                    self.client.db.set_message_status(self.id, new_status)
            except Exception:
                pass
        return True

    # -- delegação ao State --

    def send(self):
        return self._state.send()

    def check_status(self) -> str:
        return self._state.check_status()

    def get_display_icon(self) -> str:
        return self._state.get_display_icon()

    # -- helpers --

    def is_outgoing(self) -> bool:
        return self.direction == 'out'

    def is_incoming(self) -> bool:
        return self.direction == 'in'

    def is_pending(self) -> bool:
        return self.status in ('pending', 'awaiting-pubkey', 'sending')

    def is_delivered(self) -> bool:
        return self.status in ('delivered', 'ackreceived', 'received', 'read')

    def is_failed(self) -> bool:
        return self.status in ('failed', 'ack-failed')

    def to_dict(self) -> dict:
        return dict(self._row)

    def __repr__(self) -> str:
        return '<Message id=%s status=%s state=%s>' % (self.id, self.status, self.state_name)

    # Compat: permite acesso como dict (row['status'])
    def __getitem__(self, key):
        return self._row[key]

    def get(self, key, default=None):
        return self._row.get(key, default)
