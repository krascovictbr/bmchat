"""SendMessageCommand — Command Pattern para envio de mensagem."""
from .base import Command


class SendMessageCommand(Command):
    """Encapsula o envio de mensagem DM.

    Args:
        client: instância Client
        from_address: identidade remetente (BM-...)
        to_address: contato destino (BM-...)
        body: texto da mensagem
        subject: assunto opcional (será prefixado no wire)
        encoding: encoding Bitmessage (padrão TRIVIAL)
    """

    def __init__(self, client, from_address: str, to_address: str, body: str,
                 subject: str = '', encoding: int | None = None):
        super().__init__(client)
        self.from_address = from_address
        self.to_address = to_address
        self.body = body or ''
        self.subject = subject or ''
        self.encoding = encoding
        self._message_id: int | None = None

    def can_execute(self):
        if not self.from_address or not self.to_address:
            return False, 'identidade ou destino ausente'
        if self.from_address not in getattr(self.client, 'identities', {}):
            return False, 'identidade de origem não encontrada'
        # Validação de tamanho reutiliza lógica do Client
        try:
            body = self.body or ''
            wire = ('Subject: %s\n\n%s' % (self.subject, body)) if self.subject.strip() else body
            if self.client._wire_too_large(wire):
                return False, 'mensagem grande demais para um objeto'
        except Exception:
            pass
        return True, None

    def execute(self) -> tuple[str, str | None]:
        from ...protocol.const import BITMESSAGE_ENCODING_TRIVIAL
        enc = self.encoding if self.encoding is not None else BITMESSAGE_ENCODING_TRIVIAL
        status, error = self.client.send_message(
            self.from_address, self.to_address, self.subject, self.body, enc)
        self._executed = status == 'success'
        self._result = (status, error)
        if status == 'success':
            # Captura message_id de forma mais precisa (filtra por body para evitar
            # capturar mensagem errada quando há várias com mesmo from/to).
            # Usa repositório quando disponível para abstração.
            try:
                repo = getattr(self.client, 'message_repo', None)
                if repo is not None:
                    # Tenta via repositório; fallback para query direta
                    rows = repo.query(
                        'SELECT id FROM messages WHERE from_address=? AND to_address=? '
                        'AND body=? ORDER BY id DESC LIMIT 1',
                        (self.from_address, self.to_address, self.body or ''))
                else:
                    rows = self.client.db.query(
                        'SELECT id FROM messages WHERE from_address=? AND to_address=? '
                        'AND body=? ORDER BY id DESC LIMIT 1',
                        (self.from_address, self.to_address, self.body or ''))
                if rows:
                    self._message_id = rows[0]['id']
                else:
                    # Fallback legado (sem body) para compatibilidade com testes antigos
                    rows = self.client.db.query(
                        'SELECT id FROM messages WHERE from_address=? AND to_address=? '
                        'ORDER BY id DESC LIMIT 1',
                        (self.from_address, self.to_address))
                    if rows:
                        self._message_id = rows[0]['id']
            except Exception:
                pass
        else:
            self._error = error
        return status, error

    def undo(self):
        """Desfaz envio apagando a mensagem recém-criada (se ainda não enviada)."""
        if self._message_id is None:
            return 'unsupported', 'mensagem não rastreável para undo'
        try:
            # Só desfaz se ainda está em estado pendente (não foi para sent)
            row = self.client.db.get_message(self._message_id)
            if row and row['status'] in ('awaiting-pubkey', 'sending'):
                self.client.db.delete_message(self._message_id)
                return 'success', None
            return 'unsupported', 'mensagem já enviada (status=%s)' % (row['status'] if row else 'desconhecido')
        except Exception as exc:
            return 'error', str(exc)
