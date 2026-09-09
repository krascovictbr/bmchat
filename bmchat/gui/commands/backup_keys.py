"""BackupKeysCommand — Command Pattern para backup de chaves."""
from .base import Command


class BackupKeysCommand(Command):
    """Encapsula exportação de chaves (WIF / keys.dat).

    Args:
        client: Client
        address: endereço específico ou None para todas as identidades
        format: 'wif' ou 'keys_dat'
    """

    def __init__(self, client, address: str | None = None, format: str = 'keys_dat'):
        super().__init__(client)
        self.address = address
        self.format = format

    def can_execute(self):
        if self.format not in ('wif', 'keys_dat'):
            return False, 'formato inválido: %s' % self.format
        if self.format == 'wif' and self.address:
            if self.client.export_identity(self.address) is None:
                return False, 'identidade não encontrada para backup WIF'
        return True, None

    def execute(self):
        try:
            if self.format == 'wif' and self.address:
                data = self.client.export_identity(self.address)
                if data is None:
                    self._error = 'identidade não encontrada'
                    return 'error', self._error
                self._result = data
                self._executed = True
                return 'success', data
            else:
                blob = self.client.export_keys_dat()
                self._result = blob
                self._executed = True
                return 'success', blob
        except Exception as exc:
            self._error = str(exc)
            return 'error', str(exc)

    def undo(self):
        # Backup é operação de leitura; não há estado a desfazer
        return 'unsupported', 'backup não requer undo'
