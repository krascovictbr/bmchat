"""gui.commands — Command Pattern.

Exposição pública dos comandos da interface.
"""

from .base import Command, CommandHistory
from .send_message import SendMessageCommand
from .delete_contact import DeleteContactCommand
from .backup_keys import BackupKeysCommand

__all__ = [
    "Command",
    "CommandHistory",
    "SendMessageCommand",
    "DeleteContactCommand",
    "BackupKeysCommand",
]
