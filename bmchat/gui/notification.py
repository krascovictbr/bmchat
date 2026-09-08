"""Cross-platform notification system.

Segurança (C4): título/mensagem vêm de mensagens recebidas (texto
não-confiável, ex. preview em ``app.py``). Nunca interpolar esse texto
em shell/script de outro interpretador:

- Windows: usa ``powershell -EncodedCommand`` (UTF-16LE + Base64), sem
  interpolação — sequências como ``$(...)`` chegam como dado morto.
- macOS: passa título/mensagem como ``argv`` separados e usa
  ``quoted form of`` no AppleScript (``\\"`` sozinho não escapa).
- Linux notify-send/dbus: já usam argv (sem shell); mantidos.
"""

import base64
import os
import platform
import subprocess
import threading
from typing import Optional


class NotificationManager:
    """Send desktop notifications."""

    def __init__(self):
        self.system = platform.system().lower()
        self._enabled = True
        self._backend = self._detect_backend()

    def _detect_backend(self) -> str:
        """Detect available notification backend."""
        if self.system == 'linux':
            # Check for notify-send
            if self._check_command(['notify-send', '--version']):
                return 'notify-send'
            # Check for dbus
            if self._check_dbus():
                return 'dbus'
        elif self.system == 'darwin':
            return 'osascript'
        elif self.system == 'windows':
            return 'powershell'
        return 'none'

    def _check_command(self, cmd: list) -> bool:
        """Check if command exists."""
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=2)
            return True
        except Exception:
            return False

    def _check_dbus(self) -> bool:
        """Check if dbus is available."""
        try:
            import dbus  # noqa: F401 -- availability probe
            return True
        except ImportError:
            return False

    def notify(self, title: str, message: str, urgency: str = 'normal',
               timeout: int = 5000, icon: Optional[str] = None):
        """Send a desktop notification."""
        if not self._enabled:
            return

        # Run in background to avoid blocking
        threading.Thread(target=self._send_notification,
                         args=(title, message, urgency, timeout, icon),
                         daemon=True).start()

    def _send_notification(self, title: str, message: str, urgency: str,
                           timeout: int, icon: Optional[str]):
        """Send notification using detected backend."""
        try:
            if self._backend == 'notify-send':
                self._notify_send(title, message, urgency, timeout, icon)
            elif self._backend == 'osascript':
                self._notify_osascript(title, message)
            elif self._backend == 'powershell':
                self._notify_powershell(title, message)
            elif self._backend == 'dbus':
                self._notify_dbus(title, message, urgency, timeout)
        except Exception:
            pass  # Silently fail

    def _notify_send(self, title: str, message: str, urgency: str,
                     timeout: int, icon: Optional[str]):
        """Send notification using notify-send (argv, sem shell)."""
        cmd = ['notify-send', f'--urgency={urgency}', f'--expire-time={timeout}']
        if icon and os.path.exists(icon):
            cmd.extend(['--icon', icon])
        cmd.append(title)
        cmd.append(message)
        subprocess.run(cmd, timeout=5)

    @staticmethod
    def _osascript_args(title: str, message: str) -> list:
        """Build osascript argv sem interpolar texto não-confiável."""
        # Título/mensagem via argv ($1/$2) + 'quoted form of' evita
        # breakout com aspas/barras (\" não escapa em AppleScript).
        script = ('on run argv\n'
                  'display notification (item 2 of argv) '
                  'with title (item 1 of argv)\n'
                  'end run')
        return ['osascript', '-e', script, str(title), str(message)]

    def _notify_osascript(self, title: str, message: str):
        """Send notification using osascript (macOS)."""
        subprocess.run(self._osascript_args(title, message), timeout=5)

    @staticmethod
    def build_powershell_encoded(title: str, message: str) -> list:
        """Build powershell argv com -EncodedCommand (sem interpolação)."""
        # Script fixo; título/mensagem entram como literais .NET via
        # Base64(UTF-16LE) — nunca concatenados no script.
        script = (
            "$t=[System.Text.Encoding]::UTF8.GetString("
            "[System.Convert]::FromBase64String($env:BMCHAT_NT));"
            "$m=[System.Text.Encoding]::UTF8.GetString("
            "[System.Convert]::FromBase64String($env:BMCHAT_NM));"
            "Add-Type -AssemblyName System.Windows.Forms;"
            "$n=New-Object System.Windows.Forms.NotifyIcon;"
            "$n.Icon=[System.Drawing.SystemIcons]::Information;"
            "$n.Visible=$true;"
            "$n.ShowBalloonTip(5000,$t,$m,"
            "[System.Windows.Forms.ToolTipIcon]::Info);"
            "Start-Sleep -Seconds 6;$n.Dispose()")
        encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
        return ['powershell', '-NoProfile', '-NonInteractive',
                '-EncodedCommand', encoded]

    def _notify_powershell(self, title: str, message: str):
        """Send notification using PowerShell (Windows, sem RCE)."""
        import os as _os
        cmd = self.build_powershell_encoded(str(title), str(message))
        env = dict(_os.environ)
        env['BMCHAT_NT'] = base64.b64encode(
            str(title).encode('utf-8')).decode('ascii')
        env['BMCHAT_NM'] = base64.b64encode(
            str(message).encode('utf-8')).decode('ascii')
        subprocess.run(cmd, timeout=10, env=env)

    def _notify_dbus(self, title: str, message: str, urgency: str, timeout: int):
        """Send notification using DBus (Linux fallback)."""
        try:
            import dbus
            bus = dbus.SessionBus()
            obj = bus.get_object('org.freedesktop.Notifications',
                                 '/org/freedesktop/Notifications')
            interface = dbus.Interface(obj, 'org.freedesktop.Notifications')
            interface.Notify(
                'bmchat', 0, '', title, message, [], {},
                timeout)
        except Exception:
            pass

    def set_enabled(self, enabled: bool):
        """Enable/disable notifications."""
        self._enabled = enabled

    def is_available(self) -> bool:
        """Check if notifications are available."""
        return self._backend != 'none'


# Global instance
_notification_manager: Optional[NotificationManager] = None


def get_notification_manager() -> NotificationManager:
    """Get global notification manager instance."""
    global _notification_manager
    if _notification_manager is None:
        _notification_manager = NotificationManager()
    return _notification_manager


def notify(title: str, message: str, urgency: str = 'normal',
           timeout: int = 5000, icon: Optional[str] = None):
    """Convenience function to send notification."""
    get_notification_manager().notify(title, message, urgency, timeout, icon)
