"""Cross-platform notification system."""

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
            # Check for win10toast or powershell
            try:
                import win10toast  # noqa: F401 -- availability probe
                return 'win10toast'
            except ImportError:
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
            elif self._backend == 'win10toast':
                self._notify_win10toast(title, message)
            elif self._backend == 'powershell':
                self._notify_powershell(title, message)
            elif self._backend == 'dbus':
                self._notify_dbus(title, message, urgency, timeout)
        except Exception:
            pass  # Silently fail

    def _notify_send(self, title: str, message: str, urgency: str,
                     timeout: int, icon: Optional[str]):
        """Send notification using notify-send."""
        cmd = ['notify-send', f'--urgency={urgency}', f'--expire-time={timeout}']
        if icon and os.path.exists(icon):
            cmd.extend(['--icon', icon])
        cmd.append(title)
        cmd.append(message)
        subprocess.run(cmd, timeout=5)

    def _notify_osascript(self, title: str, message: str):
        """Send notification using osascript (macOS)."""
        # Escape quotes
        title = title.replace('"', '\\"')
        message = message.replace('"', '\\"')
        script = f'display notification "{message}" with title "{title}"'
        subprocess.run(['osascript', '-e', script], timeout=5)

    def _notify_win10toast(self, title: str, message: str):
        """Send notification using win10toast."""
        try:
            from win10toast import ToastNotifier
            toaster = ToastNotifier()
            toaster.show_toast(title, message, duration=5, threaded=True)
        except Exception:
            pass

    def _notify_powershell(self, title: str, message: str):
        """Send notification using PowerShell (Windows)."""
        # Escape quotes
        title = title.replace('"', '`"').replace("'", "''")
        message = message.replace('"', '`"').replace("'", "''")
        script = f'''
        Add-Type -AssemblyName System.Windows.Forms
        $notify = New-Object System.Windows.Forms.NotifyIcon
        $notify.Icon = [System.Drawing.SystemIcons]::Information
        $notify.Visible = $true
        $notify.ShowBalloonTip(5000, "{title}", "{message}", [System.Windows.Forms.ToolTipIcon]::Info)
        Start-Sleep -Seconds 6
        $notify.Dispose()
        '''
        subprocess.run(['powershell', '-Command', script], timeout=10)

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
