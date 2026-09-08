"""Tooltip widget for Tkinter."""

import tkinter as tk
from typing import Optional


class ToolTip:
    """Simple tooltip for any widget."""

    def __init__(self, widget: tk.Widget, text: str, delay: int = 500):
        self.widget = widget
        self.text = text
        self.delay = delay
        self.tip_window: Optional[tk.Toplevel] = None
        self.after_id: Optional[str] = None

        widget.bind('<Enter>', self._schedule_show, add='+')
        widget.bind('<Leave>', self._hide, add='+')
        widget.bind('<ButtonPress>', self._hide, add='+')

    def _schedule_show(self, event=None):
        self._hide()
        self.after_id = self.widget.after(self.delay, self._show)

    def _show(self):
        if self.tip_window:
            return
        try:
            x = self.widget.winfo_rootx() + 20
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        except Exception:
            return

        # Use simple colors since we can't import theme here (circular import)
        self.tip_window = tk.Toplevel(self.widget)
        self.tip_window.wm_overrideredirect(True)
        self.tip_window.wm_geometry(f'+{x}+{y}')

        label = tk.Label(
            self.tip_window,
            text=self.text,
            bg='#212529',
            fg='#ffffff',
            font=('TkDefaultFont', 9),
            padx=8,
            pady=4,
            relief='solid',
            bd=1,
        )
        label.pack()

    def _hide(self, event=None):
        if self.after_id:
            try:
                self.widget.after_cancel(self.after_id)
            except Exception:
                pass
            self.after_id = None
        if self.tip_window:
            try:
                self.tip_window.destroy()
            except Exception:
                pass
            self.tip_window = None

    def update_text(self, text: str):
        """Update tooltip text."""
        self.text = text
        if self.tip_window:
            for child in self.tip_window.winfo_children():
                if isinstance(child, tk.Label):
                    child.config(text=text)
                    break
