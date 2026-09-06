import tkinter as tk
from tkinter import messagebox

BG = '#ffffff'
FG = '#222222'
DIM = '#8a96a0'
FIELD_BG = '#f1f3f5'
ACCENT = '#4ea4e5'
ACCENT_DARK = '#3d93d6'
BTN_BG = '#e6ebf0'


def ask_simple(parent, title, fields, values=None):
    values = values or {}
    dialog = tk.Toplevel(parent)
    dialog.title(title)
    dialog.transient(parent)
    dialog.grab_set()
    dialog.configure(bg=BG)
    result = {}

    frame = tk.Frame(dialog, bg=BG)
    frame.pack(padx=16, pady=16, fill='both', expand=True)
    entries = []
    for row, field in enumerate(fields):
        label_name = field.replace('_', ' ').title()
        tk.Label(frame, text=label_name, bg=BG, fg=FG
                 ).grid(row=row, column=0, sticky='w', pady=4)
        entry = tk.Entry(frame, bg=FIELD_BG, fg=FG,
                         insertbackground=FG,
                         highlightthickness=1, highlightbackground=ACCENT)
        entry.grid(row=row, column=1, sticky='we', pady=4, padx=(12, 0))
        entry.insert(0, str(values.get(field, '')))
        entries.append((field, entry))
    frame.columnconfigure(1, weight=1)

    def on_ok(event=None):
        for field, entry in entries:
            result[field] = entry.get().strip()
        dialog.destroy()

    def on_cancel(event=None):
        result.clear()
        dialog.destroy()

    buttons = tk.Frame(dialog, bg=BG)
    buttons.pack(pady=(0, 12))
    ok = tk.Button(buttons, text='OK', command=on_ok, bg=ACCENT,
                   fg='white', activebackground=ACCENT_DARK,
                   activeforeground='white', relief='flat', width=10)
    cancel = tk.Button(buttons, text='Cancelar', command=on_cancel,
                       bg=BTN_BG, fg=FG, relief='flat', width=10)
    ok.pack(side='left', padx=6)
    cancel.pack(side='left', padx=6)
    dialog.bind('<Return>', on_ok)
    dialog.bind('<Escape>', on_cancel)
    parent.wait_window(dialog)
    return result or None


def choose(parent, title, options, prompt='Selecione:'):
    dialog = tk.Toplevel(parent)
    dialog.title(title)
    dialog.transient(parent)
    dialog.grab_set()
    dialog.configure(bg=BG)
    result = {}

    tk.Label(dialog, text=prompt, bg=BG, fg=FG
             ).pack(padx=16, pady=(14, 8))

    listbox = tk.Listbox(dialog, bg=FIELD_BG, fg=FG,
                         selectbackground=ACCENT,
                         selectforeground='white', width=52, height=12)
    listbox.pack(padx=16, pady=4)
    for option in options:
        listbox.insert(tk.END, option)
    listbox.selection_set(0)

    def on_ok(event=None):
        selection = listbox.curselection()
        if selection:
            result['index'] = selection[0]
        dialog.destroy()

    def on_cancel(event=None):
        result.clear()
        dialog.destroy()

    buttons = tk.Frame(dialog, bg=BG)
    buttons.pack(pady=(4, 12))
    tk.Button(buttons, text='OK', command=on_ok, bg=ACCENT, fg='white',
              relief='flat', width=10).pack(side='left', padx=6)
    tk.Button(buttons, text='Cancelar', command=on_cancel, bg=BTN_BG,
              fg=FG, relief='flat', width=10).pack(side='left', padx=6)
    dialog.bind('<Return>', on_ok)
    dialog.bind('<Escape>', on_cancel)
    parent.wait_window(dialog)
    return result.get('index') if result else None


def info(parent, title, message):
    messagebox.showinfo(title, message, parent=parent)


def warn(parent, title, message):
    messagebox.showwarning(title, message, parent=parent)


def confirm(parent, title, message):
    return messagebox.askyesno(title, message, parent=parent)
