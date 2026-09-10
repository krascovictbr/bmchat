"""Diálogos modais leves da GUI (ask_simple, choose, info, warn, confirm).

Notas de consistência (sem importar ``app.py`` para evitar ciclo):
``BG`` espelha ``PANEL_BG`` ('#ffffff'), ``FG`` espelha ``TEXT_INK``,
``DIM`` espelha ``TEXT_GRAY`` e ``ACCENT`` espelha ``FAB_BG`` ('#4ea4e5').
"""

import tkinter as tk
from tkinter import messagebox

BG = "#ffffff"
FG = "#222222"
DIM = "#8a96a0"
FIELD_BG = "#f1f3f5"
ACCENT = "#4ea4e5"
ACCENT_DARK = "#3d93d6"
BTN_BG = "#e6ebf0"

# Estilos compartilhados (dicts criados uma vez; nunca em loop).
_OK_STYLE = {
    "bg": ACCENT,
    "fg": "white",
    "activebackground": ACCENT_DARK,
    "activeforeground": "white",
    "relief": "flat",
    "width": 10,
}
_CANCEL_STYLE = {
    "bg": BTN_BG,
    "fg": FG,
    "activebackground": BTN_BG,
    "activeforeground": FG,
    "relief": "flat",
    "width": 10,
}
_ENTRY_STYLE = {
    "bg": FIELD_BG,
    "fg": FG,
    "insertbackground": FG,
    "highlightthickness": 1,
    "highlightbackground": ACCENT,
}
_MODAL_KEYS = ("<Return>", "<KP_Enter>", "<Escape>")


def _release_grab(dialog):
    try:
        dialog.grab_release()
    except Exception:
        pass


def _close(dialog):
    """Cancela binds do modal e destrói a janela (tolera duplo close).

    Libera o ``grab`` antes de destruir (idempotente): cobre exceção no
    caminho OK/Cancelar e duplo fechamento (botão + Escape/X seguidos).
    """
    _release_grab(dialog)
    for seq in _MODAL_KEYS:
        try:
            dialog.unbind(seq)
        except Exception:
            pass
    try:
        dialog.destroy()
    except Exception:
        pass


def _center_on_parent(dialog, parent):
    """Centraliza o modal sobre a janela pai (ou na tela, se falhar)."""
    try:
        dialog.update_idletasks()
        dw = max(1, dialog.winfo_reqwidth())
        dh = max(1, dialog.winfo_reqheight())
        try:
            px = parent.winfo_rootx()
            py = parent.winfo_rooty()
            pw = parent.winfo_width()
            ph = parent.winfo_height()
            if pw < 10 or ph < 10:
                raise ValueError("pai sem geometria útil")
        except Exception:
            sw = dialog.winfo_screenwidth()
            sh = dialog.winfo_screenheight()
            x = max(0, (sw - dw) // 2)
            y = max(0, (sh - dh) // 2)
        else:
            x = px + max(0, (pw - dw) // 2)
            y = py + max(0, (ph - dh) // 2)
            try:
                sw = dialog.winfo_screenwidth()
                sh = dialog.winfo_screenheight()
                x = max(0, min(x, sw - min(dw, sw)))
                y = max(0, min(y, sh - min(dh, sh)))
            except Exception:
                pass
        dialog.geometry("+%d+%d" % (x, y))
    except Exception:
        pass


def _make_shell(parent, title, minsize):
    """Construtor interno comum: casca modal (Toplevel transiente).

    Começa com ``withdraw`` para posicionar antes de mapear
    (``withdraw`` → monta → centraliza → ``deiconify`` em ``_run_modal``),
    eliminando cintilação na abertura. Sem ``update``/``wait_visibility``.
    """
    dialog = tk.Toplevel(parent)
    try:
        dialog.withdraw()
    except Exception:
        pass
    dialog.title(title)
    try:
        dialog.transient(parent)
    except Exception:
        pass
    dialog.configure(bg=BG)
    dialog.resizable(True, True)
    try:
        dialog.minsize(minsize[0], minsize[1])
    except Exception:
        pass
    return dialog


def _make_button_bar(dialog, on_ok, on_cancel):
    """Barra OK/Cancelar padronizada; devolve (ok, cancel)."""
    bar = tk.Frame(dialog, bg=BG)
    bar.pack(side="bottom", pady=(8, 12))
    ok = tk.Button(bar, text="OK", command=lambda: on_ok(), **_OK_STYLE)
    cancel = tk.Button(bar, text="Cancelar", command=lambda: on_cancel(), **_CANCEL_STYLE)
    ok.pack(side="left", padx=6)
    cancel.pack(side="left", padx=6)
    return ok, cancel


def _reveal_modal(dialog, focus_widget=None):
    """Map, grab and focus the dialog (all steps tolerate dead windows)."""
    try:
        dialog.deiconify()
    except Exception:
        pass
    try:
        dialog.lift()
    except Exception:
        pass
    try:
        dialog.grab_set()
    except Exception:
        pass
    try:
        if focus_widget is not None:
            focus_widget.focus_set()
        else:
            dialog.focus_set()
    except Exception:
        pass


def _await_modal_close(parent, dialog):
    """Wait for the dialog; never leak the grab, never orphan wait_window."""
    try:
        try:
            parent.wait_window(dialog)
        except Exception:
            pass
    finally:
        _release_grab(dialog)


def _run_modal(parent, dialog, on_ok, on_cancel, focus_widget=None):
    """Loop modal comum: WM_DELETE, binds, centro, grab, foco, espera.

    ``on_ok``/``on_cancel`` recebem ``event=None`` e fecham via ``_close``.
    Ordem sem cintilação: a casca nasce em ``withdraw`` (ver
    ``_make_shell``), centraliza ainda oculta e só então ``deiconify``.
    Foco é aplicado após mapear (foco imediato). Nunca deixa grab vazado:
    libera em ``finally`` (tolera janela morta e duplo close). ``wait_window``
    nunca é órfão: ``TclError`` (pai morto/diálogo já destruído) é absorvido.
    Único ``update_idletasks`` do arquivo vive em ``_center_on_parent``
    (não bloqueante; sem ``update``/``wait_visibility`` e sem ``after``).
    """
    dialog.protocol("WM_DELETE_WINDOW", lambda: on_cancel())
    dialog.bind("<Return>", on_ok)
    dialog.bind("<KP_Enter>", on_ok)
    dialog.bind("<Escape>", on_cancel)
    _center_on_parent(dialog, parent)
    _reveal_modal(dialog, focus_widget)
    _await_modal_close(parent, dialog)


def _secret_fields(fields, password):
    """Return set of fields whose content is secret (no strip, masked)."""
    if password is True:
        return set(fields)
    if isinstance(password, (list, tuple, set, frozenset)):
        wanted = set(password)
        return {f for f in fields if f in wanted}
    return set()


def _build_simple_entries(dialog, fields, values, labels=None, password=False):
    """Build the label/entry form; return [(field, entry)]."""
    form = tk.Frame(dialog, bg=BG)
    form.pack(padx=16, pady=16, fill="both", expand=True)
    entries = []
    labels = labels or {}
    secret = _secret_fields(fields, password)
    for row, field in enumerate(fields):
        text = labels.get(field) or field.replace("_", " ").title()
        tk.Label(form, text=text, bg=BG, fg=FG).grid(row=row, column=0, sticky="w", pady=4)
        entry = tk.Entry(form, show="•" if field in secret else "", **_ENTRY_STYLE)
        entry.grid(row=row, column=1, sticky="we", pady=4, padx=(12, 0))
        try:
            entry.insert(0, str(values.get(field, "")))
        except Exception:
            pass
        entries.append((field, entry))
    form.columnconfigure(1, weight=1)
    return entries


def _read_simple_entries(entries, secret=None):
    """Collect entry values; secret fields keep verbatim (no strip)."""
    secret = secret or set()
    result = {}
    for field, entry in entries:
        try:
            raw = entry.get()
        except Exception:
            result[field] = ""
            continue
        try:
            result[field] = raw if field in secret else raw.strip()
        except Exception:
            result[field] = ""
    return result


def ask_simple(parent, title, fields, values=None, labels=None, password=False, **_kwargs):
    fields = list(fields or [])
    values = values or {}
    dialog = _make_shell(parent, title, minsize=(360, 120))
    result = {}
    try:
        secret = _secret_fields(fields, password)
        entries = _build_simple_entries(dialog, fields, values, labels=labels, password=password)

        def on_ok(event=None):
            result.update(_read_simple_entries(entries, secret=secret))
            _close(dialog)

        def on_cancel(event=None):
            result.clear()
            _close(dialog)

        ok_btn, _cancel_btn = _make_button_bar(dialog, on_ok, on_cancel)
        focus = entries[0][1] if entries else ok_btn
        _run_modal(parent, dialog, on_ok, on_cancel, focus_widget=focus)
    except Exception:
        # Falha síncrona na montagem (ex.: pai destruído): sem janela órfã
        # oculta em withdraw; semântica de retorno preservada via reraise.
        _close(dialog)
        raise
    return result or None


def _fill_listbox(listbox, options):
    """Batch insert with per-item fallback for exotic option values."""
    if not options:
        return
    try:
        listbox.insert(tk.END, *options)
    except Exception:
        for option in options:
            try:
                listbox.insert(tk.END, option)
            except Exception:
                pass


def _preselect_listbox(listbox, options):
    if options:
        try:
            listbox.selection_set(0)
            listbox.see(0)
        except Exception:
            pass


def _take_listbox_selection(listbox):
    """Return selected index or None (tolerates dead widgets)."""
    try:
        selection = listbox.curselection()
    except Exception:
        return None
    return selection[0] if selection else None


def choose(parent, title, options, prompt="Selecione:"):
    options = list(options or [])
    dialog = _make_shell(parent, title, minsize=(400, 220))
    result = {}
    try:
        tk.Label(dialog, text=prompt, bg=BG, fg=FG).pack(padx=16, pady=(14, 8))

        list_frame = tk.Frame(dialog, bg=BG)
        list_frame.pack(padx=16, pady=4, fill="both", expand=True)
        visible = max(4, min(12, len(options) or 4))
        scrollbar = tk.Scrollbar(list_frame, orient="vertical")
        listbox = tk.Listbox(
            list_frame,
            bg=FIELD_BG,
            fg=FG,
            selectbackground=ACCENT,
            selectforeground="white",
            width=52,
            height=visible,
            yscrollcommand=scrollbar.set,
            exportselection=False,
            activestyle="none",
            highlightthickness=1,
            highlightbackground=ACCENT,
        )
        scrollbar.config(command=listbox.yview)
        listbox.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        # Inserção em lote: 1 chamada Tcl em vez de N (500 itens abre sem
        # engasgo). Fallback em loop se o unpack falhar (opções exóticas).
        _fill_listbox(listbox, options)
        _preselect_listbox(listbox, options)

        def on_ok(event=None):
            index = _take_listbox_selection(listbox)
            if index is not None:
                result["index"] = index
            _close(dialog)

        def on_cancel(event=None):
            result.clear()
            _close(dialog)

        listbox.bind("<Double-Button-1>", on_ok)
        ok_btn, _cancel_btn = _make_button_bar(dialog, on_ok, on_cancel)
        _run_modal(parent, dialog, on_ok, on_cancel, focus_widget=listbox if options else ok_btn)
    except Exception:
        # Mesma garantia anti-órfão de ask_simple (ver acima).
        _close(dialog)
        raise
    return result.get("index") if result else None


def info(parent, title, message):
    messagebox.showinfo(title, message, parent=parent)


def warn(parent, title, message):
    messagebox.showwarning(title, message, parent=parent)


def confirm(parent, title, message):
    return messagebox.askyesno(title, message, parent=parent)
