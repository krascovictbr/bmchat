"""EventEmitter — Observer Pattern.

Implementação thread-safe de pub/sub para desacoplar Client da GUI.
Mantém compatibilidade com o legado ui_queue ao mesmo tempo que
permite que a GUI se registre como observer e reaja a eventos sem polling.

Exemplo:
    emitter = EventEmitter()
    emitter.on(Events.NEW_MESSAGE, lambda data: print(data))
    emitter.emit(Events.NEW_MESSAGE, {'from': 'BM-...', 'body': 'oi'})

    # Compat: ui_queue também recebe para testes antigos
    queue = Queue()
    emitter = EventEmitter(queue=queue, legacy_bridge=True)
"""
import threading
from collections import defaultdict
from typing import Any, Callable, Dict, List


class EventEmitter:
    """Observable base.

    Thread-safe, suporta on/off/once/emit/clear.
    Callbacks nunca propagam exceção para não quebrar emissor.
    """

    def __init__(self, queue=None, legacy_bridge: bool = False):
        self._listeners: Dict[str, List[Callable]] = defaultdict(list)
        self._once_wrappers: Dict[str, List[Callable]] = {}
        self._lock = threading.RLock()
        self._queue = queue
        self._legacy_bridge = legacy_bridge

    # -- subscrição --

    def on(self, event: str, callback: Callable) -> Callable:
        """Registra callback para evento. Retorna callback para chaining."""
        with self._lock:
            if callback not in self._listeners[event]:
                self._listeners[event].append(callback)
        return callback

    def off(self, event: str, callback: Callable) -> None:
        """Remove callback de evento."""
        with self._lock:
            try:
                self._listeners[event].remove(callback)
            except ValueError:
                pass
            # Limpa wrappers once se necessário
            wrappers = self._once_wrappers.get(event)
            if wrappers:
                self._once_wrappers[event] = [w for w in wrappers if w[0] is not callback]

    def once(self, event: str, callback: Callable) -> Callable:
        """Registra callback que dispara uma única vez."""
        def wrapper(data=None):
            try:
                callback(data)
            finally:
                self.off(event, wrapper)
        with self._lock:
            self._listeners[event].append(wrapper)
            self._once_wrappers.setdefault(event, []).append((callback, wrapper))
        return wrapper

    def clear(self, event: str | None = None) -> None:
        """Limpa listeners. Se event=None limpa tudo."""
        with self._lock:
            if event is None:
                self._listeners.clear()
                self._once_wrappers.clear()
            else:
                self._listeners.pop(event, None)
                self._once_wrappers.pop(event, None)

    # -- emissão --

    def emit(self, event: str, data: Any = None) -> int:
        """Emite evento para todos os listeners. Retorna nº de callbacks chamados."""
        with self._lock:
            callbacks = list(self._listeners.get(event, []))
            # wildcard listeners ('*') recebem (event, data)
            wildcard = list(self._listeners.get('*', []))
        count = 0
        for cb in callbacks:
            try:
                # Tenta chamar com data; se falhar por assinatura, tenta sem args
                try:
                    cb(data)
                except TypeError:
                    cb()
            except Exception:
                # Observer não deve quebrar emissor; log silencioso
                pass
            count += 1
        for cb in wildcard:
            try:
                cb(event, data)
            except Exception:
                try:
                    cb(data)
                except Exception:
                    pass
            count += 1
        # Bridge opcional para compatibilidade legada (ex.: forward para fila)
        if self._queue is not None and self._legacy_bridge:
            try:
                self._queue.put((event, data))
            except Exception:
                pass
        return count

    # -- introspecção --

    def listeners(self, event: str) -> List[Callable]:
        with self._lock:
            return list(self._listeners.get(event, []))

    def has_listeners(self, event: str) -> bool:
        with self._lock:
            return bool(self._listeners.get(event))

    def event_names(self):
        with self._lock:
            return [k for k, v in self._listeners.items() if v]

    # Alias compatível com prompt original
    subscribe = on
    unsubscribe = off
    notify = emit
