import socket
import struct
import threading
import time

from ..protocol import packets
from ..protocol.const import NODE_NETWORK
from ..util import decode_varint


class PeerConnection(threading.Thread):

    def __init__(self, manager, peer, sock=None):
        super().__init__(daemon=True, name='peer-%s:%s' % (peer.host, peer.port))
        self.manager = manager
        self.peer = peer
        self.peer_key = (peer.host, peer.port)
        self.sock = sock
        self.established = False
        self.their_version = None
        self.their_services = 0
        self.their_streams = []
        self.their_timestamp = None
        self.time_offset = None
        self.got_version = False
        self.sent_verack = False
        self.initial_data_sent = False
        self.write_lock = threading.Lock()
        self.started_at = time.time()
        self.connected_at = None
        # Último addr/inv/object recebido (getdata inbound também conta,
        # via manager.on_getdata; version/verack/ping NÃO: handshake e
        # keepalive não provam par falante). None = mudo.
        self.last_useful_at = None
        self.bytes_sent = 0
        self.bytes_received = 0
        self._closing = False

    def close(self):
        self._closing = True
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self.sock.close()
            except Exception:
                pass

    def send_packet(self, command, payload=b''):
        if self.sock is None or self._closing:
            raise ConnectionError('conexão fechada')
        blob = packets.create_packet(command, payload)
        with self.write_lock:
            self.sock.sendall(blob)
            self.bytes_sent += len(blob)

    def send_packets(self, command, blobs):
        if self.sock is None or self._closing:
            raise ConnectionError('conexão fechada')
        buffer = b''.join(
            packets.create_packet(command, blob) for blob in blobs)
        with self.write_lock:
            self.sock.sendall(buffer)
            self.bytes_sent += len(buffer)

    def _recv_exact(self, sock, size):
        data = b''
        while len(data) < size:
            chunk = sock.recv(size - len(data))
            if not chunk:
                raise ConnectionError('conexão encerrada')
            data += chunk
            self.bytes_received += len(chunk)
        return data

    def run(self):
        try:
            if self.sock is None:
                self.sock = self._connect()
            self._handshake()
            if not self.established:
                return
            self._read_loop()
        except Exception as exc:
            self.manager.log('peer %s:%s encerrou: %s' % (
                self.peer.host, self.peer.port, exc))
        finally:
            self.close()
            # Só remove se o mapa ainda aponta para ESTA conexão: após
            # um wipe a reconexão imediata pode já ter registrado uma
            # conexão nova com a mesma chave; remover à toa orfana a
            # conexão nova (some do diagnóstico e do prune).
            try:
                with self.manager.lock:
                    if self.manager.connections.get(
                            self.peer_key) is self:
                        self.manager.connections.pop(self.peer_key, None)
            except Exception:
                try:
                    self.manager.connections.pop(self.peer_key, None)
                except Exception:
                    pass
            if not self.established:
                try:
                    self.manager.peers.record_failure(
                        self.peer.host, self.peer.port)
                except Exception:
                    pass
            self.manager.on_log('network', 'conexão encerrada: %s' % self.peer)

    def _connect(self):
        from ..net.proxy import connect_socket
        try:
            connect_timeout = int(
                self.manager.db.get_int('connect_timeout', 30))
        except (TypeError, ValueError):
            connect_timeout = 30
        try:
            recv_timeout = int(self.manager.db.get_int('recv_timeout', 60))
        except (TypeError, ValueError):
            recv_timeout = 60
        sock = connect_socket(
            self.peer.host, self.peer.port, self.manager.proxy,
            timeout=max(5, min(connect_timeout, 300)))
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(max(10, min(recv_timeout, 600)))
        return sock

    def _handshake_timeout(self):
        try:
            timeout = float(getattr(
                self.manager, 'HANDSHAKE_TIMEOUT', 25))
        except Exception:
            timeout = 25.0
        return max(5.0, min(timeout, 120.0))

    def _log_handshake_timeout(self):
        try:
            self.manager.log(
                'peer %s handshake sem resposta há %ds '
                '(sem version/verack)' % (
                    self.peer, int(time.time() - self.started_at)))
        except Exception:
            pass

    def _handshake_once(self, digest):
        magic, command, length, checksum = self._read_header()
        payload = self._recv_exact(self.sock, length)
        try:
            if digest(payload)[:4] != checksum:
                return
        except Exception:
            return
        try:
            self._handle(command, payload)
        except Exception as exc:
            try:
                self.manager.log('peer %s handshake %r falhou: %s' % (
                    self.peer, command, exc))
            except Exception:
                pass

    def _handshake(self):
        self.send_packet(b'version', packets.assemble_version_payload(
            self.peer.host, self.peer.port, self.manager.streams,
            nonce=self.manager.nonce))
        from ..util.hashing import sha512 as _sha512hs
        # Referência (connectionpool.py, reaper): par não-estabelecido sem
        # tráfego há 20s é fechado ("Timeout"). Aqui: deadline único para
        # version+verack; _prune_connections aplica o mesmo limite a
        # conexões presas no TCP-connect (↑0B ↓0B) que nem chegaram aqui.
        end = time.time() + self._handshake_timeout()
        while not self._closing and time.time() < end and not self.established:
            self._handshake_once(_sha512hs)
        if not self.established and not self._closing:
            self._log_handshake_timeout()

    def _receive_payload(self, header):
        _magic, command, length, checksum = header
        if length == 0:
            payload = b''
        else:
            payload = self._recv_exact(self.sock, length)
        from ..util.hashing import sha512 as _sha512
        try:
            if _sha512(payload)[:4] != checksum:
                return None, None
        except Exception:
            return None, None
        return command, payload

    def _log_command_error(self, command, exc):
        try:
            self.manager.log('peer %s comando %r falhou: %s' % (
                self.peer, command, exc))
        except Exception:
            pass

    def _read_loop(self):
        while not self._closing:
            try:
                header = self._read_header()
            except socket.timeout:
                continue
            command, payload = self._receive_payload(header)
            if command is None:
                continue
            try:
                self._handle(command, payload)
            except Exception as exc:
                self._log_command_error(command, exc)

    def _read_header(self):
        from ..protocol.const import MAX_OBJECT_LENGTH
        from ..protocol.packets import HEADER_SIZE
        blob = self._recv_exact(self.sock, HEADER_SIZE)
        magic, command, length, checksum = packets.parse_header(blob)
        if magic != packets.MAGIC:
            raise ValueError('magic inválido')
        if length > MAX_OBJECT_LENGTH + 64 + HEADER_SIZE:
            raise ValueError('comprimento excessivo')
        return magic, command, length, checksum

    _PAYLOAD_COMMANDS = {
        'version': '_on_version',
        'addr': '_on_addr',
        'inv': '_on_inv',
        'dinv': '_on_inv',
        'getdata': '_on_getdata',
        'object': '_on_object',
    }

    def _handle(self, command, payload):
        command = command.rstrip('\x00')
        if command in self._PAYLOAD_COMMANDS:
            getattr(self, self._PAYLOAD_COMMANDS[command])(payload)
        else:
            self._handle_control(command, payload)

    def _handle_control(self, command, payload):
        if command == 'verack':
            self._on_verack()
        elif command == 'ping':
            self.send_packet(b'pong')
        elif command == 'pong':
            pass
        elif command == 'error':
            self.manager.log('erro do peer %s: %s' % (self.peer, payload[:200]))
        else:
            self.manager.log('comando desconhecido: %s' % command)

    def _on_version(self, payload):
        self.their_version = payload
        if len(payload) < 80:
            return
        version, = struct.unpack('>L', payload[0:4])
        self.their_services, = struct.unpack('>q', payload[4:12])
        self.their_timestamp, = struct.unpack('>q', payload[12:20])
        try:
            self.time_offset = self.their_timestamp - int(time.time())
        except Exception:
            self.time_offset = None
        nonce = payload[72:80]
        if nonce == self.manager.nonce:
            self.manager.log('auto-conexão, ignorando')
            self.close()
            return
        self.got_version = True
        try:
            streams = self._parse_streams(payload)
            self.their_streams = streams
        except Exception:
            pass
        if not self.sent_verack:
            self.sent_verack = True
            self.send_packet(b'verack')
        self.manager.add_peer(self.peer.host, self.peer.port,
                              stream=1, services=self.their_services)
        self._maybe_send_initial_data()

    def _parse_streams(self, payload):
        position = 80
        agent_len, agent_size = decode_varint(payload[position:])
        position += agent_size + agent_len
        count, count_size = decode_varint(payload[position:])
        position += count_size
        streams = []
        for _ in range(min(count, 10000)):
            stream, size = decode_varint(payload[position:])
            position += size
            streams.append(stream)
        return streams

    def _on_verack(self):
        self.established = True
        try:
            self.manager.peers.record_success(self.peer.host, self.peer.port)
        except Exception:
            pass
        if self.connected_at is None:
            self.connected_at = time.time()
        self.manager.on_log('network', 'conectado a %s' % self.peer)
        self._maybe_send_initial_data()

    def _maybe_send_initial_data(self):
        if self.established and self.got_version and \
                not self.initial_data_sent:
            self.initial_data_sent = True
            self._send_initial_data()

    def _send_initial_data(self):
        peers = []
        for peer, info in self.manager.peers.best(limit=30, exclude={self.peer_key}):
            try:
                if len(packets.encode_host(peer.host)) != 16:
                    continue
            except Exception:
                continue
            peers.append((peer.host, peer.port,
                          info.get('stream', 1),
                          info.get('services', NODE_NETWORK),
                          info.get('last_seen', int(time.time()))))
        if peers:
            self.send_packet(b'addr', packets.assemble_addr(peers))
        self.manager.send_inventory(self)

    def _on_addr(self, payload):
        self.last_useful_at = time.time()
        entries = packets.parse_addr(payload)
        for timestamp, stream, services, ip_bytes, port in entries[:200]:
            try:
                host = packets.decode_host(ip_bytes)
            except Exception:
                host = self._fallback_host(ip_bytes)
            if not host or not port:
                continue
            now = time.time()
            if timestamp > now + 3600 or timestamp < now - 3 * 24 * 3600:
                continue
            self.manager.add_peer(host, port, stream=stream, services=services)

    def _fallback_host(self, ip_bytes):
        try:
            if ip_bytes[:12] == b'\x00' * 10 + b'\xff\xff':
                import socket as s
                return s.inet_ntoa(ip_bytes[12:16])
        except Exception:
            pass
        return None

    def _on_inv(self, payload):
        self.last_useful_at = time.time()
        self.manager.on_inv(self, payload)

    def _on_getdata(self, payload):
        self.manager.on_getdata(self, payload)

    def _on_object(self, payload):
        self.last_useful_at = time.time()
        self.manager.received_object(payload, self)
