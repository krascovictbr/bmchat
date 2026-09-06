import hashlib
import os
import socket
import struct
import time

from ..util import encode_varint, decode_varint, sha512
from .const import (
    MAGIC, NODE_NETWORK, PROTOCOL_VERSION, USER_AGENT,
)

HEADER_FORMAT = '!L12sL4s'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

SELF_NONCE = struct.pack('>Q', int.from_bytes(os.urandom(8), 'big'))


def create_packet(command, payload=b''):
    if isinstance(command, str):
        command = command.encode('ascii')
    checksum = sha512(payload)[:4]
    header = struct.pack(
        HEADER_FORMAT, MAGIC, command[:12].ljust(12, b'\x00'),
        len(payload), checksum)
    return header + payload


def parse_header(blob):
    magic, command, length, checksum = struct.unpack(HEADER_FORMAT, blob)
    command = command.decode('ascii', 'replace').rstrip('\x00')
    return magic, command, length, checksum


def encode_host(host):
    if host.endswith('.onion'):
        import base64
        return b'\xfd\x87\xd8\x7e\xeb\x43' + base64.b32decode(
            host.split('.')[0], True)
    if host.find(':') != -1:
        return socket.inet_pton(socket.AF_INET6, host)
    return b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff' + \
        socket.inet_aton(host)


def is_onion(host):
    return host.endswith('.onion')


def decode_host(ip_bytes):
    import base64
    if ip_bytes[:6] == b'\xfd\x87\xd8\x7e\xeb\x43':
        host = base64.b32encode(ip_bytes[6:]).decode('ascii').lower()
        return host.rstrip('=') + '.onion'
    if ip_bytes[:12] == b'\x00' * 10 + b'\xff\xff':
        return socket.inet_ntoa(ip_bytes[12:16])
    try:
        return socket.inet_ntop(socket.AF_INET6, ip_bytes)
    except Exception:
        return None


def assemble_version_payload(remote_host, remote_port, participating_streams,
                             services=NODE_NETWORK, nonce=None):
    nonce = nonce if nonce is not None else \
        struct.pack('>Q', int.from_bytes(os.urandom(8), 'big'))
    payload = struct.pack('>L', PROTOCOL_VERSION)
    payload += struct.pack('>q', services)
    payload += struct.pack('>q', int(time.time()))
    payload += struct.pack('>q', NODE_NETWORK)
    remote_bytes = encode_host(remote_host)
    if len(remote_bytes) != 16:
        remote_bytes = b'\x00' * 10 + b'\xff\xff' + \
            socket.inet_aton('0.0.0.0')
    payload += remote_bytes
    payload += struct.pack('>H', remote_port)
    payload += struct.pack('>q', services)
    payload += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff' + \
        struct.pack('>L', 2130706433)
    payload += struct.pack('>H', 8444)
    payload += nonce
    agent = USER_AGENT.encode('utf-8')
    payload += encode_varint(len(agent)) + agent
    streams = sorted(participating_streams)
    payload += encode_varint(len(streams))
    for stream in streams[:160000]:
        payload += encode_varint(stream)
    return payload


def assemble_version(remote_host, remote_port, participating_streams, **kw):
    return create_packet('version', assemble_version_payload(
        remote_host, remote_port, participating_streams, **kw))


def assemble_addr(peers):
    if not peers:
        return b''
    payload = encode_varint(len(peers))
    for host, port, stream, services, timestamp in peers:
        payload += struct.pack('>Q', timestamp)
        payload += struct.pack('>I', stream)
        payload += struct.pack('>q', 1)
        payload += encode_host(host)
        payload += struct.pack('>H', port)
    return payload


def assemble_inventory(hashes):
    payload = encode_varint(len(hashes))
    for obj_hash in hashes:
        payload += obj_hash
    return payload


def assemble_getdata(hashes):
    payload = encode_varint(len(hashes))
    for obj_hash in hashes:
        payload += obj_hash
    return payload


def parse_inventory(payload):
    count, position = decode_varint(payload)
    result = []
    for _ in range(count):
        if len(payload) < position + 32:
            break
        result.append(payload[position:position + 32])
        position += 32
    return result


def parse_addr(payload):
    count, position = decode_varint(payload)
    result = []
    for _ in range(count):
        if len(payload) < position + 38:
            break
        timestamp, = struct.unpack('>Q', payload[position:position + 8])
        stream, = struct.unpack('>I', payload[position + 8:position + 12])
        services, = struct.unpack('>q', payload[position + 12:position + 20])
        ip_bytes = payload[position + 20:position + 36]
        port, = struct.unpack('>H', payload[position + 36:position + 38])
        position += 38
        result.append((timestamp, stream, services, ip_bytes, port))
    return result


def version_packet_command(cmd):
    return cmd.encode()[:12].ljust(12, b'\x00')