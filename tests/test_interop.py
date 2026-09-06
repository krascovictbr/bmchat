import os
import re
import socket
import struct
import time

import pytest

from bmchat.crypto import ecc
from bmchat.crypto.keys import generate_keys
from bmchat.crypto.pow import (
    calculate_target, find_nonce_single_threaded, initial_hash_of,
    is_proof_of_work_sufficient,
)
from bmchat.protocol import objects, packets
from bmchat.protocol.const import MAGIC
from bmchat.util import decode_varint

REFERENCE_PROTOCOL = '/tmp/opencode/bmsrc/protocol.py'


def _reference_pow_validator():
    if not os.path.exists(REFERENCE_PROTOCOL):
        pytest.skip('fonte de referência indisponível')
    import types
    with open(REFERENCE_PROTOCOL) as handle:
        src = handle.read()
    start = src.index('def isProofOfWorkSufficient(')
    end = src.index('# Packet creation')
    namespace = {
        'defaults': types.SimpleNamespace(
            networkDefaultProofOfWorkNonceTrialsPerByte=1000,
            networkDefaultPayloadLengthExtraBytes=1000),
        'unpack': struct.unpack,
        'hashlib': __import__('hashlib'),
        'time': __import__('time'),
    }
    exec(src[start:end], namespace)
    return namespace['isProofOfWorkSufficient']


def test_der_signatures():
    priv = os.urandom(32)
    pub = ecc.point_mult(priv)
    assert len(pub) == 65 and pub[:1] == b'\x04'
    data = b'rede bitmessage' * 20
    sig = ecc.sign_data(priv, data)
    assert sig[:1] == b'\x30'
    assert ecc.verify_signature(pub, sig, data)
    assert not ecc.verify_signature(pub, sig, data + b'x')
    # legado raw-64 continua aceito
    import hashlib as _hashlib
    from ecdsa import SECP256k1, SigningKey
    from ecdsa.util import sigencode_string
    sk = SigningKey.from_secret_exponent(
        int.from_bytes(priv, 'big'), curve=SECP256k1)
    raw_sig = sk.sign(data, hashfunc=_hashlib.sha256,
                      sigencode=sigencode_string)
    assert len(raw_sig) == 64
    assert ecc.verify_signature(pub, raw_sig, data)


def test_version_packet_strict_parse():
    payload = packets.assemble_version_payload(
        '127.0.0.1', 8444, [1], nonce=b'12345678')
    version, = struct.unpack('>L', payload[0:4])
    assert version == 3
    services, = struct.unpack('>q', payload[4:12])
    assert services == 1
    timestamp, = struct.unpack('>q', payload[12:20])
    assert abs(timestamp - int(time.time())) < 120
    remote_services, = struct.unpack('>q', payload[20:28])
    assert remote_services == 1
    assert payload[28:44] == packets.encode_host('127.0.0.1')
    remote_port, = struct.unpack('>H', payload[44:46])
    assert remote_port == 8444
    local_services, = struct.unpack('>q', payload[46:54])
    assert local_services == 1
    assert payload[54:70] == b'\x00' * 10 + b'\xff\xff' + \
        socket.inet_aton('127.0.0.1')
    local_port, = struct.unpack('>H', payload[70:72])
    assert local_port == 8444
    assert payload[72:80] == b'12345678'
    agent_len, agent_size = decode_varint(payload[80:])
    agent = payload[80 + agent_size:80 + agent_size + agent_len]
    assert re.match(rb'^/[a-zA-Z]+:[0-9]+\.?[\w\s\(\)\./:;-]*/$', agent)
    position = 80 + agent_size + agent_len
    count, count_size = decode_varint(payload[position:])
    position += count_size
    streams = []
    for _ in range(count):
        stream, size = decode_varint(payload[position:])
        position += size
        streams.append(stream)
    assert streams == [1]
    assert position == len(payload)


def test_pow_matches_reference():
    reference = _reference_pow_validator()
    keys = generate_keys(stream=1)
    expires = int(time.time()) + 300
    unsigned = objects.build_getpubkey_unsigned(expires, 1, 4, keys.tag)
    target = calculate_target(1000, 1000, len(unsigned) + 8, 300)
    nonce = find_nonce_single_threaded(initial_hash_of(unsigned), target)
    raw = objects.complete_object(unsigned, nonce)
    assert is_proof_of_work_sufficient(raw)
    assert reference(raw)
    tampered = bytearray(raw)
    tampered[30] ^= 1
    assert not is_proof_of_work_sufficient(bytes(tampered))
    assert not reference(bytes(tampered))


def test_packet_header_matches_reference():
    packet = packets.create_packet('version', b'\x00' * 10)
    magic, command, length, checksum = packets.parse_header(packet[:24])
    assert magic == MAGIC == 0xE9BEB4D9
    assert command == 'version'
    assert length == 10
    import hashlib
    assert checksum == hashlib.sha512(b'\x00' * 10).digest()[:4]
    assert len(packet) == 24 + 10
