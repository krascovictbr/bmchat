from ..util import (
    encode_varint, decode_varint, encode_base58, decode_base58,
    double_sha512,
)

MAX_ADDRESS_VERSION = 4
CHECKSUM_LEN = 4


def encode_address(version, stream, ripe):
    if version < 2 or version > 4:
        raise ValueError('unsupported address version')
    if len(ripe) != 20:
        raise ValueError('ripe must be 20 bytes')
    stored = encode_varint(version) + encode_varint(stream)
    if version == 4:
        body = ripe.lstrip(b'\x00')
    else:
        body = ripe[2:] if ripe[:2] == b'\x00\x00' else ripe
        if ripe[:1] == b'\x00':
            body = ripe[1:]
    data = stored + body
    checksum = double_sha512(data)[:CHECKSUM_LEN]
    return 'BM-' + encode_base58(data + checksum)


def decode_address(address):
    text = str(address).strip()
    if text[:3] == 'BM-':
        text = text[3:]
    try:
        raw = decode_base58(text)
    except ValueError:
        return 'invalidcharacters', 0, 0, None
    if len(raw) < CHECKSUM_LEN + 2:
        return 'tooshort', 0, 0, None
    data, checksum = raw[:-CHECKSUM_LEN], raw[-CHECKSUM_LEN:]
    if double_sha512(data)[:CHECKSUM_LEN] != checksum:
        return 'checksumfailed', 0, 0, None
    try:
        version, version_len = decode_varint(data[:9])
    except Exception:
        return 'varintmalformed', 0, 0, None
    if version == 0:
        return 'versiontoohigh', 0, 0, None
    if version > MAX_ADDRESS_VERSION:
        return 'versiontoohigh', 0, 0, None
    try:
        stream, stream_len = decode_varint(data[version_len:])
    except Exception:
        return 'varintmalformed', 0, 0, None
    embedded = data[version_len + stream_len:]
    if len(embedded) > 20:
        return 'ripetoolong', 0, 0, None
    if len(embedded) < 1:
        return 'ripetooshort', 0, 0, None
    if version == 4:
        if embedded[0:1] == b'\x00':
            return 'encodingproblem', 0, 0, None
        ripe = b'\x00' * (20 - len(embedded)) + embedded
    else:
        ripe = b'\x00' * (20 - len(embedded)) + embedded
    return 'success', version, stream, ripe


def validate_address(address):
    status, version, stream, ripe = decode_address(address)
    return status == 'success'


def add_bm_prefix(address):
    text = str(address).strip()
    return text if text[:3] == 'BM-' else 'BM-' + text