from ..util import (
    encode_varint,
    decode_varint,
    encode_base58,
    decode_base58,
    double_sha512,
)

MAX_ADDRESS_VERSION = 4
CHECKSUM_LEN = 4


class _AddressError(Exception):
    """Internal status carrier for decode_address helpers."""

    def __init__(self, status):
        super().__init__(status)
        self.status = status


def encode_address(version, stream, ripe):
    if version < 2 or version > 4:
        raise ValueError("unsupported address version")
    if len(ripe) != 20:
        raise ValueError("ripe must be 20 bytes")
    stored = encode_varint(version) + encode_varint(stream)
    if version == 4:
        body = ripe.lstrip(b"\x00")
    elif ripe[:2] == b"\x00\x00":
        body = ripe[2:]
    elif ripe[:1] == b"\x00":
        body = ripe[1:]
    else:
        body = ripe
    data = stored + body
    checksum = double_sha512(data)[:CHECKSUM_LEN]
    return "BM-" + encode_base58(data + checksum)


def _checked_address_data(raw):
    if len(raw) < CHECKSUM_LEN + 2:
        raise _AddressError("tooshort")
    data, checksum = raw[:-CHECKSUM_LEN], raw[-CHECKSUM_LEN:]
    if double_sha512(data)[:CHECKSUM_LEN] != checksum:
        raise _AddressError("checksumfailed")
    return data


def _decoded_address_header(data):
    try:
        version, version_len = decode_varint(data[:9])
    except Exception:
        raise _AddressError("varintmalformed")
    if version == 0 or version == 1:
        raise _AddressError("versiontoohigh")
    if version > MAX_ADDRESS_VERSION:
        raise _AddressError("versiontoohigh")
    try:
        stream, stream_len = decode_varint(data[version_len:])
    except Exception:
        raise _AddressError("varintmalformed")
    if stream == 0:
        raise _AddressError("versiontoohigh")
    return version, stream, data[version_len + stream_len:]


def _padded_address_ripe(version, embedded):
    if len(embedded) > 20:
        raise _AddressError("ripetoolong")
    if len(embedded) < 1:
        raise _AddressError("ripetooshort")
    if version == 4 and embedded[0:1] == b"\x00":
        raise _AddressError("encodingproblem")
    return b"\x00" * (20 - len(embedded)) + embedded


def decode_address(address):
    text = str(address).strip()
    if text[:3] == "BM-":
        text = text[3:]
    try:
        raw = decode_base58(text)
    except ValueError:
        return "invalidcharacters", 0, 0, None
    try:
        data = _checked_address_data(raw)
        version, stream, embedded = _decoded_address_header(data)
        ripe = _padded_address_ripe(version, embedded)
    except _AddressError as exc:
        return exc.status, 0, 0, None
    return "success", version, stream, ripe


def validate_address(address):
    status, version, stream, ripe = decode_address(address)
    return status == "success"


def add_bm_prefix(address):
    text = str(address).strip()
    return text if text[:3] == "BM-" else "BM-" + text
