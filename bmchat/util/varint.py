from struct import pack, unpack


class VarintEncodeError(Exception):
    pass


class VarintDecodeError(Exception):
    pass


# (prefix byte, total length, struct format, minimal value)
_VARINT_SPECS = (
    (253, 3, '>H', 253),
    (254, 5, '>I', 65536),
    (255, 9, '>Q', 4294967296),
)


def encode_varint(integer):
    if integer < 0:
        raise VarintEncodeError('varint cannot be < 0')
    if integer < 253:
        return pack('>B', integer)
    if integer < 65536:
        return pack('>B', 253) + pack('>H', integer)
    if integer < 4294967296:
        return pack('>B', 254) + pack('>I', integer)
    if integer < 18446744073709551616:
        return pack('>B', 255) + pack('>Q', integer)
    raise VarintEncodeError('varint cannot be >= 2**64')


def _decode_varint_prefixed(data, first_byte):
    for prefix, length, fmt, minimum in _VARINT_SPECS:
        if first_byte != prefix:
            continue
        if len(data) < length:
            raise VarintDecodeError('varint truncated')
        value, = unpack(fmt, data[1:length])
        if value < minimum:
            raise VarintDecodeError('varint not minimally encoded')
        return value, length
    raise VarintDecodeError('invalid varint')


def decode_varint(data):
    if not data:
        raise VarintDecodeError('varint truncated (empty)')
    first_byte, = unpack('>B', data[0:1])
    if first_byte < 253:
        return first_byte, 1
    return _decode_varint_prefixed(data, first_byte)
