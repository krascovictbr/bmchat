from struct import pack, unpack


class VarintEncodeError(Exception):
    pass


class VarintDecodeError(Exception):
    pass


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


def decode_varint(data):
    if not data:
        return 0, 0
    first_byte, = unpack('>B', data[0:1])
    if first_byte < 253:
        return first_byte, 1
    if first_byte == 253:
        if len(data) < 3:
            raise VarintDecodeError('varint truncated')
        value, = unpack('>H', data[1:3])
        if value < 253:
            raise VarintDecodeError('varint not minimally encoded')
        return value, 3
    if first_byte == 254:
        if len(data) < 5:
            raise VarintDecodeError('varint truncated')
        value, = unpack('>I', data[1:5])
        if value < 65536:
            raise VarintDecodeError('varint not minimally encoded')
        return value, 5
    if first_byte == 255:
        if len(data) < 9:
            raise VarintDecodeError('varint truncated')
        value, = unpack('>Q', data[1:9])
        if value < 4294967296:
            raise VarintDecodeError('varint not minimally encoded')
        return value, 9
    raise VarintDecodeError('invalid varint')