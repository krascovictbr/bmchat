ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {c: i for i, c in enumerate(ALPHABET)}


def encode_base58(blob):
    if not blob:
        return ALPHABET[0]
    pad = len(blob) - len(blob.lstrip(b'\x00'))
    num = int.from_bytes(blob, 'big')
    if num == 0:
        return ALPHABET[0] * max(pad, 1)
    arr = []
    base = len(ALPHABET)
    while num:
        num, rem = divmod(num, base)
        arr.append(ALPHABET[rem])
    arr.reverse()
    return ALPHABET[0] * pad + ''.join(arr)


def decode_base58(text):
    if len(text) > 100:
        raise ValueError('base58 muito longo')
    base = len(ALPHABET)
    num = 0
    pad = 0
    for char in text:
        if char == ALPHABET[0] and num == 0:
            pad += 1
        try:
            num = num * base + _INDEX[char]
        except KeyError:
            raise ValueError('invalid base58 character: %r' % char)
    raw = num.to_bytes((num.bit_length() + 7) // 8 or 1, 'big')
    if pad and raw != b'\x00':
        raw = b'\x00' * pad + raw.lstrip(b'\x00')
    return raw