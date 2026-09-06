ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def encode_base58(blob):
    num = int.from_bytes(blob, 'big')
    if num == 0:
        return ALPHABET[0]
    arr = []
    base = len(ALPHABET)
    while num:
        num, rem = divmod(num, base)
        arr.append(ALPHABET[rem])
    arr.reverse()
    return ''.join(arr)


def decode_base58(text):
    base = len(ALPHABET)
    num = 0
    for char in text:
        if char not in ALPHABET:
            raise ValueError('invalid base58 character: %r' % char)
        num = num * base + ALPHABET.index(char)
    return num.to_bytes((num.bit_length() + 7) // 8 or 1, 'big')