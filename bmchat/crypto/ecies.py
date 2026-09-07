import hmac
import os

from Crypto.Cipher import AES
from Crypto.Util import Padding

from ..util.hashing import sha512, hmac_sha256
from . import ecc

CURVE_TYPE = 0x02CA
X_LEN = 0x0020
Y_LEN = 0x0020
R_PREFIX = (b'\x02\xca' + b'\x00\x20')
R_LEN = 70
IV_LEN = 16
MAC_LEN = 32


def encode_ephemeral_public(point):
    point = ecc.decode_point_public(ecc.encode_point_public(point)) \
        if isinstance(point, bytes) else point
    return (
        R_PREFIX
        + point.x().to_bytes(32, 'big')
        + Y_LEN.to_bytes(2, 'big')
        + point.y().to_bytes(32, 'big')
    )


def decode_ephemeral_public(blob):
    if len(blob) != R_LEN:
        raise ValueError('invalid ephemeral public key length')
    curve = int.from_bytes(blob[0:2], 'big')
    xlen = int.from_bytes(blob[2:4], 'big')
    x = blob[4:4 + xlen]
    ylen = int.from_bytes(blob[36:38], 'big')
    y = blob[38:38 + ylen]
    if curve != CURVE_TYPE or xlen != 32 or ylen != 32:
        raise ValueError('invalid ephemeral public key')
    from ecdsa.ellipticcurve import Point
    from .ecc import CURVE
    return Point(CURVE, int.from_bytes(x, 'big'), int.from_bytes(y, 'big'))


def _derive_keys(shared_point):
    shared_x = shared_point.x().to_bytes(32, 'big')
    digest = sha512(shared_x)
    return digest[:32], digest[32:]


def encrypt(plaintext, public_key):
    iv = os.urandom(IV_LEN)
    r = ecc.random_private_key()
    r_bytes = ecc.int_to_32(r)
    r_point = ecc.GENERATOR * r
    ephemeral = encode_ephemeral_public(r_point)
    shared_point = ecc.ecdh_point(r_bytes, public_key)
    key_e, key_m = _derive_keys(shared_point)
    padded = Padding.pad(plaintext, 16)
    cipher = AES.new(key_e, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded)
    mac = hmac_sha256(key_m, iv + ephemeral + ciphertext)
    return iv + ephemeral + ciphertext + mac


def decrypt(payload, private):
    if len(payload) < IV_LEN + R_LEN + MAC_LEN + 16:
        raise ValueError('encrypted payload too short')
    iv = payload[:IV_LEN]
    ephemeral = payload[IV_LEN:IV_LEN + R_LEN]
    ciphertext = payload[IV_LEN + R_LEN:-MAC_LEN]
    mac = payload[-MAC_LEN:]
    r_point = decode_ephemeral_public(ephemeral)
    shared_point = ecc.ecdh_point(private, r_point)
    key_e, key_m = _derive_keys(shared_point)
    expected = hmac_sha256(key_m, iv + ephemeral + ciphertext)
    if not hmac.compare_digest(expected, mac):
        raise ValueError('MAC verification failed')
    cipher = AES.new(key_e, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    return Padding.unpad(padded, 16)
