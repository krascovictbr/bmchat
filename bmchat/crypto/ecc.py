import hashlib
import secrets

from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point
from ecdsa.util import (
    sigdecode_der, sigdecode_string, sigencode_der,
)

CURVE = SECP256k1.curve
GENERATOR = SECP256k1.generator
ORDER = SECP256k1.order
ORDER_BYTES = ORDER.to_bytes(32, 'big')


def int_to_32(value):
    return value.to_bytes(32, 'big')


def random_private_key():
    while True:
        candidate = secrets.randbelow(ORDER)
        if 1 <= candidate < ORDER:
            return candidate


def point_mult(secret):
    if len(secret) != 32:
        raise ValueError('chave privada deve ter 32 bytes')
    value = int.from_bytes(secret, 'big')
    if not 1 <= value < ORDER:
        raise ValueError('chave privada fora do intervalo')
    point = GENERATOR * value
    return encode_point_public(point)


def encode_point_public(point):
    return b'\x04' + point.x().to_bytes(32, 'big') + point.y().to_bytes(32, 'big')


def decode_point_public(pub):
    if len(pub) != 65 or pub[0] != 4:
        raise ValueError('invalid uncompressed public key')
    point = Point(
        CURVE,
        int.from_bytes(pub[1:33], 'big'),
        int.from_bytes(pub[33:65], 'big'))
    try:
        if not CURVE.contains_point(point.x(), point.y()):
            raise ValueError('ponto fora da curva')
    except Exception as exc:
        raise ValueError('ponto inválido: %s' % exc)
    return point


def point_from_secret(secret):
    if len(secret) != 32:
        raise ValueError('chave privada deve ter 32 bytes')
    value = int.from_bytes(secret, 'big')
    if not 1 <= value < ORDER:
        raise ValueError('chave privada fora do intervalo')
    return GENERATOR * value


def ecdh_point(private, point):
    if isinstance(point, bytes):
        point = decode_point_public(point)
    if len(private) != 32:
        raise ValueError('chave privada deve ter 32 bytes')
    scalar = int.from_bytes(private, 'big')
    if not 1 <= scalar < ORDER:
        raise ValueError('chave privada fora do intervalo')
    result = point * scalar
    return result


def ecdh_x(private, point):
    return ecdh_point(private, point).x().to_bytes(32, 'big')


def sign_data(private, data):
    from ecdsa import SigningKey
    sk = SigningKey.from_secret_exponent(
        int.from_bytes(private, 'big'), curve=SECP256k1)
    # DER, como o OpenSSL do PyBitmessage: é o único formato que a rede aceita
    signature = sk.sign(
        data, hashfunc=hashlib.sha256, sigencode=sigencode_der)
    return signature


def verify_signature(public, signature, data):
    from ecdsa import VerifyingKey
    if isinstance(public, bytes) and len(public) == 65 and \
            public[:1] == b'\x04':
        public = public[1:]
    if len(signature) < 64:
        return False
    try:
        vk = VerifyingKey.from_string(public, curve=SECP256k1)
    except Exception:
        return False
    # DER primeiro (formato da rede); raw-64 como reserva
    for decoder in (sigdecode_der, sigdecode_string):
        try:
            if vk.verify(signature, data, hashfunc=hashlib.sha256,
                         sigdecode=decoder):
                return True
        except Exception:
            continue
    return False
