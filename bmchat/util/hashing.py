import hashlib
import hmac

from Crypto.Hash import RIPEMD160


def sha512(data):
    return hashlib.sha512(data).digest()


def sha256(data):
    return hashlib.sha256(data).digest()


def double_sha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def double_sha512(data):
    return hashlib.sha512(hashlib.sha512(data).digest()).digest()


def sha512_obj():
    return hashlib.sha512()


def ripemd160(data):
    h = RIPEMD160.new()
    h.update(data)
    return h.digest()


def hmac_sha256(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def sha512_hash_id(data):
    return double_sha512(data)[0:32]