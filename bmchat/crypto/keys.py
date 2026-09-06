import os

from ..util import (
    encode_varint, double_sha512, sha512, ripemd160, encode_base58, decode_base58,
    double_sha256,
)
from ..protocol.address import encode_address, decode_address
from . import ecc


class AddressKeys:
    __slots__ = (
        'version', 'stream', 'ripe', 'address', 'signing_private',
        'encryption_private', 'signing_public', 'encryption_public',
        'tag', 'encryption_private_from_address',
        'nonce_trials_per_byte', 'payload_length_extra_bytes',
    )

    def __init__(self):
        self.version = 4
        self.stream = 1
        self.ripe = None
        self.address = None
        self.signing_private = None
        self.encryption_private = None
        self.signing_public = None
        self.encryption_public = None
        self.tag = None
        self.encryption_private_from_address = None
        self.nonce_trials_per_byte = 1000
        self.payload_length_extra_bytes = 1000

    @classmethod
    def from_private_keys(cls, signing_private, encryption_private, stream=1):
        obj = cls()
        obj.version = 4
        obj.stream = stream
        obj.signing_private = signing_private
        obj.encryption_private = encryption_private
        obj.signing_public = ecc.point_mult(signing_private)
        obj.encryption_public = ecc.point_mult(encryption_private)
        obj.ripe = ripe_of(obj.signing_public, obj.encryption_public)
        obj.address = encode_address(4, stream, obj.ripe)
        obj.tag = tag_of(4, stream, obj.ripe)
        return obj

    @classmethod
    def from_address(cls, address):
        status, version, stream, ripe = decode_address(address)
        if status != 'success' or version != 4:
            raise ValueError('somente endereços versão 4 são suportados')
        obj = cls()
        obj.version = version
        obj.stream = stream
        obj.ripe = ripe
        obj.address = address
        obj.tag = tag_of(version, stream, ripe)
        obj.encryption_private_from_address = address_encryption_private(
            version, stream, ripe)
        return obj

    def public_encryption_point(self):
        return ecc.decode_point_public(self.encryption_public)


def ripe_of(public_signing, public_encryption):
    return ripemd160(sha512(public_signing + public_encryption))


def tag_of(version, stream, ripe):
    return double_sha512(
        encode_varint(version) + encode_varint(stream) + ripe)[32:]


def address_encryption_private(version, stream, ripe):
    return double_sha512(
        encode_varint(version) + encode_varint(stream) + ripe)[:32]


def chan_keys_from_name(name, stream=1):
    passphrase = name.encode('utf-8')
    signing_nonce, encryption_nonce = 0, 1
    while True:
        signing_private = sha512(
            passphrase + encode_varint(signing_nonce))[:32]
        encryption_private = sha512(
            passphrase + encode_varint(encryption_nonce))[:32]
        signing_public = ecc.point_mult(signing_private)
        encryption_public = ecc.point_mult(encryption_private)
        if ripe_of(signing_public, encryption_public)[:1] == b'\x00':
            return AddressKeys.from_private_keys(
                signing_private, encryption_private, stream)
        signing_nonce += 2
        encryption_nonce += 2


def generate_keys(stream=1, nullprefix=1):
    if nullprefix < 0 or nullprefix > 20:
        raise ValueError('nullprefix inválido')
    target = b'\x00' * nullprefix
    while True:
        signing_private = os.urandom(32)
        encryption_private = os.urandom(32)
        signing_public = ecc.point_mult(signing_private)
        encryption_public = ecc.point_mult(encryption_private)
        ripe = ripe_of(signing_public, encryption_public)
        if ripe.startswith(target):
            result = AddressKeys.from_private_keys(
                signing_private, encryption_private, stream)
            if encode_address(4, stream, ripe) == result.address:
                return result


def wif_encode(private):
    data = b'\x80' + private
    return encode_base58(data + double_sha256(data)[:4])


def wif_decode(wif):
    raw = decode_base58(wif)
    if len(raw) != 37 or raw[0] != 0x80:
        raise ValueError('WIF inválido')
    payload, checksum = raw[:-4], raw[-4:]
    if double_sha256(payload)[:4] != checksum:
        raise ValueError('WIF checksum inválido')
    return raw[1:-4]