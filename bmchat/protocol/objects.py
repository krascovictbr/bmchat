import struct

from ..util import (
    encode_varint, decode_varint, double_sha512,
)
from ..crypto import ecc, ecies
from .const import (
    OBJECT_GETPUBKEY, OBJECT_PUBKEY, OBJECT_MSG, OBJECT_BROADCAST,
    BITFIELD_DOESACK,
)


class ParsedObject:
    __slots__ = ('raw', 'nonce', 'expires', 'object_type', 'version', 'stream',
                 'data', 'inventory_hash')

    def __init__(self, raw):
        if len(raw) < 20:
            raise ValueError('objeto curto demais')
        self.raw = raw
        self.nonce = raw[:8]
        self.expires = struct.unpack('>Q', raw[8:16])[0]
        self.object_type = struct.unpack('>I', raw[16:20])[0]
        position = 20
        self.version, version_len = decode_varint(raw[20:29])
        position += version_len
        self.stream, stream_len = decode_varint(raw[position:position + 9])
        position += stream_len
        self.data = raw[position:]
        self.inventory_hash = double_sha512(raw)[:32]


def assemble_object_unsigned(expires, object_type, version, stream, data):
    return (
        struct.pack('>Q', expires)
        + struct.pack('>I', object_type)
        + encode_varint(version)
        + encode_varint(stream)
        + data
    )


def complete_object(unsigned, nonce):
    return nonce.to_bytes(8, 'big') + unsigned


def build_ack_unsigned(expires, watch_data, stream=1):
    return (
        struct.pack('>Q', expires)
        + struct.pack('>I', OBJECT_MSG)
        + encode_varint(1)
        + encode_varint(stream)
        + watch_data
    )


def ack_watch_key(ack_object):
    return ack_object[16:]


def bitfield(bitfield_value=None):
    if bitfield_value is None:
        bitfield_value = BITFIELD_DOESACK
    return struct.pack('>I', bitfield_value)


def build_getpubkey_unsigned(expires, stream, version, tag_or_ripe):
    return assemble_object_unsigned(
        expires, OBJECT_GETPUBKEY, version, stream, tag_or_ripe)


def build_pubkey_unsigned(expires, stream, identity, bitfield_value=None):
    doublehash = double_sha512(
        encode_varint(4) + encode_varint(stream) + identity.ripe)
    private_encryption = doublehash[:32]
    tag = doublehash[32:]
    plain = bitfield(bitfield_value)
    plain += identity.signing_public[1:]
    plain += identity.encryption_public[1:]
    plain += encode_varint(_ntpb_of(identity)) + encode_varint(_eb_of(identity))
    unsigned = assemble_object_unsigned(
        expires, OBJECT_PUBKEY, 4, stream, tag)
    signed_data = unsigned + plain
    signature = ecc.sign_data(identity.signing_private, signed_data)
    plain += encode_varint(len(signature)) + signature
    encryption_point = ecc.encode_point_public(
        ecc.point_from_secret(private_encryption))
    encrypted = ecies.encrypt(plain, encryption_point)
    return unsigned + encrypted


def build_msg_unsigned(expires, stream, identity, recipient_encryption_public,
                       recipient_ripe, message, encoding,
                       ack_packet=b'', bitfield_value=None):
    plain = encode_varint(4) + encode_varint(stream)
    plain += bitfield(bitfield_value)
    plain += identity.signing_public[1:]
    plain += identity.encryption_public[1:]
    plain += encode_varint(_ntpb_of(identity)) + encode_varint(_eb_of(identity))
    plain += recipient_ripe
    plain += encode_varint(encoding)
    plain += encode_varint(len(message)) + message
    plain += encode_varint(len(ack_packet)) + ack_packet
    unsigned = assemble_object_unsigned(expires, OBJECT_MSG, 1, stream, b'')
    signed_data = (
        unsigned + plain
    )
    signature = ecc.sign_data(identity.signing_private, signed_data)
    plain += encode_varint(len(signature)) + signature
    encrypted = ecies.encrypt(plain, recipient_encryption_public)
    return assemble_object_unsigned(
        expires, OBJECT_MSG, 1, stream, encrypted)


def build_broadcast_unsigned(expires, stream, identity, message, encoding,
                             bitfield_value=None):
    doublehash = double_sha512(
        encode_varint(4) + encode_varint(stream) + identity.ripe)
    private_encryption = doublehash[:32]
    tag = doublehash[32:]
    plain = encode_varint(4) + encode_varint(stream)
    plain += bitfield(bitfield_value)
    plain += identity.signing_public[1:]
    plain += identity.encryption_public[1:]
    plain += encode_varint(_ntpb_of(identity)) + encode_varint(_eb_of(identity))
    plain += encode_varint(encoding)
    plain += encode_varint(len(message)) + message
    unsigned = assemble_object_unsigned(
        expires, OBJECT_BROADCAST, 5, stream, tag)
    signed_data = unsigned + plain
    signature = ecc.sign_data(identity.signing_private, signed_data)
    plain += encode_varint(len(signature)) + signature
    encryption_point = ecc.encode_point_public(
        ecc.point_from_secret(private_encryption))
    encrypted = ecies.encrypt(plain, encryption_point)
    return unsigned + encrypted


def _ntpb_of(identity):
    return getattr(identity, 'nonce_trials_per_byte', None) or 1000


def _eb_of(identity):
    return getattr(identity, 'payload_length_extra_bytes', None) or 1000


class IncomingMessage:
    __slots__ = (
        'raw', 'inventory_hash', 'to_identity', 'sender_version',
        'sender_stream', 'sender_signing_public', 'sender_encryption_public',
        'sender_address', 'encoding', 'message', 'ack_data', 'expires',
    )


def process_msg(raw, identities):
    obj = ParsedObject(raw)
    if obj.object_type != OBJECT_MSG or obj.version != 1:
        return None
    for identity in identities:
        try:
            plain = ecies.decrypt(obj.data, identity.encryption_private)
        except Exception:
            continue
        result = _parse_msg_plaintext(plain, obj, identity)
        if result is not None:
            return result
    return None


def _parse_msg_plaintext(plain, obj, identity):
    position = 0
    sender_version, position = _take_varint(plain, position)
    if sender_version == 0 or sender_version > 4:
        return None
    sender_stream, position = _take_varint(plain, position)
    if sender_stream == 0:
        return None
    if len(plain) < position + 4:
        return None
    position += 4
    if len(plain) < position + 128:
        return None
    pub_signing = b'\x04' + plain[position:position + 64]
    position += 64
    pub_encryption = b'\x04' + plain[position:position + 64]
    position += 64
    if sender_version >= 3:
        ntpb, position = _take_varint(plain, position)
        eb, position = _take_varint(plain, position)
        if ntpb < 1000 or eb < 1000 or ntpb > 1000000 or eb > 1000000:
            return None
    if len(plain) < position + 20:
        return None
    to_ripe = plain[position:position + 20]
    position += 20
    if to_ripe != identity.ripe:
        return None
    encoding, position = _take_varint(plain, position)
    message_length, position = _take_varint(plain, position)
    message = plain[position:position + message_length]
    position += message_length
    ack_length, position = _take_varint(plain, position)
    ack_data = plain[position:position + ack_length]
    position += ack_length
    bottom_of_ack = position
    signature_length, position = _take_varint(plain, position)
    signature = plain[position:position + signature_length]
    signed_data = (
        struct.pack('>Q', obj.expires)
        + struct.pack('>I', obj.object_type)
        + encode_varint(1)
        + encode_varint(obj.stream)
        + plain[:bottom_of_ack]
    )
    if not ecc.verify_signature(pub_signing, signature, signed_data):
        return None
    item = IncomingMessage()
    item.raw = obj.raw
    item.inventory_hash = obj.inventory_hash
    item.to_identity = identity
    item.sender_version = sender_version
    item.sender_stream = sender_stream
    item.sender_signing_public = pub_signing
    item.sender_encryption_public = pub_encryption
    item.sender_address = _address_from_pubkeys(
        sender_version, sender_stream, pub_signing, pub_encryption)
    item.encoding = encoding
    item.message = message
    item.ack_data = ack_data
    item.expires = obj.expires
    return item


class IncomingPubkey:
    __slots__ = ('address', 'signing_public', 'encryption_public',
                 'nonce_trials_per_byte', 'payload_length_extra_bytes',
                 'inventory_hash', 'expires')


def process_pubkey(raw, address_keys):
    obj = ParsedObject(raw)
    if obj.object_type != OBJECT_PUBKEY or obj.version != 4:
        return None
    if len(obj.data) < 32 + ecies.IV_LEN + ecies.R_LEN + ecies.MAC_LEN + 16:
        return None
    tag = obj.data[:32]
    if tag != address_keys.tag:
        return None
    position = 20
    position += len(encode_varint(obj.version))
    position += len(encode_varint(obj.stream))
    signed_so_far = raw[8:position + 32]
    encrypted = obj.data[32:]
    try:
        plain = ecies.decrypt(
            encrypted, address_keys.encryption_private_from_address)
    except Exception:
        return None
    pos = 0
    pos += 4
    pub_signing = b'\x04' + plain[pos:pos + 64]
    pos += 64
    pub_encryption = b'\x04' + plain[pos:pos + 64]
    pos += 64
    ntpb, pos = _take_varint(plain, pos)
    eb, pos = _take_varint(plain, pos)
    end_extra_bytes = pos
    signature_length, pos = _take_varint(plain, pos)
    signature = plain[pos:pos + signature_length]
    signed_data = signed_so_far + plain[:end_extra_bytes]
    if not ecc.verify_signature(pub_signing, signature, signed_data):
        return None
    computed_ripe = _ripe_of(pub_signing, pub_encryption)
    if computed_ripe != address_keys.ripe:
        return None
    item = IncomingPubkey()
    item.address = address_keys.address
    item.signing_public = pub_signing
    item.encryption_public = pub_encryption
    item.nonce_trials_per_byte = max(ntpb, 1000)
    item.payload_length_extra_bytes = max(eb, 1000)
    item.inventory_hash = obj.inventory_hash
    item.expires = obj.expires
    return item


class IncomingBroadcast:
    __slots__ = ('raw', 'inventory_hash', 'address', 'encoding', 'message',
                 'expires', 'sender_version', 'sender_stream')


def process_broadcast(raw, subscriptions):
    obj = ParsedObject(raw)
    if obj.object_type != OBJECT_BROADCAST:
        return None
    if obj.version != 5:
        return None
    if len(obj.data) < 32:
        return None
    tag = obj.data[:32]
    address_keys = subscriptions.get(tag)
    if address_keys is None:
        return None
    try:
        plain = ecies.decrypt(
            obj.data[32:], address_keys.encryption_private_from_address)
    except Exception:
        return None
    position = 0
    sender_version, position = _take_varint(plain, position)
    if sender_version < 4:
        return None
    sender_stream, position = _take_varint(plain, position)
    position += 4
    pub_signing = b'\x04' + plain[position:position + 64]
    position += 64
    pub_encryption = b'\x04' + plain[position:position + 64]
    position += 64
    ntpb, position = _take_varint(plain, position)
    eb, position = _take_varint(plain, position)
    encoding, position = _take_varint(plain, position)
    if encoding == 0:
        return None
    message_length, position = _take_varint(plain, position)
    message = plain[position:position + message_length]
    position += message_length
    bottom_of_message = position
    signature_length, position = _take_varint(plain, position)
    signature = plain[position:position + signature_length]
    signed_data = (
        struct.pack('>Q', obj.expires)
        + struct.pack('>I', obj.object_type)
        + encode_varint(5)
        + encode_varint(obj.stream)
        + tag
        + plain[:bottom_of_message]
    )
    if not ecc.verify_signature(pub_signing, signature, signed_data):
        return None
    computed_ripe = _ripe_of(pub_signing, pub_encryption)
    computed_tag = _tag_of(sender_version, sender_stream, computed_ripe)
    if computed_tag != tag:
        return None
    item = IncomingBroadcast()
    item.raw = raw
    item.inventory_hash = obj.inventory_hash
    item.address = _address_from_pubkeys(
        sender_version, sender_stream, pub_signing, pub_encryption)
    item.encoding = encoding
    item.message = message
    item.expires = obj.expires
    item.sender_version = sender_version
    item.sender_stream = sender_stream
    return item


def _take_varint(blob, position):
    try:
        value, length = decode_varint(blob[position:position + 10])
    except Exception:
        return 0, position
    return value, position + length


def _address_from_pubkeys(version, stream, pub_signing, pub_encryption):
    from .address import encode_address
    return encode_address(version, stream, _ripe_of(pub_signing, pub_encryption))


def _ripe_of(pub_signing, pub_encryption):
    from ..crypto.keys import ripe_of
    return ripe_of(pub_signing, pub_encryption)


def _tag_of(version, stream, ripe):
    from ..crypto.keys import tag_of
    return tag_of(version, stream, ripe)
