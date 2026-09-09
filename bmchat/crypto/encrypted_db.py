"""Backup criptografado com PBKDF2 + AES-GCM (export/import/change).

Nota de arquitetura (C5): o banco de dados em uso (``bmchat.db``)
permanece EM CLARO em repouso, protegido apenas por permissões do
sistema de arquivos (diretório ``0700``/arquivo ``0600`` criados em
``core/database.py`` e ``run.py``). Não há criptografia transparente
em nível de página/VFS. A classe ``EncryptedDB`` anterior era um
placeholder quebrado (``connect()`` devolvia sqlite em claro,
``header[32:64]`` sobre header de 60B, ``enable_encryption`` com
``NotImplementedError`` e nenhum importador) e foi REMOVIDA. O que
existe de funcional é backup ``.enc`` autocontido
(salt+nonce+tag+ciphertext) via as funções abaixo.
"""

import os
import tempfile

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2


# Constants
SALT_SIZE = 32
NONCE_SIZE = 12
KEY_SIZE = 32  # AES-256
PBKDF2_ITERATIONS = 200_000
HEADER_SIZE = SALT_SIZE + NONCE_SIZE + 16  # salt + nonce + tag


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive encryption key from password using PBKDF2-HMAC-SHA256."""
    if not isinstance(salt, (bytes, bytearray)) or len(salt) != SALT_SIZE:
        raise ValueError("salt inválido")
    if isinstance(password, str):
        # ADV: Crypto PBKDF2 faz encode latin-1 interno e quebra com
        # emoji/acentos (UnicodeEncodeError). Normaliza para UTF-8 aqui
        # para senhas unicode funcionarem (ASCII inalterado).
        password_bytes = password.encode('utf-8')
    else:
        password_bytes = bytes(password)
    return PBKDF2(password_bytes, bytes(salt), dkLen=KEY_SIZE,  # type: ignore[arg-type]
                  count=PBKDF2_ITERATIONS,
                  hmac_hash_module=SHA256)


def encrypt_page(key: bytes, page_data: bytes, page_number: int) -> bytes:
    """Encrypt a single database page using AES-GCM."""
    nonce = get_random_bytes(NONCE_SIZE)
    # Use page number as additional authenticated data
    aad = page_number.to_bytes(8, 'little')

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(page_data)

    return nonce + tag + ciphertext


def decrypt_page(key: bytes, encrypted_data: bytes, page_number: int) -> bytes:
    """Decrypt a single database page using AES-GCM."""
    if len(encrypted_data) < NONCE_SIZE + 16:
        raise ValueError("Encrypted data too short")

    nonce = encrypted_data[:NONCE_SIZE]
    tag = encrypted_data[NONCE_SIZE:NONCE_SIZE + 16]
    ciphertext = encrypted_data[NONCE_SIZE + 16:]
    aad = page_number.to_bytes(8, 'little')

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    return cipher.decrypt_and_verify(ciphertext, tag)


def _secret_write_bytes(path: str, data: bytes) -> None:
    """Write bytes atomically with mode 0600 (tmp+fsync+os.replace)."""
    directory = os.path.dirname(os.path.abspath(path)) or '.'
    fd = None
    tmp_path = ''
    try:
        fd, tmp_path = tempfile.mkstemp(
            dir=directory, prefix='.tmp-enc-')
        try:
            os.fchmod(fd, 0o600)
        except Exception:
            pass
        with os.fdopen(fd, 'wb') as handle:
            fd = None
            handle.write(data)
            try:
                handle.flush()
                os.fsync(handle.fileno())
            except Exception:
                pass
        try:
            os.chmod(tmp_path, 0o600)
        except Exception:
            pass
        os.replace(tmp_path, path)
        tmp_path = ''
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass


def _read_backup_blob(path: str) -> tuple:
    """Read (salt, nonce, tag, ciphertext) or raise ValueError."""
    with open(path, 'rb') as handle:
        header = handle.read(HEADER_SIZE)
        if len(header) < HEADER_SIZE:
            raise ValueError("Backup file too short")
        salt = header[:SALT_SIZE]
        nonce = header[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
        tag = header[SALT_SIZE + NONCE_SIZE:SALT_SIZE + NONCE_SIZE + 16]
        ciphertext = handle.read()
    return salt, nonce, tag, ciphertext


def _seal(plaintext: bytes, password: str) -> bytes:
    """Encrypt plaintext bytes into salt+nonce+tag+ciphertext blob."""
    if not password or len(password) < 8:
        raise ValueError("senha deve ter ao menos 8 caracteres")
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(salt)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return salt + nonce + tag + ciphertext


def _open(blob: bytes, password: str) -> bytes:
    """Decrypt a salt+nonce+tag+ciphertext blob."""
    if len(blob) < HEADER_SIZE:
        raise ValueError("Backup file too short")
    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    tag = blob[SALT_SIZE + NONCE_SIZE:SALT_SIZE + NONCE_SIZE + 16]
    ciphertext = blob[HEADER_SIZE:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(salt)
    return cipher.decrypt_and_verify(ciphertext, tag)


def _backup_original(db_path: str) -> None:
    try:
        with open(db_path, 'rb') as src:
            original = src.read()
        _secret_write_bytes(db_path + '.bak', original)
    except Exception:
        pass


def change_password(db_path: str, old_password: str, new_password: str):
    """Change database password (atômico: tmp+fsync+replace, .bak)."""
    if not os.path.exists(db_path):
        raise FileNotFoundError("Database not found")
    if not new_password or len(new_password) < 8:
        raise ValueError("nova senha deve ter ao menos 8 caracteres")
    salt, nonce, tag, ciphertext = _read_backup_blob(db_path)
    old_key = derive_key(old_password, salt)
    cipher = AES.new(old_key, AES.MODE_GCM, nonce=nonce)
    cipher.update(salt)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    blob = _seal(bytes(plaintext), new_password)
    _backup_original(db_path)
    _secret_write_bytes(db_path, blob)


def is_encrypted(db_path: str) -> bool:
    """Check if database file is encrypted."""
    if not os.path.exists(db_path):
        return False
    if os.path.getsize(db_path) < HEADER_SIZE:
        return False
    # Check if file has valid SQLite header (unencrypted)
    with open(db_path, 'rb') as handle:
        header = handle.read(16)
    return header[:16] != b'SQLite format 3\x00'


def export_encrypted_backup(db_path: str, output_path: str, password: str):
    """Export database as encrypted backup (atômico, 0600)."""
    with open(db_path, 'rb') as handle:
        plaintext = handle.read()
    blob = _seal(plaintext, password)
    _secret_write_bytes(output_path, blob)


def import_encrypted_backup(backup_path: str, output_path: str,
                            password: str):
    """Import database from encrypted backup (atômico, 0600).

    Grava em arquivo temporário no mesmo diretório e troca com
    ``os.replace``; o temporário é removido em ``finally`` mesmo se
    a descriptografia falhar, sem deixar plaintext em claro para trás.
    Se ``output_path`` já existir, um ``.bak`` é preservado antes.
    """
    with open(backup_path, 'rb') as handle:
        blob = handle.read()
    plaintext = _open(blob, password)
    if os.path.exists(output_path):
        try:
            with open(output_path, 'rb') as src:
                original = src.read()
            _secret_write_bytes(output_path + '.bak', original)
        except Exception:
            pass
    _secret_write_bytes(output_path, bytes(plaintext))
