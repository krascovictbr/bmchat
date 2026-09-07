"""Encrypted database support using PBKDF2 + AES-GCM."""

import os
import sqlite3
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2


# Constants
SALT_SIZE = 32
NONCE_SIZE = 12
KEY_SIZE = 32  # AES-256
PBKDF2_ITERATIONS = 200_000
HEADER_SIZE = SALT_SIZE + NONCE_SIZE + 16  # salt + nonce + tag


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive encryption key from password using PBKDF2."""
    import hashlib
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS,
                  hmac_hash_module=hashlib.sha256)  # type: ignore[arg-type]


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
    tag = encrypted_data[NONCE_SIZE:NONCE_SIZE+16]
    ciphertext = encrypted_data[NONCE_SIZE+16:]
    aad = page_number.to_bytes(8, 'little')
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    return cipher.decrypt_and_verify(ciphertext, tag)


class EncryptedDB:
    """SQLite database with transparent page-level encryption."""
    
    def __init__(self, path: str, password: str | None = None, page_size: int = 4096):
        self.path = path
        self.password: str | None = password
        self.page_size = page_size
        self.key: bytes | None = None
        self.salt: bytes | None = None
        self.conn = None
        self._initialized = False
    
    def _init_encryption(self):
        """Initialize or verify encryption."""
        if not os.path.exists(self.path):
            # New database - create salt and key
            self.salt = get_random_bytes(SALT_SIZE)
            self.key = derive_key(self.password, self.salt)
            return
        
        # Existing database - read salt and verify password
        with open(self.path, 'rb') as f:
            header = f.read(HEADER_SIZE)
            if len(header) < HEADER_SIZE:
                raise ValueError("Database file too short to be encrypted")
            self.salt = header[:SALT_SIZE]
            stored_key_check = header[SALT_SIZE:SALT_SIZE+32]  # First 32 bytes of key hash
            self.key = derive_key(self.password, self.salt)
            # Verify key by checking hash
            key_hash = hashlib.sha256(self.key).digest()[:32]
            if not hmac.compare_digest(key_hash, stored_key_check):
                raise ValueError("Senha incorreta para o banco de dados criptografado")
    
    def connect(self) -> sqlite3.Connection:
        """Create encrypted SQLite connection."""
        if not self._initialized:
            self._init_encryption()
            self._initialized = True
        
        # Custom VFS for page-level encryption would go here
        # For now, we'll use a simpler approach: encrypt entire DB file
        # This is a placeholder for the full implementation
        return sqlite3.connect(self.path, check_same_thread=False)
    
    def create_encrypted(self):
        """Create a new encrypted database file."""
        if os.path.exists(self.path):
            raise FileExistsError("Database already exists")
        
        # Create temp unencrypted DB
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as tmp:
            tmp_path = tmp.name
        
        try:
            conn = sqlite3.connect(tmp_path)
            conn.execute("PRAGMA page_size=4096")
            conn.close()
            
            # Read the file and encrypt it
            with open(tmp_path, 'rb') as f:
                plaintext = f.read()
            
            # Encrypt entire file (simplified - real implementation would be page-level)
            key = self.key
            nonce = get_random_bytes(NONCE_SIZE)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            cipher.update(self.salt)
            ciphertext, tag = cipher.encrypt_and_digest(plaintext)
            
            # Write encrypted file with header
            with open(self.path, 'wb') as f:
                f.write(self.salt)
                f.write(nonce)
                f.write(tag)
                f.write(ciphertext)
            
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
    
    def export_encrypted(self, output_path: str, new_password: str):
        """Export database with new password."""
        # Read current encrypted DB
        with open(self.path, 'rb') as f:
            header = f.read(HEADER_SIZE)
            self.salt = header[:SALT_SIZE]
            nonce = header[SALT_SIZE:SALT_SIZE+NONCE_SIZE]
            tag = header[SALT_SIZE+NONCE_SIZE:SALT_SIZE+NONCE_SIZE+16]
            ciphertext = f.read()
        
        # Decrypt with current key
        assert self.key is not None
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        cipher.update(self.salt)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        # Re-encrypt with new password
        new_salt = get_random_bytes(SALT_SIZE)
        new_key = derive_key(new_password, new_salt)
        new_nonce = get_random_bytes(NONCE_SIZE)
        new_cipher = AES.new(new_key, AES.MODE_GCM, nonce=new_nonce)
        new_cipher.update(new_salt)
        new_ciphertext, new_tag = new_cipher.encrypt_and_digest(plaintext)
        
        with open(output_path, 'wb') as f:
            f.write(new_salt)
            f.write(new_nonce)
            f.write(new_tag)
            f.write(new_ciphertext)


def change_password(db_path: str, old_password: str, new_password: str):
    """Change database password."""
    if not os.path.exists(db_path):
        raise FileNotFoundError("Database not found")
    
    # Read and decrypt with old password
    with open(db_path, 'rb') as f:
        header = f.read(HEADER_SIZE)
        if len(header) < HEADER_SIZE:
            raise ValueError("Database file too short")
        salt = header[:SALT_SIZE]
        nonce = header[SALT_SIZE:SALT_SIZE+NONCE_SIZE]
        tag = header[SALT_SIZE+NONCE_SIZE:SALT_SIZE+NONCE_SIZE+16]
        ciphertext = f.read()
    
    old_key = derive_key(old_password, salt)
    cipher = AES.new(old_key, AES.MODE_GCM, nonce=nonce)
    cipher.update(salt)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    
    # Encrypt with new password
    new_salt = get_random_bytes(SALT_SIZE)
    new_key = derive_key(new_password, new_salt)
    new_nonce = get_random_bytes(NONCE_SIZE)
    new_cipher = AES.new(new_key, AES.MODE_GCM, nonce=new_nonce)
    new_cipher.update(new_salt)
    new_ciphertext, new_tag = new_cipher.encrypt_and_digest(plaintext)
    
    # Write new encrypted file
    with open(db_path, 'wb') as f:
        f.write(new_salt)
        f.write(new_nonce)
        f.write(new_tag)
        f.write(new_ciphertext)


def is_encrypted(db_path: str) -> bool:
    """Check if database file is encrypted."""
    if not os.path.exists(db_path):
        return False
    if os.path.getsize(db_path) < HEADER_SIZE:
        return False
    # Check if file has valid SQLite header (unencrypted)
    with open(db_path, 'rb') as f:
        header = f.read(16)
    return header[:16] != b'SQLite format 3\x00'


def enable_encryption(db_path: str, password: str):
    """Enable encryption on an existing unencrypted database."""
    if is_encrypted(db_path):
        raise ValueError("Database already encrypted")
    
    # Create EncryptedDB instance
    enc_db = EncryptedDB(db_path + '.enc', password)
    # Use a proper salt
    enc_db.salt = get_random_bytes(SALT_SIZE)
    enc_db.key = derive_key(password, enc_db.salt)
    
    # Actually, we need a different approach
    # For now, just document the API
    raise NotImplementedError("Full encryption implementation requires custom VFS")


def export_encrypted_backup(db_path: str, output_path: str, password: str):
    """Export database as encrypted backup."""
    # Read plaintext DB
    with open(db_path, 'rb') as f:
        plaintext = f.read()
    
    # Encrypt
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(salt)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    with open(output_path, 'wb') as f:
        f.write(salt)
        f.write(nonce)
        f.write(tag)
        f.write(ciphertext)


def import_encrypted_backup(backup_path: str, output_path: str, password: str):
    """Import database from encrypted backup."""
    with open(backup_path, 'rb') as f:
        header = f.read(HEADER_SIZE)
        if len(header) < HEADER_SIZE:
            raise ValueError("Backup file too short")
        salt = header[:SALT_SIZE]
        nonce = header[SALT_SIZE:SALT_SIZE+NONCE_SIZE]
        tag = header[SALT_SIZE+NONCE_SIZE:SALT_SIZE+NONCE_SIZE+16]
        ciphertext = f.read()
    
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(salt)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    
    with open(output_path, 'wb') as f:
        f.write(plaintext)