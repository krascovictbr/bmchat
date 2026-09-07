import json
import os
import sqlite3
import threading
import time


class Database:

    def __init__(self, data_dir):
        os.makedirs(data_dir, mode=0o700, exist_ok=True)
        try:
            os.chmod(data_dir, 0o700)
        except Exception:
            pass
        self.path = os.path.join(data_dir, 'bmchat.db')
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        self._create_schema()

    def _create_schema(self):
        with self.lock:
            self.conn.executescript('''
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS identities (
    address TEXT PRIMARY KEY,
    label TEXT,
    stream INTEGER DEFAULT 1,
    enabled INTEGER DEFAULT 1,
    priv_signing BLOB,
    priv_encryption BLOB,
    noncetrials INTEGER DEFAULT 1000,
    extrabytes INTEGER DEFAULT 1000,
    created INTEGER,
    chan INTEGER DEFAULT 0,
    chan_label TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS contacts (
    address TEXT PRIMARY KEY,
    label TEXT,
    stream INTEGER DEFAULT 1,
    added INTEGER
);
CREATE TABLE IF NOT EXISTS subscriptions (
    address TEXT PRIMARY KEY,
    label TEXT,
    added INTEGER,
    name TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    obj_hash BLOB,
    from_address TEXT,
    to_address TEXT,
    subject TEXT,
    body TEXT,
    encoding INTEGER,
    timestamp INTEGER,
    direction TEXT,
    status TEXT,
    target_stream INTEGER
);
CREATE TABLE IF NOT EXISTS objects (
    hash BLOB PRIMARY KEY,
    raw BLOB,
    type INTEGER,
    version INTEGER,
    stream INTEGER,
    expires INTEGER,
    received INTEGER
);
CREATE TABLE IF NOT EXISTS pubkeys (
    address TEXT PRIMARY KEY,
    signing_public BLOB,
    encryption_public BLOB,
    noncetrials INTEGER DEFAULT 1000,
    extrabytes INTEGER DEFAULT 1000,
    received INTEGER
);
CREATE INDEX IF NOT EXISTS idx_messages_from ON messages(from_address);
CREATE INDEX IF NOT EXISTS idx_messages_to ON messages(to_address);
CREATE INDEX IF NOT EXISTS idx_messages_status ON messages(status, direction);
CREATE INDEX IF NOT EXISTS idx_messages_ts ON messages(timestamp);
CREATE INDEX IF NOT EXISTS idx_objects_type ON objects(type);
CREATE INDEX IF NOT EXISTS idx_objects_expires ON objects(expires);
CREATE INDEX IF NOT EXISTS idx_objects_type_ver_exp ON objects(type, version, expires);
CREATE UNIQUE INDEX IF NOT EXISTS idx_msg_hash ON messages(obj_hash) WHERE obj_hash IS NOT NULL;
''')
            self.conn.commit()
        self._migrate_message_timestamps()

    def _migrate_message_timestamps(self):
        now = int(time.time())
        future = now + 3600
        with self.lock:
            self.conn.execute('''
                UPDATE messages SET timestamp = (
                    SELECT received FROM objects
                    WHERE objects.hash = messages.obj_hash)
                WHERE direction='in' AND obj_hash IS NOT NULL
                    AND timestamp > ?
                    AND EXISTS (SELECT 1 FROM objects
                        WHERE objects.hash = messages.obj_hash)
            ''', (future,))
            self.conn.execute(
                'UPDATE messages SET timestamp=? WHERE timestamp > ?',
                (now, future))
            self.conn.commit()

    def close(self):
        with self.lock:
            try:
                self.conn.close()
            except Exception:
                pass

    def query(self, sql, params=()):
        with self.lock:
            cur = self.conn.execute(sql, params)
            rows = cur.fetchall()
        return [dict(row) for row in rows]

    def execute(self, sql, params=()):
        with self.lock:
            cur = self.conn.execute(sql, params)
            self.conn.commit()
            return cur.lastrowid

    # ---- settings ----

    def get_setting(self, key, default=''):
        rows = self.query('SELECT value FROM settings WHERE key=?', (key,))
        return rows[0]['value'] if rows else default

    def set_setting(self, key, value):
        self.execute(
            'INSERT INTO settings(key, value) VALUES(?,?) '
            'ON CONFLICT(key) DO UPDATE SET value=excluded.value',
            (key, str(value)))

    def get_json(self, key, default=None):
        raw = self.get_setting(key)
        if not raw:
            return default if default is not None else {}
        try:
            return json.loads(raw)
        except Exception:
            return default if default is not None else {}

    def set_json(self, key, value):
        self.set_setting(key, json.dumps(value))

    def get_int(self, key, default=0):
        try:
            return int(self.get_setting(key, default))
        except Exception:
            return default

    # ---- identities ----

    def add_identity(self, address, label, stream, priv_signing,
                     priv_encryption, noncetrials=1000, extrabytes=1000,
                     chan=0, chan_label=''):
        self.execute('''
            INSERT INTO identities(address, label, stream, enabled,
                priv_signing, priv_encryption, noncetrials, extrabytes,
                created, chan, chan_label)
            VALUES(?,?,?,1,?,?,?,?,?,?,?)
            ON CONFLICT(address) DO UPDATE SET
                label=excluded.label, enabled=1,
                priv_signing=excluded.priv_signing,
                priv_encryption=excluded.priv_encryption,
                noncetrials=excluded.noncetrials,
                extrabytes=excluded.extrabytes,
                chan=excluded.chan, chan_label=excluded.chan_label
        ''', (address, label, stream, priv_signing, priv_encryption,
              noncetrials, extrabytes, int(time.time()), chan, chan_label))

    def all_identities(self, enabled_only=False):
        sql = 'SELECT * FROM identities'
        if enabled_only:
            sql += ' WHERE enabled=1'
        rows = self.query(sql + ' ORDER BY chan, created')
        return rows

    def get_identity(self, address):
        rows = self.query('SELECT * FROM identities WHERE address=?', (address,))
        return rows[0] if rows else None

    def delete_identity(self, address):
        self.execute('DELETE FROM identities WHERE address=?', (address,))

    def set_identity_label(self, address, label):
        self.execute('UPDATE identities SET label=? WHERE address=?',
                     (label, address))

    def set_identity_difficulty(self, address, noncetrials, extrabytes):
        self.execute(
            'UPDATE identities SET noncetrials=?, extrabytes=? '
            'WHERE address=?', (noncetrials, extrabytes, address))

    # ---- contacts ----

    def add_contact(self, address, label, stream=1):
        self.execute('''
            INSERT INTO contacts(address, label, stream, added)
            VALUES(?,?,?,?)
            ON CONFLICT(address) DO UPDATE SET
                label=excluded.label, stream=excluded.stream
        ''', (address, label, stream, int(time.time())))

    def all_contacts(self):
        return self.query('SELECT * FROM contacts ORDER BY label')

    def get_contact(self, address):
        rows = self.query('SELECT * FROM contacts WHERE address=?', (address,))
        return rows[0] if rows else None

    def remove_contact(self, address):
        self.execute('DELETE FROM contacts WHERE address=?', (address,))

    # ---- subscriptions ----

    def add_subscription(self, address, label=None, name=''):
        self._ensure_subscription_name_column()
        self.execute('''
            INSERT INTO subscriptions(address, label, added, name)
            VALUES(?,?,?,?)
            ON CONFLICT(address) DO UPDATE SET label=excluded.label,
                name=COALESCE(NULLIF(excluded.name,''), subscriptions.name)
        ''', (address, label or '', int(time.time()), name or ''))

    def set_subscription_name(self, address, name):
        self._ensure_subscription_name_column()
        self.execute('UPDATE subscriptions SET name=? WHERE address=?',
                     (name or '', address))

    def _ensure_subscription_name_column(self):
        with self.lock:
            cols = [r[1] for r in self.conn.execute(
                'PRAGMA table_info(subscriptions)').fetchall()]
            if 'name' not in cols:
                self.conn.execute(
                    'ALTER TABLE subscriptions ADD COLUMN name TEXT '
                    "DEFAULT ''")
                self.conn.commit()

    def all_subscriptions(self):
        return self.query('SELECT * FROM subscriptions ORDER BY label')

    def get_subscription(self, address):
        rows = self.query('SELECT * FROM subscriptions WHERE address=?',
                          (address,))
        return rows[0] if rows else None

    def remove_subscription(self, address):
        self.execute('DELETE FROM subscriptions WHERE address=?', (address,))

    # ---- messages ----

    def add_message(self, obj_hash, from_address, to_address, subject, body,
                    encoding, timestamp, direction, status,
                    target_stream=None):
        return self.execute('''
            INSERT INTO messages(obj_hash, from_address, to_address, subject,
                body, encoding, timestamp, direction, status, target_stream)
            VALUES(?,?,?,?,?,?,?,?,?,?)
        ''', (obj_hash, from_address, to_address, subject or '', body or '',
              encoding, int(timestamp), direction, status, target_stream))

    def message_exists(self, obj_hash):
        rows = self.query('SELECT id FROM messages WHERE obj_hash=?',
                          (obj_hash,))
        return bool(rows)

    def get_message(self, message_id):
        rows = self.query('SELECT * FROM messages WHERE id=?', (message_id,))
        return rows[0] if rows else None

    def messages_for(self, address):
        return self.query(
            'SELECT * FROM messages WHERE to_address=? OR from_address=? '
            'ORDER BY timestamp', (address, address))

    def messages_for_contact(self, contact_address, identity_address):
        return self.query(
            'SELECT * FROM messages WHERE '
            '(to_address=? AND from_address=?) OR '
            '(to_address=? AND from_address=?) '
            'ORDER BY timestamp',
            (identity_address, contact_address,
             contact_address, identity_address))

    def messages_for_conversation(self, address, limit=None):
        if limit is None:
            return self.query(
                'SELECT * FROM messages WHERE to_address=? OR from_address=? '
                'ORDER BY timestamp, id', (address, address))
        try:
            limit = max(1, min(int(limit), 1000))
        except Exception:
            limit = 200
        return self.query(
            'SELECT * FROM (SELECT * FROM messages WHERE to_address=? OR '
            'from_address=? ORDER BY timestamp DESC, id DESC LIMIT ?) '
            'ORDER BY timestamp, id', (address, address, limit))

    _VALID_STATUSES = frozenset([
        'awaiting-pubkey', 'sending', 'sent', 'ackreceived', 'received',
        'read', 'ack-failed',
    ])

    def set_message_status(self, message_id, status):
        if status not in self._VALID_STATUSES:
            raise ValueError('status inválido: %r' % (status,))
        self.execute('UPDATE messages SET status=? WHERE id=?',
                     (status, message_id))

    def delete_conversation(self, address):
        self.execute('DELETE FROM messages WHERE from_address=? OR '
                     'to_address=?', (address, address))

    def unread_count(self):
        rows = self.query(
            "SELECT COUNT(*) AS n FROM messages WHERE status='received'")
        return rows[0]['n'] if rows else 0

    def mark_conversation_read(self, contact_address, identity_address):
        self.execute(
            'UPDATE messages SET status=? WHERE '
            '(to_address=? AND from_address=?) AND status=?',
            ('read', identity_address, contact_address, 'received'))

    def recent_messages(self, limit=200):
        return self.query(
            'SELECT * FROM messages ORDER BY id DESC LIMIT ?', (limit,))

    # ---- objects ----

    def store_object(self, obj_hash, raw, obj_type, version, stream,
                     expires):
        try:
            self.execute('''
                INSERT INTO objects(hash, raw, type, version, stream,
                    expires, received)
                VALUES(?,?,?,?,?,?,?)
            ''', (obj_hash, raw, obj_type, version, stream,
                  int(expires), int(time.time())))
        except sqlite3.IntegrityError:
            pass

    def get_object(self, obj_hash):
        rows = self.query('SELECT * FROM objects WHERE hash=?', (obj_hash,))
        return rows[0] if rows else None

    def object_type_of(self, obj_hash):
        rows = self.query('SELECT type FROM objects WHERE hash=?', (obj_hash,))
        return rows[0]['type'] if rows else None

    # ---- pubkeys ----

    def store_pubkey(self, address, signing_public, encryption_public,
                     noncetrials=1000, extrabytes=1000):
        self.execute('''
            INSERT INTO pubkeys(address, signing_public, encryption_public,
                noncetrials, extrabytes, received)
            VALUES(?,?,?,?,?,?)
            ON CONFLICT(address) DO UPDATE SET
                signing_public=excluded.signing_public,
                encryption_public=excluded.encryption_public,
                noncetrials=excluded.noncetrials,
                extrabytes=excluded.extrabytes
        ''', (address, signing_public, encryption_public, noncetrials,
              extrabytes, int(time.time())))

    def get_pubkey(self, address):
        rows = self.query(
            'SELECT * FROM pubkeys WHERE address=?', (address,))
        return rows[0] if rows else None

    def all_pubkeys(self):
        return self.query('SELECT * FROM pubkeys')
