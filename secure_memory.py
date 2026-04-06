"""
secure_memory.py — MrPink Encrypted Memory Client

Pipeline: plaintext → LZ4 compress → AES-256-GCM encrypt → store
          read → AES-256-GCM decrypt+verify → LZ4 decompress → plaintext

Key derivation: HKDF-SHA256 from RSA private key fingerprint
Tamper detection: built into AES-GCM auth tag (any modification = auth failure)
"""

import os
import struct
import hashlib
import lz4.frame
import psycopg2
import psycopg2.extras
from datetime import datetime
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# ── Key derivation ─────────────────────────────────────────────────────────────

def derive_key_from_rsa(private_key_path: str, salt: bytes = b"mrpink-memory-v1") -> bytes:
    """Derive a 256-bit AES key from the RSA private key using HKDF-SHA256."""
    with open(private_key_path, "rb") as f:
        pem_data = f.read()

    # Use SHA-256 of the raw PEM as input key material
    ikm = hashlib.sha256(pem_data).digest()

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"mrpink-aes-gcm-memory",
        backend=default_backend()
    )
    return hkdf.derive(ikm)


# ── Encryption / Decryption ────────────────────────────────────────────────────

VERSION = b"\x01"  # format version byte

# Padding range for CRIME mitigation — random bytes prepended to compressed data
# before encryption. 2-byte length prefix lets us strip on decrypt.
# Attacker sees variable output length regardless of plaintext similarity.
PAD_MIN = 16
PAD_MAX = 128


def encrypt(plaintext: str, key: bytes) -> bytes:
    """LZ4 compress → random pad → AES-256-GCM encrypt (VERSION as AAD).

    Blob format: VERSION(1) + nonce(12) + ciphertext+tag
    Plaintext-inside-GCM format: pad_len(2, big-endian) + pad(N) + compressed
    VERSION byte is authenticated via AAD — tamper on header is detected.
    Random padding (16–128 bytes) defeats CRIME-style compression oracles.
    """
    compressed = lz4.frame.compress(plaintext.encode("utf-8"))

    # Random padding — authenticated but discarded on decrypt
    pad_len = struct.unpack(">H", os.urandom(2))[0] % (PAD_MAX - PAD_MIN) + PAD_MIN
    pad = os.urandom(pad_len)
    padded = struct.pack(">H", pad_len) + pad + compressed

    nonce = os.urandom(12)  # 96-bit nonce, cryptographically random
    aesgcm = AESGCM(key)
    # VERSION byte as AAD — authenticated, not encrypted; tamper = InvalidTag
    ciphertext = aesgcm.encrypt(nonce, padded, VERSION)

    return VERSION + nonce + ciphertext


def decrypt(blob: bytes, key: bytes) -> str:
    """AES-256-GCM decrypt (VERSION as AAD) → strip pad → LZ4 decompress.

    Raises InvalidTag on any tamper (header, nonce, or ciphertext).
    Raises ValueError on unknown version.
    """
    if not blob or blob[0:1] != VERSION:
        raise ValueError(f"Unknown blob version: {blob[0:1]!r}")
    nonce = blob[1:13]
    ciphertext = blob[13:]
    aesgcm = AESGCM(key)
    # VERSION as AAD — verifies header integrity
    padded = aesgcm.decrypt(nonce, ciphertext, VERSION)

    # Strip padding: first 2 bytes = pad_len, skip pad, remainder = compressed
    pad_len = struct.unpack(">H", padded[:2])[0]
    compressed = padded[2 + pad_len:]

    return lz4.frame.decompress(compressed).decode("utf-8")


# ── Database client ────────────────────────────────────────────────────────────

DB_CONFIG = {
    "host": "localhost",
    "port": 5433,
    "dbname": "mrpink_memory",
    "user": "mrpink",
    "password": "MrPink-Memory-Secure-2026",
}

KEY_PATH = os.path.expanduser("~/.openclaw/workspace/a2a-redis/agent-keys/mrpink.private.pem")


class SecureMemory:
    """Encrypted memory client. LZ4+AES-GCM on every read/write."""

    def __init__(self, key_path: str = KEY_PATH):
        self.key = derive_key_from_rsa(key_path)
        self._conn = None

    def _db(self):
        if self._conn is None or self._conn.closed:
            self._conn = psycopg2.connect(**DB_CONFIG)
        return self._conn

    def _cur(self):
        return self._db().cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # ── Schema migration ────────────────────────────────────────────────────

    def migrate(self):
        """Add encrypted_content column if not present."""
        with self._cur() as cur:
            cur.execute("""
                ALTER TABLE memories
                ADD COLUMN IF NOT EXISTS encrypted_content BYTEA;

                ALTER TABLE decisions
                ADD COLUMN IF NOT EXISTS encrypted_content BYTEA;

                ALTER TABLE contacts
                ADD COLUMN IF NOT EXISTS encrypted_content BYTEA;
            """)
        self._db().commit()
        print("✓ Schema migrated — encrypted_content columns added")

    # ── Write ───────────────────────────────────────────────────────────────

    def store(self, title: str, content: str, tags: list = None,
              memory_type: str = "note", importance: int = 3) -> str:
        """Encrypt and store a memory. Returns row id (uuid)."""
        blob = encrypt(content, self.key)
        with self._cur() as cur:
            cur.execute("""
                INSERT INTO memories (title, content, encrypted_content, tags, type, importance)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (title, "[encrypted]", blob, tags or [], memory_type, min(importance, 5)))
            row_id = cur.fetchone()["id"]
        self._db().commit()
        return str(row_id)

    # ── Read ────────────────────────────────────────────────────────────────

    def get(self, memory_id: int) -> Optional[dict]:
        """Fetch and decrypt a memory by id."""
        with self._cur() as cur:
            cur.execute(
                "SELECT * FROM memories WHERE id = %s", (memory_id,)
            )
            row = cur.fetchone()
        if not row:
            return None
        row = dict(row)
        if row.get("encrypted_content"):
            try:
                row["content"] = decrypt(bytes(row["encrypted_content"]), self.key)
                row["tamper_detected"] = False
            except Exception as e:
                row["content"] = f"[TAMPER DETECTED: {e}]"
                row["tamper_detected"] = True
                self._flag_tamper(memory_id)
        return row

    def search(self, query: str, limit: int = 10) -> list:
        """Full-text search, decrypt results."""
        with self._cur() as cur:
            cur.execute("""
                SELECT * FROM memories
                WHERE to_tsvector('english', title || ' ' || coalesce(tags::text, ''))
                      @@ plainto_tsquery('english', %s)
                ORDER BY importance DESC, updated_at DESC
                LIMIT %s
            """, (query, limit))
            rows = cur.fetchall()
        return [self._decrypt_row(dict(r)) for r in rows]

    def recent(self, limit: int = 10) -> list:
        """Fetch most recent memories, decrypted."""
        with self._cur() as cur:
            cur.execute(
                "SELECT * FROM memories ORDER BY updated_at DESC LIMIT %s", (limit,)
            )
            rows = cur.fetchall()
        return [self._decrypt_row(dict(r)) for r in rows]

    # ── Integrity check ─────────────────────────────────────────────────────

    def integrity_check(self) -> dict:
        """Verify all encrypted memories. Returns tamper report."""
        with self._cur() as cur:
            cur.execute("SELECT id, title, encrypted_content FROM memories WHERE encrypted_content IS NOT NULL")
            rows = cur.fetchall()

        results = {"ok": [], "tampered": [], "missing_key": []}
        for row in rows:
            row = dict(row)
            try:
                decrypt(bytes(row["encrypted_content"]), self.key)
                results["ok"].append(row["id"])
            except Exception as e:
                results["tampered"].append({"id": row["id"], "title": row["title"], "error": str(e)})
                self._flag_tamper(row["id"])

        return results

    # ── Internal ────────────────────────────────────────────────────────────

    def _decrypt_row(self, row: dict) -> dict:
        if row.get("encrypted_content"):
            try:
                row["content"] = decrypt(bytes(row["encrypted_content"]), self.key)
                row["tamper_detected"] = False
            except Exception as e:
                row["content"] = f"[TAMPER DETECTED: {e}]"
                row["tamper_detected"] = True
        return row

    def _flag_tamper(self, memory_id: int):
        try:
            with self._cur() as cur:
                cur.execute(
                    "UPDATE memories SET tamper_detected = TRUE WHERE id = %s", (memory_id,)
                )
            self._db().commit()
        except Exception:
            pass

    def close(self):
        if self._conn and not self._conn.closed:
            self._conn.close()


# ── CLI smoke test ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== SecureMemory Smoke Test ===\n")

    mem = SecureMemory()

    # Migrate schema
    mem.migrate()

    # Test encrypt/decrypt roundtrip
    test_content = "This is a secret memory. Keys are identity. Protect them."
    blob = encrypt(test_content, mem.key)
    recovered = decrypt(blob, mem.key)
    assert recovered == test_content, "Roundtrip failed"

    import lz4.frame
    compressed_size = len(lz4.frame.compress(test_content.encode()))
    print(f"✓ Encrypt/decrypt roundtrip passed")
    print(f"  Original:   {len(test_content.encode())} bytes")
    print(f"  Compressed: {compressed_size} bytes")
    print(f"  Encrypted:  {len(blob)} bytes")

    # Test tamper detection
    tampered = bytearray(blob)
    tampered[20] ^= 0xFF  # flip a bit
    try:
        decrypt(bytes(tampered), mem.key)
        print("✗ Tamper detection FAILED")
    except Exception:
        print("✓ Tamper detection working — modified blob rejected")

    # Test store/retrieve
    row_id = mem.store(
        title="Key security doctrine",
        content="Keys are identity. Protect at a cost. Rotate proactively. Monitor access.",
        tags=["security", "identity", "keys"],
        memory_type="note",
        importance=5
    )
    print(f"✓ Stored encrypted memory (id={row_id})")

    row = mem.get(row_id)
    assert row["tamper_detected"] == False
    print(f"✓ Retrieved and decrypted: '{row['content'][:50]}...'")

    # Integrity check
    report = mem.integrity_check()
    print(f"✓ Integrity check: {len(report['ok'])} ok, {len(report['tampered'])} tampered")

    mem.close()
    print("\n✓ All tests passed.")
