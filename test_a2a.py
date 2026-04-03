"""
Tests for A2A over Redis — PKI + TOTP

Tests cover:
  - PKI key generation, save, load
  - Message signing and verification
  - TOTP generation and verification
  - Message serialization round-trip
  - Staleness rejection
  - Replay detection (nonce dedup)
  - Per-peer TOTP seeds
  - Max message size enforcement

Run: pytest test_a2a.py -v
"""

import json
import os
import time
import tempfile
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pytest
import pyotp

from a2a_redis import (
    PKIStore, A2AMessage, A2ARedisClient,
    SignatureError, TOTPError, StaleMessageError,
    ReplayError, MessageTooLargeError,
    generate_agent_keys, generate_totp_seed,
    MAX_MESSAGE_SIZE,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_keys_dir():
    """Temporary directory for test keypairs."""
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def pki(tmp_keys_dir):
    """PKI store with alice and bob keypairs."""
    store = PKIStore(tmp_keys_dir)
    priv_a, pub_a = PKIStore.generate_keypair()
    priv_b, pub_b = PKIStore.generate_keypair()
    store.save_keypair("alice", priv_a, pub_a)
    store.save_keypair("bob", priv_b, pub_b)
    return store


@pytest.fixture
def shared_seed():
    return generate_totp_seed()


# ── PKI Tests ─────────────────────────────────────────────────────────────────

class TestPKIStore:

    def test_generate_keypair(self):
        priv, pub = PKIStore.generate_keypair()
        assert b"PRIVATE KEY" in priv
        assert b"PUBLIC KEY" in pub

    def test_save_and_load(self, tmp_keys_dir):
        store = PKIStore(tmp_keys_dir)
        priv, pub = PKIStore.generate_keypair()
        store.save_keypair("test", priv, pub)

        loaded_priv = store.load_private_key("test")
        loaded_pub = store.load_public_key("test")
        assert loaded_priv is not None
        assert loaded_pub is not None

    def test_private_key_permissions(self, tmp_keys_dir):
        store = PKIStore(tmp_keys_dir)
        priv, pub = PKIStore.generate_keypair()
        store.save_keypair("test", priv, pub)

        priv_path = os.path.join(tmp_keys_dir, "test.private.pem")
        mode = oct(os.stat(priv_path).st_mode)[-3:]
        assert mode == "600", f"Private key permissions should be 600, got {mode}"

    def test_key_caching(self, pki):
        key1 = pki.load_private_key("alice")
        key2 = pki.load_private_key("alice")
        assert key1 is key2  # Same object from cache

        pki.clear_cache()
        key3 = pki.load_private_key("alice")
        assert key3 is not key1  # Reloaded from disk

    def test_missing_key(self, tmp_keys_dir):
        store = PKIStore(tmp_keys_dir)
        with pytest.raises(FileNotFoundError):
            store.load_private_key("nonexistent")


# ── Message Tests ─────────────────────────────────────────────────────────────

class TestA2AMessage:

    def test_create_message(self):
        msg = A2AMessage("alice", "bob", "hello", {"text": "hi"})
        assert msg.from_agent == "alice"
        assert msg.to_agent == "bob"
        assert msg.method == "hello"
        assert msg.params == {"text": "hi"}
        assert msg.id is not None
        assert msg.timestamp is not None

    def test_custom_message_id(self):
        msg = A2AMessage("alice", "bob", "test", {}, message_id="custom-123")
        assert msg.id == "custom-123"

    def test_sign_and_verify(self, pki):
        msg = A2AMessage("alice", "bob", "test", {"x": 1}, pki=pki)
        msg.sign()
        assert msg.signature is not None

    def test_signing_payload_is_deterministic(self, pki):
        msg = A2AMessage("alice", "bob", "test", {"b": 2, "a": 1}, pki=pki)
        p1 = msg._signing_payload()
        p2 = msg._signing_payload()
        assert p1 == p2
        # Keys should be sorted
        parsed = json.loads(p1)
        keys = list(parsed.keys())
        assert keys == sorted(keys)

    def test_totp_generation(self):
        seed = generate_totp_seed()
        msg = A2AMessage("alice", "bob", "test", {}, totp_seed=seed)
        msg.add_totp()
        assert msg.totp is not None
        assert len(msg.totp) == 6

    def test_serialization_roundtrip(self, pki):
        seed = generate_totp_seed()
        msg = A2AMessage("alice", "bob", "test", {"key": "value"},
                        totp_seed=seed, pki=pki)
        msg.sign()
        msg.add_totp()

        json_str = msg.to_json()
        restored = A2AMessage.from_json(json_str)

        assert restored.id == msg.id
        assert restored.from_agent == "alice"
        assert restored.to_agent == "bob"
        assert restored.method == "test"
        assert restored.params == {"key": "value"}
        assert restored.signature == msg.signature
        assert restored.totp == msg.totp

    def test_max_message_size(self):
        huge = json.dumps({
            "id": "x", "from": "a", "to": "b",
            "timestamp": "2026-01-01T00:00:00Z",
            "method": "test", "params": {"data": "x" * (MAX_MESSAGE_SIZE + 100)}
        })
        with pytest.raises(MessageTooLargeError):
            A2AMessage.from_json(huge)


# ── Client Tests (mocked Redis) ──────────────────────────────────────────────

class TestA2ARedisClient:

    def _make_client(self, name, pki, seeds=None):
        """Create client with mocked Redis."""
        client = A2ARedisClient(
            agent_name=name,
            totp_seeds=seeds or {},
            pki=pki
        )
        client.redis_client = MagicMock()
        return client

    def test_ping(self, pki):
        client = self._make_client("alice", pki)
        client.redis_client.ping.return_value = True
        assert client.ping() is True

    def test_send_fire_and_forget(self, pki, shared_seed):
        alice = self._make_client("alice", pki, {"bob": shared_seed})

        result = alice.send("bob", "hello", {"msg": "hi"}, wait_for_reply=False)
        assert "message_id" in result

        # Verify RPUSH was called
        alice.redis_client.rpush.assert_called_once()
        args = alice.redis_client.rpush.call_args
        assert args[0][0] == "mesh:inbox:bob"

        # Verify the message is valid JSON with signature + TOTP
        msg_json = args[0][1]
        msg = json.loads(msg_json)
        assert msg["from"] == "alice"
        assert msg["to"] == "bob"
        assert "signature" in msg
        assert "totp" in msg

    def test_send_wait_for_reply(self, pki, shared_seed):
        alice = self._make_client("alice", pki, {"bob": shared_seed})

        # Mock: bob's reply is already waiting
        reply_msg = A2AMessage("bob", "alice", "__reply__",
                               {"status": "ok"}, pki=pki)
        reply_msg.sign()
        alice.redis_client.blpop.return_value = ("mesh:reply:x", reply_msg.to_json())

        result = alice.send("bob", "hello", {"msg": "hi"}, wait_for_reply=True)
        assert result["status"] == "ok"

    def test_send_timeout(self, pki):
        alice = self._make_client("alice", pki)
        alice.redis_client.blpop.return_value = None

        with pytest.raises(TimeoutError):
            alice.send("bob", "hello", {}, wait_for_reply=True, timeout_seconds=1)

    def test_listen_returns_message_id(self, pki, shared_seed):
        bob = self._make_client("bob", pki, {"alice": shared_seed})

        # Create a valid signed message from alice
        msg = A2AMessage("alice", "bob", "test", {"x": 1},
                        totp_seed=shared_seed, pki=pki)
        msg.sign()
        msg.add_totp()

        bob.redis_client.blpop.return_value = ("mesh:inbox:bob", msg.to_json())
        # Mock nonce check
        bob.redis_client.set.return_value = True

        result = bob.listen(timeout_seconds=5)
        assert result is not None
        msg_id, from_agent, method, params = result
        assert msg_id == msg.id
        assert from_agent == "alice"
        assert method == "test"
        assert params == {"x": 1}

    def test_signature_verification_rejects_tampered(self, pki, shared_seed):
        bob = self._make_client("bob", pki, {"alice": shared_seed})

        msg = A2AMessage("alice", "bob", "test", {"x": 1},
                        totp_seed=shared_seed, pki=pki)
        msg.sign()
        msg.add_totp()

        # Tamper with params
        raw = json.loads(msg.to_json())
        raw["params"]["x"] = 999
        tampered = json.dumps(raw)

        bob.redis_client.blpop.return_value = ("mesh:inbox:bob", tampered)

        with pytest.raises(SignatureError):
            bob.listen(timeout_seconds=5)

    def test_totp_verification_rejects_bad_code(self, pki):
        bob = self._make_client("bob", pki, {"alice": generate_totp_seed()})

        # Alice uses a DIFFERENT seed than what bob expects
        wrong_seed = generate_totp_seed()
        msg = A2AMessage("alice", "bob", "test", {},
                        totp_seed=wrong_seed, pki=pki)
        msg.sign()
        msg.add_totp()

        bob.redis_client.blpop.return_value = ("mesh:inbox:bob", msg.to_json())
        bob.redis_client.set.return_value = True

        with pytest.raises(TOTPError):
            bob.listen(timeout_seconds=5)

    def test_staleness_rejection(self, pki):
        bob = self._make_client("bob", pki)
        bob.max_message_age = 60

        msg = A2AMessage("alice", "bob", "test", {}, pki=pki)
        msg.sign()

        # Backdate timestamp by 5 minutes
        old_time = datetime.now(timezone.utc) - timedelta(minutes=5)
        raw = json.loads(msg.to_json())
        raw["timestamp"] = old_time.isoformat()
        stale = json.dumps(raw)

        bob.redis_client.blpop.return_value = ("mesh:inbox:bob", stale)

        # Signature will fail because timestamp changed, so disable sig check
        with pytest.raises(StaleMessageError):
            bob.listen(timeout_seconds=5, verify_signature=False, verify_totp=False)

    def test_replay_detection(self, pki, shared_seed):
        bob = self._make_client("bob", pki, {"alice": shared_seed})

        msg = A2AMessage("alice", "bob", "test", {},
                        totp_seed=shared_seed, pki=pki)
        msg.sign()
        msg.add_totp()

        bob.redis_client.blpop.return_value = ("mesh:inbox:bob", msg.to_json())

        # First time: nonce accepted
        bob.redis_client.set.return_value = True
        result = bob.listen(timeout_seconds=5)
        assert result is not None

        # Second time: nonce rejected (replay)
        bob.redis_client.set.return_value = False
        bob.redis_client.blpop.return_value = ("mesh:inbox:bob", msg.to_json())
        with pytest.raises(ReplayError):
            bob.listen(timeout_seconds=5)

    def test_per_peer_totp_seeds(self, pki):
        seed_alice = generate_totp_seed()
        seed_charlie = generate_totp_seed()

        bob = self._make_client("bob", pki, {
            "alice": seed_alice,
            "charlie": seed_charlie
        })

        assert bob._get_totp_seed_for("alice") == seed_alice
        assert bob._get_totp_seed_for("charlie") == seed_charlie
        assert bob._get_totp_seed_for("unknown") is None

    def test_legacy_single_seed(self, pki, shared_seed):
        """Legacy mode: single TOTP seed for all peers."""
        client = A2ARedisClient(
            agent_name="bob",
            totp_seed=shared_seed,
            pki=pki
        )
        client.redis_client = MagicMock()

        assert client._get_totp_seed_for("alice") == shared_seed
        assert client._get_totp_seed_for("anyone") == shared_seed


# ── Integration-style test (no Redis) ────────────────────────────────────────

class TestEndToEnd:

    def test_full_message_flow(self, pki, shared_seed):
        """Alice creates, signs, serializes → Bob deserializes, verifies."""
        # Alice creates and signs
        msg = A2AMessage("alice", "bob", "process",
                        {"target": "example.com", "depth": 3},
                        totp_seed=shared_seed, pki=pki)
        msg.sign()
        msg.add_totp()
        wire = msg.to_json()

        # Bob receives and verifies
        received = A2AMessage.from_json(wire)

        # Verify signature manually
        public_key = pki.load_public_key("alice")
        import base64
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        sig_bytes = base64.b64decode(received.signature)
        payload = received._signing_payload()
        # This should NOT raise
        public_key.verify(
            sig_bytes,
            payload.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Verify TOTP manually
        totp = pyotp.TOTP(shared_seed)
        assert totp.verify(received.totp, valid_window=1)

        # Verify payload integrity
        assert received.params == {"target": "example.com", "depth": 3}
        assert received.method == "process"
