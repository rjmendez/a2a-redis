"""
A2A over Redis with PKI + TOTP Authentication

Reference implementation for secure inter-agent communication over Redis.
Supports both synchronous (request/reply) and asynchronous (fire-and-forget) patterns.

Message Format:
  {
    "id": "uuid-request-id",
    "from": "agent-name",
    "to": "agent-name",
    "timestamp": "2026-04-03T16:00:00Z",
    "method": "skill_name",
    "params": {...},
    "signature": "base64-encoded-rsa-signature",
    "totp": "6-digit-code"
  }

Queues:
  mesh:inbox:{agent_name} — receive task envelope
  mesh:reply:{request_id} — receive result (if requested)
"""

import os
import json
import uuid
import base64
import time
from datetime import datetime, timezone
from typing import Dict, Optional, Any, Tuple
import logging

import redis
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import pyotp

logger = logging.getLogger(__name__)

# Maximum message size (bytes) to prevent abuse
MAX_MESSAGE_SIZE = 1024 * 1024  # 1MB

# Default max age for message staleness check (seconds)
DEFAULT_MAX_MESSAGE_AGE = 120

# Nonce dedup TTL (seconds) — how long to remember seen message IDs
NONCE_TTL = 300


# ── Exceptions ────────────────────────────────────────────────────────────────

class A2AError(Exception):
    """Base exception for A2A framework."""
    pass

class SignatureError(A2AError):
    """Signature verification failed."""
    pass

class TOTPError(A2AError):
    """TOTP verification failed."""
    pass

class StaleMessageError(A2AError):
    """Message timestamp is too old."""
    pass

class ReplayError(A2AError):
    """Duplicate message ID detected (replay attempt)."""
    pass

class MessageTooLargeError(A2AError):
    """Message exceeds maximum allowed size."""
    pass


# ── PKI Store ─────────────────────────────────────────────────────────────────

class PKIStore:
    """Manages agent keypairs. Keys are cached after first load."""

    def __init__(self, keys_path: str = "./agent-keys"):
        self.keys_path = keys_path
        os.makedirs(keys_path, exist_ok=True)
        self._private_cache: Dict[str, Any] = {}
        self._public_cache: Dict[str, Any] = {}

    def save_keypair(self, agent_name: str, private_pem: bytes, public_pem: bytes):
        """Save agent keypair locally with restricted permissions."""
        priv_path = os.path.join(self.keys_path, f"{agent_name}.private.pem")
        pub_path = os.path.join(self.keys_path, f"{agent_name}.public.pem")

        # Write private key with 0600 permissions
        fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, private_pem)
        finally:
            os.close(fd)

        with open(pub_path, "wb") as f:
            f.write(public_pem)

        # Invalidate cache
        self._private_cache.pop(agent_name, None)
        self._public_cache.pop(agent_name, None)
        logger.info(f"✓ Saved keypair for {agent_name} (private key: 0600)")

    def load_private_key(self, agent_name: str):
        """Load agent's private key for signing (cached)."""
        if agent_name in self._private_cache:
            return self._private_cache[agent_name]

        path = os.path.join(self.keys_path, f"{agent_name}.private.pem")
        if not os.path.exists(path):
            raise FileNotFoundError(f"Private key not found: {path}")
        with open(path, "rb") as f:
            key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        self._private_cache[agent_name] = key
        return key

    def load_public_key(self, agent_name: str):
        """Load agent's public key for verification (cached)."""
        if agent_name in self._public_cache:
            return self._public_cache[agent_name]

        path = os.path.join(self.keys_path, f"{agent_name}.public.pem")
        if not os.path.exists(path):
            raise FileNotFoundError(f"Public key not found: {path}")
        with open(path, "rb") as f:
            key = serialization.load_pem_public_key(
                f.read(), backend=default_backend()
            )
        self._public_cache[agent_name] = key
        return key

    def clear_cache(self):
        """Clear all cached keys (call after key rotation)."""
        self._private_cache.clear()
        self._public_cache.clear()

    @staticmethod
    def generate_keypair() -> Tuple[bytes, bytes]:
        """Generate a new RSA-2048 keypair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_pem, public_pem


# ── Message Envelope ──────────────────────────────────────────────────────────

class A2AMessage:
    """Message envelope with signatures and TOTP codes."""

    def __init__(self, from_agent: str, to_agent: str, method: str,
                 params: Dict[str, Any], message_id: Optional[str] = None,
                 totp_seed: Optional[str] = None, pki: Optional[PKIStore] = None):
        self.id = message_id or str(uuid.uuid4())
        self.from_agent = from_agent
        self.to_agent = to_agent
        self.method = method
        self.params = params
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.totp_seed = totp_seed
        self.pki = pki
        self.signature: Optional[str] = None
        self.totp: Optional[str] = None

    def _signing_payload(self) -> str:
        """
        Canonical payload for signing. Separate from to_dict() so the signing
        contract is explicit and won't break if we add display-only fields.
        """
        return json.dumps({
            "id": self.id,
            "from": self.from_agent,
            "to": self.to_agent,
            "timestamp": self.timestamp,
            "method": self.method,
            "params": self.params
        }, sort_keys=True, separators=(',', ':'))

    def to_dict(self) -> Dict:
        """Serialize message body (without auth fields)."""
        return {
            "id": self.id,
            "from": self.from_agent,
            "to": self.to_agent,
            "timestamp": self.timestamp,
            "method": self.method,
            "params": self.params
        }

    def sign(self) -> None:
        """Sign message with agent's private key."""
        if not self.pki:
            raise A2AError("PKI store required for signing")

        payload = self._signing_payload()
        private_key = self.pki.load_private_key(self.from_agent)
        signature_bytes = private_key.sign(
            payload.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        self.signature = base64.b64encode(signature_bytes).decode()

    def add_totp(self) -> None:
        """Add TOTP code to message."""
        if not self.totp_seed:
            raise A2AError("TOTP seed required")
        totp = pyotp.TOTP(self.totp_seed)
        self.totp = totp.now()

    def to_json(self) -> str:
        """Serialize message with signature and TOTP for transmission."""
        payload = self.to_dict()
        if self.signature:
            payload["signature"] = self.signature
        if self.totp:
            payload["totp"] = self.totp
        return json.dumps(payload)

    @staticmethod
    def from_json(data: str) -> "A2AMessage":
        """Deserialize message from JSON."""
        if len(data) > MAX_MESSAGE_SIZE:
            raise MessageTooLargeError(
                f"Message size {len(data)} exceeds max {MAX_MESSAGE_SIZE}")

        obj = json.loads(data)
        msg = A2AMessage(
            from_agent=obj["from"],
            to_agent=obj["to"],
            method=obj["method"],
            params=obj["params"],
            message_id=obj["id"]
        )
        msg.timestamp = obj["timestamp"]
        msg.signature = obj.get("signature")
        msg.totp = obj.get("totp")
        return msg


# ── Redis Client ──────────────────────────────────────────────────────────────

class A2ARedisClient:
    """Redis-backed A2A client with PKI + TOTP auth."""

    def __init__(self, agent_name: str, redis_host: str = "localhost",
                 redis_port: int = 6379, redis_password: Optional[str] = None,
                 totp_seeds: Optional[Dict[str, str]] = None,
                 totp_seed: Optional[str] = None,
                 pki: Optional[PKIStore] = None,
                 max_message_age: int = DEFAULT_MAX_MESSAGE_AGE):
        """
        Args:
            agent_name: This agent's identity.
            totp_seeds: Per-peer TOTP seeds: {"peer_name": "base32_seed", ...}
                        Used for both sending and verifying.
            totp_seed:  Single shared TOTP seed (legacy, used if totp_seeds is None).
            pki:        PKI store for signing/verification.
            max_message_age: Max seconds since message timestamp before rejection.
        """
        self.agent_name = agent_name
        self.pki = pki or PKIStore()
        self.max_message_age = max_message_age

        # Per-peer TOTP seeds (preferred) or single shared seed (legacy)
        if totp_seeds:
            self._totp_seeds = totp_seeds
        elif totp_seed:
            self._totp_seeds = {"__default__": totp_seed}
        else:
            self._totp_seeds = {}

        self.redis_client = redis.Redis(
            host=redis_host,
            port=redis_port,
            password=redis_password,
            decode_responses=True
        )

        self.inbox_key = f"mesh:inbox:{agent_name}"
        self._nonce_prefix = "mesh:nonce:"
        logger.info(f"✓ A2A Redis client initialized for {agent_name}")

    def _get_totp_seed_for(self, peer: str) -> Optional[str]:
        """Look up TOTP seed for a peer. Falls back to default."""
        return self._totp_seeds.get(peer) or self._totp_seeds.get("__default__")

    def ping(self) -> bool:
        """Health check: verify Redis connectivity."""
        try:
            return self.redis_client.ping()
        except redis.ConnectionError:
            return False

    def send(self, to_agent: str, method: str, params: Dict[str, Any],
             wait_for_reply: bool = False, timeout_seconds: int = 30) -> Optional[Dict]:
        """
        Send a message to another agent.

        If wait_for_reply=True, blocks until reply is received or timeout.
        Returns the reply params dict, or None for fire-and-forget.
        """
        seed = self._get_totp_seed_for(to_agent)

        msg = A2AMessage(
            from_agent=self.agent_name,
            to_agent=to_agent,
            method=method,
            params=params,
            totp_seed=seed,
            pki=self.pki
        )

        msg.sign()
        if seed:
            msg.add_totp()

        recipient_inbox = f"mesh:inbox:{to_agent}"
        self.redis_client.rpush(recipient_inbox, msg.to_json())
        logger.info(f"→ Sent {method} to {to_agent} (id={msg.id})")

        if not wait_for_reply:
            return {"message_id": msg.id}

        # Wait for reply using BLPOP (efficient, no busy-polling)
        reply_key = f"mesh:reply:{msg.id}"
        result = self.redis_client.blpop(reply_key, timeout=timeout_seconds)

        if not result:
            raise TimeoutError(f"No reply from {to_agent} after {timeout_seconds}s")

        _, reply_json = result
        reply = A2AMessage.from_json(reply_json)
        logger.info(f"← Reply from {reply.from_agent} for {msg.id}")
        return reply.params

    def listen(self, timeout_seconds: int = 0, verify_signature: bool = True,
               verify_totp: bool = True,
               verify_freshness: bool = True) -> Optional[Tuple[str, str, str, Dict]]:
        """
        Listen for incoming messages on inbox.

        Returns: (message_id, from_agent, method, params) or None on timeout.
        """
        if timeout_seconds > 0:
            result = self.redis_client.blpop(self.inbox_key, timeout=timeout_seconds)
        else:
            result = self.redis_client.lpop(self.inbox_key)

        if not result:
            return None

        msg_json = result[1] if isinstance(result, tuple) else result
        msg = A2AMessage.from_json(msg_json)

        # Verify freshness (reject stale messages)
        if verify_freshness:
            self._verify_freshness(msg)

        # Verify signature
        if verify_signature and self.pki:
            self._verify_signature(msg)

        # Verify TOTP
        if verify_totp:
            self._verify_totp(msg)

        # Nonce dedup (reject replays)
        self._check_nonce(msg)

        logger.info(f"← Received {msg.method} from {msg.from_agent} (id={msg.id})")
        return msg.id, msg.from_agent, msg.method, msg.params

    def reply(self, request_id: str, to_agent: str, result: Dict) -> None:
        """Send a reply to a request."""
        seed = self._get_totp_seed_for(to_agent)

        msg = A2AMessage(
            from_agent=self.agent_name,
            to_agent=to_agent,
            method="__reply__",
            params=result,
            message_id=request_id,
            totp_seed=seed,
            pki=self.pki
        )

        msg.sign()
        if seed:
            msg.add_totp()

        reply_key = f"mesh:reply:{request_id}"
        self.redis_client.rpush(reply_key, msg.to_json())
        self.redis_client.expire(reply_key, NONCE_TTL)
        logger.info(f"→ Reply to {to_agent} for {request_id}")

    def _verify_signature(self, msg: A2AMessage) -> None:
        """Verify message signature using sender's public key."""
        if not msg.signature:
            raise SignatureError(f"Message {msg.id} missing signature")

        try:
            public_key = self.pki.load_public_key(msg.from_agent)
            signature_bytes = base64.b64decode(msg.signature)
            payload = msg._signing_payload()

            public_key.verify(
                signature_bytes,
                payload.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except SignatureError:
            raise
        except Exception as e:
            raise SignatureError(f"Signature verification failed for {msg.id}: {e}")

    def _verify_totp(self, msg: A2AMessage) -> None:
        """Verify TOTP code using per-peer seed."""
        seed = self._get_totp_seed_for(msg.from_agent)
        if not seed:
            return  # No TOTP configured for this peer

        if not msg.totp:
            raise TOTPError(f"Message {msg.id} missing TOTP (required for {msg.from_agent})")

        totp = pyotp.TOTP(seed)
        if not totp.verify(msg.totp, valid_window=1):
            raise TOTPError(f"TOTP verification failed for {msg.id} from {msg.from_agent}")

    def _verify_freshness(self, msg: A2AMessage) -> None:
        """Reject messages older than max_message_age."""
        try:
            msg_time = datetime.fromisoformat(msg.timestamp)
            if msg_time.tzinfo is None:
                msg_time = msg_time.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            age = (now - msg_time).total_seconds()

            if age > self.max_message_age:
                raise StaleMessageError(
                    f"Message {msg.id} is {age:.1f}s old (max {self.max_message_age}s)")
            if age < -30:  # Future message (clock skew tolerance)
                raise StaleMessageError(
                    f"Message {msg.id} is {-age:.1f}s in the future")
        except (ValueError, TypeError) as e:
            raise StaleMessageError(f"Invalid timestamp in message {msg.id}: {e}")

    def _check_nonce(self, msg: A2AMessage) -> None:
        """Reject duplicate message IDs (replay protection)."""
        nonce_key = f"{self._nonce_prefix}{msg.id}"
        # SETNX returns True if key was set (new message), False if exists (replay)
        if not self.redis_client.set(nonce_key, "1", nx=True, ex=NONCE_TTL):
            raise ReplayError(f"Duplicate message ID {msg.id} (possible replay)")


# ── Setup Helpers ─────────────────────────────────────────────────────────────

def generate_agent_keys(agent_name: str, pki: PKIStore) -> None:
    """Generate keypair for an agent (skip if exists)."""
    try:
        pki.load_private_key(agent_name)
        logger.info(f"✓ Keypair already exists for {agent_name}")
    except FileNotFoundError:
        logger.info(f"Generating keypair for {agent_name}...")
        private_pem, public_pem = PKIStore.generate_keypair()
        pki.save_keypair(agent_name, private_pem, public_pem)


def generate_totp_seed() -> str:
    """Generate a new random TOTP seed."""
    return pyotp.random_base32()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    pki = PKIStore("./test-keys")

    # Setup agents
    generate_agent_keys("alice", pki)
    generate_agent_keys("bob", pki)

    # Shared seed for this demo (in production: per-peer seeds)
    shared_seed = generate_totp_seed()

    alice = A2ARedisClient("alice", totp_seeds={"bob": shared_seed}, pki=pki)
    bob = A2ARedisClient("bob", totp_seeds={"alice": shared_seed}, pki=pki)

    # Alice sends to Bob
    alice.send("bob", "hello", {"msg": "Hi Bob! This is Alice."})

    # Bob listens
    result = bob.listen(timeout_seconds=5)
    if result:
        msg_id, from_agent, method, params = result
        print(f"\nBob received from {from_agent}: {params}")
        # Bob can now reply:
        bob.reply(msg_id, from_agent, {"status": "ok", "echo": params})
