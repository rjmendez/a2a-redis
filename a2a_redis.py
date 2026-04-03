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
import hmac
import hashlib
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


class PKIStore:
    """Manages agent public keys (or could be backed by a key server)."""
    
    def __init__(self, keys_path: str = "./agent-keys"):
        self.keys_path = keys_path
        os.makedirs(keys_path, exist_ok=True)
    
    def save_keypair(self, agent_name: str, private_pem: bytes, public_pem: bytes):
        """Save agent keypair locally."""
        with open(os.path.join(self.keys_path, f"{agent_name}.private.pem"), "wb") as f:
            f.write(private_pem)
        with open(os.path.join(self.keys_path, f"{agent_name}.public.pem"), "wb") as f:
            f.write(public_pem)
        logger.info(f"✓ Saved keypair for {agent_name}")
    
    def load_private_key(self, agent_name: str):
        """Load agent's private key for signing."""
        path = os.path.join(self.keys_path, f"{agent_name}.private.pem")
        if not os.path.exists(path):
            raise FileNotFoundError(f"Private key not found: {path}")
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
    
    def load_public_key(self, agent_name: str):
        """Load agent's public key for verification."""
        path = os.path.join(self.keys_path, f"{agent_name}.public.pem")
        if not os.path.exists(path):
            raise FileNotFoundError(f"Public key not found: {path}")
        with open(path, "rb") as f:
            return serialization.load_pem_public_key(
                f.read(), backend=default_backend()
            )
    
    @staticmethod
    def generate_keypair() -> Tuple[bytes, bytes]:
        """Generate a new RSA keypair."""
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


class A2AMessage:
    """Message envelope with signatures and TOTP codes."""
    
    def __init__(self, from_agent: str, to_agent: str, method: str, params: Dict[str, Any],
                 totp_seed: Optional[str] = None, pki: Optional[PKIStore] = None):
        self.id = str(uuid.uuid4())
        self.from_agent = from_agent
        self.to_agent = to_agent
        self.method = method
        self.params = params
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.totp_seed = totp_seed
        self.pki = pki
        self.signature: Optional[str] = None
        self.totp: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Serialize message (without signature/TOTP initially)."""
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
            raise ValueError("PKI store required for signing")
        
        payload = json.dumps(self.to_dict(), sort_keys=True)
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
        logger.debug(f"✓ Signed message {self.id} from {self.from_agent}")
    
    def add_totp(self) -> None:
        """Add TOTP code to message."""
        if not self.totp_seed:
            raise ValueError("TOTP seed required")
        totp = pyotp.TOTP(self.totp_seed)
        self.totp = totp.now()
        logger.debug(f"✓ Added TOTP to message {self.id}")
    
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
        obj = json.loads(data)
        msg = A2AMessage(
            from_agent=obj["from"],
            to_agent=obj["to"],
            method=obj["method"],
            params=obj["params"]
        )
        msg.id = obj["id"]
        msg.timestamp = obj["timestamp"]
        msg.signature = obj.get("signature")
        msg.totp = obj.get("totp")
        return msg


class A2ARedisClient:
    """Redis-backed A2A client with PKI + TOTP auth."""
    
    def __init__(self, agent_name: str, redis_host: str = "localhost", redis_port: int = 6379,
                 redis_password: Optional[str] = None, totp_seed: Optional[str] = None,
                 pki: Optional[PKIStore] = None):
        self.agent_name = agent_name
        self.totp_seed = totp_seed
        self.pki = pki or PKIStore()
        
        self.redis_client = redis.Redis(
            host=redis_host,
            port=redis_port,
            password=redis_password,
            decode_responses=True
        )
        
        self.inbox_key = f"mesh:inbox:{agent_name}"
        self.reply_prefix = "mesh:reply:"
        logger.info(f"✓ A2A Redis client initialized for {agent_name}")
    
    def send(self, to_agent: str, method: str, params: Dict[str, Any],
             wait_for_reply: bool = False, timeout_seconds: int = 30) -> Optional[Dict]:
        """
        Send a message to another agent.
        
        If wait_for_reply=True, blocks until reply is received or timeout.
        """
        msg = A2AMessage(
            from_agent=self.agent_name,
            to_agent=to_agent,
            method=method,
            params=params,
            totp_seed=self.totp_seed,
            pki=self.pki
        )
        
        # Sign message
        msg.sign()
        
        # Add TOTP if configured
        if self.totp_seed:
            msg.add_totp()
        
        # Push to recipient's inbox
        recipient_inbox = f"mesh:inbox:{to_agent}"
        self.redis_client.rpush(recipient_inbox, msg.to_json())
        logger.info(f"→ Sent {method} to {to_agent} (id={msg.id})")
        
        if not wait_for_reply:
            return None
        
        # Wait for reply
        reply_key = f"{self.reply_prefix}{msg.id}"
        start = time.time()
        while time.time() - start < timeout_seconds:
            reply_json = self.redis_client.lpop(reply_key)
            if reply_json:
                reply = A2AMessage.from_json(reply_json)
                logger.info(f"← Received reply from {reply.from_agent} (latency={time.time()-start:.2f}s)")
                return reply.params
            time.sleep(0.1)
        
        raise TimeoutError(f"No reply from {to_agent} after {timeout_seconds}s")
    
    def listen(self, timeout_seconds: int = 0, verify_signature: bool = True,
               verify_totp: bool = True) -> Optional[Tuple[str, str, Dict]]:
        """
        Listen for incoming messages on inbox.
        
        Returns: (from_agent, method, params) or None on timeout.
        """
        if timeout_seconds > 0:
            msg_json = self.redis_client.blpop(self.inbox_key, timeout=timeout_seconds)
        else:
            msg_json = self.redis_client.lpop(self.inbox_key)
        
        if not msg_json:
            return None
        
        # msg_json is a tuple (key, value) when using blpop
        if isinstance(msg_json, tuple):
            msg_json = msg_json[1]
        
        msg = A2AMessage.from_json(msg_json)
        
        # Verify signature if PKI available
        if verify_signature and self.pki:
            self._verify_signature(msg)
        
        # Verify TOTP if configured
        if verify_totp and self.totp_seed and msg.totp:
            self._verify_totp(msg)
        
        logger.info(f"← Received {msg.method} from {msg.from_agent} (id={msg.id})")
        return msg.from_agent, msg.method, msg.params
    
    def reply(self, request_id: str, from_agent: str, result: Dict) -> None:
        """Send a reply to a request."""
        msg = A2AMessage(
            from_agent=self.agent_name,
            to_agent=from_agent,
            method="__reply__",
            params=result,
            totp_seed=self.totp_seed,
            pki=self.pki
        )
        msg.id = request_id  # Reuse request ID for correlation
        msg.sign()
        if self.totp_seed:
            msg.add_totp()
        
        reply_key = f"{self.reply_prefix}{request_id}"
        self.redis_client.rpush(reply_key, msg.to_json())
        self.redis_client.expire(reply_key, 300)  # 5min TTL
        logger.info(f"→ Sent reply to {from_agent} for request {request_id}")
    
    def _verify_signature(self, msg: A2AMessage) -> None:
        """Verify message signature using sender's public key."""
        if not msg.signature:
            raise ValueError(f"Message {msg.id} missing signature")
        
        try:
            public_key = self.pki.load_public_key(msg.from_agent)
            signature_bytes = base64.b64decode(msg.signature)
            payload = json.dumps(msg.to_dict(), sort_keys=True)
            
            public_key.verify(
                signature_bytes,
                payload.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            logger.debug(f"✓ Signature verified for message {msg.id} from {msg.from_agent}")
        except Exception as e:
            raise ValueError(f"Signature verification failed for {msg.id}: {e}")
    
    def _verify_totp(self, msg: A2AMessage) -> None:
        """Verify TOTP code with tolerance window."""
        if not msg.totp:
            raise ValueError(f"Message {msg.id} missing TOTP")
        
        totp = pyotp.TOTP(self.totp_seed)
        # Allow ±1 time window (30s tolerance)
        if not totp.verify(msg.totp, valid_window=1):
            raise ValueError(f"TOTP verification failed for {msg.id}")
        logger.debug(f"✓ TOTP verified for message {msg.id}")


def example_agent_setup(agent_name: str, pki: PKIStore):
    """Generate keypair and TOTP seed for an agent."""
    # Generate keypair if not exists
    try:
        pki.load_private_key(agent_name)
        logger.info(f"✓ Keypair already exists for {agent_name}")
    except FileNotFoundError:
        logger.info(f"Generating keypair for {agent_name}...")
        private_pem, public_pem = PKIStore.generate_keypair()
        pki.save_keypair(agent_name, private_pem, public_pem)
    
    # Generate TOTP seed if needed
    totp_seed = pyotp.random_base32()
    logger.info(f"TOTP Seed for {agent_name}: {totp_seed}")
    return totp_seed


if __name__ == "__main__":
    # Example: Alice sends message to Bob
    
    logging.basicConfig(level=logging.INFO)
    
    pki = PKIStore("./test-keys")
    
    # Setup agents
    alice_seed = example_agent_setup("alice", pki)
    bob_seed = example_agent_setup("bob", pki)
    
    # Create clients
    alice = A2ARedisClient("alice", totp_seed=alice_seed, pki=pki)
    bob = A2ARedisClient("bob", totp_seed=bob_seed, pki=pki)
    
    # Alice sends to Bob (fire-and-forget)
    alice.send("bob", "hello", {"msg": "Hi Bob! This is Alice."})
    
    # Bob listens and replies
    result = bob.listen(timeout_seconds=5)
    if result:
        from_agent, method, params = result
        print(f"\nBob received from {from_agent}: {params}")
        # In real app, Bob would process and call bob.reply(...)
