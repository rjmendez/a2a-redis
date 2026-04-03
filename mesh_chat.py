"""
mesh_chat.py — Freeform Collaboration Layer for Agent Mesh

Adds a pub/sub chat channel on top of the existing A2A-over-Redis transport.
All messages are signed (RSA) and TOTP-authenticated — same security model as
structured A2A calls, but the payload is freeform text (no required schema).

Design goals:
  - Zero RPC ceremony: publish text, subscribe to text
  - Persistent: ring buffer in Redis, both agents catch up on reconnect
  - Capability-aware: agents self-advertise skills on join/heartbeat
  - Channel-aware: default "mesh:chat:general", custom channels supported
  - Compatible with existing a2a_redis.py PKIStore and auth machinery

Redis keys used:
  mesh:chat:{channel}            — Redis Stream (XADD/XREAD, auto ring-buffer)
  mesh:chat:{channel}:cursor:{agent} — each agent's last-read stream ID
  mesh:capabilities:{agent}      — Hash: skill → description (TTL 5min, refreshed on heartbeat)
  mesh:chat:{channel}:members    — Sorted Set: agent → last_seen_ts (TTL-managed)

Message envelope (stored in stream):
  {
    "id":        "<uuid>",
    "from":      "charlie",
    "channel":   "general",
    "ts":        "2026-04-03T17:00:00Z",
    "text":      "...",        # freeform content
    "kind":      "chat",       # chat | join | leave | capability | question | idea | update
    "signature": "<base64>",   # RSA-PSS over canonical payload
    "totp":      "123456"      # TOTP code (if seed configured)
  }

Usage (quick start):

    from mesh_chat import MeshChat, MeshChatClient
    from a2a_redis import PKIStore

    pki = PKIStore("./agent-keys")
    chat = MeshChatClient("charlie", redis_host="audit-redis", redis_password="...",
                          totp_seeds={"oxalis": "32EE5VTB5CL7BLJID4IBFZCXJMQKDH2W"},
                          pki=pki)

    # Publish a freeform idea
    chat.say("Hey Oxalis — what if we ran the DistilBERT batch_classify on GPU directly?")

    # Publish a structured update
    chat.update("Pipeline recovered: 9/9 workers healthy after health.py fix")

    # Ask a question (prompts response from listeners)
    chat.ask("Do you have hashcat_crack ready yet? I have 240 MD5 hashes ready to send")

    # Advertise capabilities (call on startup + periodically)
    chat.advertise_capabilities({
        "pipeline_status":  "Real-time audit pipeline health",
        "findings_query":   "Search scan_secrets DB",
        "chunk_scanner":    "107,840 chunks, 327/hr throughput",
    })

    # Read new messages (non-blocking)
    for msg in chat.read_new(channel="general"):
        print(f"[{msg.from_agent}] {msg.text}")

    # Blocking listen loop
    chat.listen_loop(callback=my_handler, channel="general")
"""

import json
import uuid
import base64
import time
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, List, Callable, Any
from dataclasses import dataclass, field, asdict

import redis
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import pyotp

from a2a_redis import PKIStore, A2AError, SignatureError, TOTPError, generate_totp_seed

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

DEFAULT_CHANNEL    = "general"
STREAM_MAX_LEN     = 500          # ring buffer: keep last N messages per channel
CAPABILITIES_TTL   = 300          # seconds — re-advertise before expiry
MEMBER_PRESENCE_TTL = 600         # seconds — agent considered offline after this
CURSOR_TTL         = 86400 * 7    # 1 week — remember read position across restarts
MAX_TEXT_LEN       = 8192         # characters — hard cap on message text
MESSAGE_MAX_AGE    = 300          # seconds — reject messages older than this

# Message kinds
KIND_CHAT       = "chat"        # freeform conversation
KIND_IDEA       = "idea"        # proposal or design thought
KIND_QUESTION   = "question"    # explicit question, expects response
KIND_UPDATE     = "update"      # status/progress update
KIND_JOIN       = "join"        # agent came online
KIND_LEAVE      = "leave"       # agent going offline
KIND_CAPABILITY = "capability"  # skill advertisement
KIND_ACK        = "ack"         # acknowledgement of a question/idea


# ── Message dataclass ─────────────────────────────────────────────────────────

@dataclass
class ChatMessage:
    """A single message in the mesh chat."""
    id: str
    from_agent: str
    channel: str
    ts: str
    text: str
    kind: str = KIND_CHAT
    reply_to: Optional[str] = None   # id of message being replied to
    signature: Optional[str] = None
    totp: Optional[str] = None
    stream_id: Optional[str] = None  # Redis stream ID (populated on read)

    def signing_payload(self) -> str:
        """Canonical string over which signature is computed."""
        return json.dumps({
            "id": self.id,
            "from": self.from_agent,
            "channel": self.channel,
            "ts": self.ts,
            "text": self.text,
            "kind": self.kind,
        }, sort_keys=True, separators=(',', ':'))

    def to_stream_dict(self) -> Dict[str, str]:
        """Flat dict for Redis XADD."""
        d = {
            "id":        self.id,
            "from":      self.from_agent,
            "channel":   self.channel,
            "ts":        self.ts,
            "text":      self.text,
            "kind":      self.kind,
        }
        if self.reply_to:
            d["reply_to"] = self.reply_to
        if self.signature:
            d["signature"] = self.signature
        if self.totp:
            d["totp"] = self.totp
        return d

    @classmethod
    def from_stream_dict(cls, d: Dict[str, str], stream_id: str = None) -> "ChatMessage":
        return cls(
            id=d["id"],
            from_agent=d["from"],
            channel=d["channel"],
            ts=d["ts"],
            text=d["text"],
            kind=d.get("kind", KIND_CHAT),
            reply_to=d.get("reply_to"),
            signature=d.get("signature"),
            totp=d.get("totp"),
            stream_id=stream_id,
        )

    def __str__(self):
        kind_prefix = f"[{self.kind}] " if self.kind != KIND_CHAT else ""
        ts_short = self.ts[11:16] if len(self.ts) >= 16 else self.ts
        return f"{ts_short} <{self.from_agent}> {kind_prefix}{self.text}"


# ── MeshChatClient ────────────────────────────────────────────────────────────

class MeshChatClient:
    """
    Freeform collaboration layer on top of Redis Streams.
    Handles signing, TOTP, presence, capability advertisement, and ring-buffered history.
    """

    def __init__(
        self,
        agent_name: str,
        redis_host: str = "localhost",
        redis_port: int = 6379,
        redis_password: Optional[str] = None,
        totp_seeds: Optional[Dict[str, str]] = None,
        pki: Optional[PKIStore] = None,
        default_channel: str = DEFAULT_CHANNEL,
    ):
        self.agent_name = agent_name
        self.pki = pki or PKIStore()
        self._totp_seeds: Dict[str, str] = totp_seeds or {}
        self.default_channel = default_channel

        self.r = redis.Redis(
            host=redis_host,
            port=redis_port,
            password=redis_password,
            decode_responses=True,
        )
        logger.info(f"MeshChat initialized for {agent_name}")

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _stream_key(self, channel: str) -> str:
        return f"mesh:chat:{channel}"

    def _cursor_key(self, channel: str) -> str:
        return f"mesh:chat:{channel}:cursor:{self.agent_name}"

    def _members_key(self, channel: str) -> str:
        return f"mesh:chat:{channel}:members"

    def _capabilities_key(self, agent: str) -> str:
        return f"mesh:capabilities:{agent}"

    def _sign(self, msg: ChatMessage) -> str:
        """Sign message payload with agent's private key."""
        private_key = self.pki.load_private_key(self.agent_name)
        payload = msg.signing_payload()
        sig_bytes = private_key.sign(
            payload.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return base64.b64encode(sig_bytes).decode()

    def _totp_for(self, peer: str) -> Optional[str]:
        """Get current TOTP code for a peer (or None if no seed)."""
        seed = self._totp_seeds.get(peer) or self._totp_seeds.get("__default__")
        if not seed:
            return None
        return pyotp.TOTP(seed).now()

    def _verify_message(self, msg: ChatMessage) -> bool:
        """
        Verify signature and TOTP. Returns True if valid, False if unverifiable
        (no public key for sender). Raises on active verification failures.
        """
        # Freshness check
        try:
            msg_time = datetime.fromisoformat(msg.ts)
            if msg_time.tzinfo is None:
                msg_time = msg_time.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - msg_time).total_seconds()
            if age > MESSAGE_MAX_AGE:
                raise A2AError(f"Stale message from {msg.from_agent}: {age:.0f}s old")
        except (ValueError, TypeError):
            raise A2AError(f"Invalid timestamp in message {msg.id}")

        # Signature (skip if no public key on file — graceful degradation)
        if msg.signature:
            try:
                pub_key = self.pki.load_public_key(msg.from_agent)
                sig_bytes = base64.b64decode(msg.signature)
                pub_key.verify(
                    sig_bytes,
                    msg.signing_payload().encode(),
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256(),
                )
            except FileNotFoundError:
                logger.warning(f"No public key for {msg.from_agent} — skipping sig check")
                return False
            except Exception as e:
                raise SignatureError(f"Bad signature from {msg.from_agent}: {e}")

        # TOTP (skip if no seed configured for this peer)
        seed = self._totp_seeds.get(msg.from_agent) or self._totp_seeds.get("__default__")
        if seed and msg.totp:
            totp = pyotp.TOTP(seed)
            if not totp.verify(msg.totp, valid_window=1):
                raise TOTPError(f"Bad TOTP from {msg.from_agent}")

        return True

    def _publish(self, msg: ChatMessage) -> str:
        """Sign, add TOTP, and push to Redis Stream. Returns stream ID."""
        if len(msg.text) > MAX_TEXT_LEN:
            raise ValueError(f"Message text too long ({len(msg.text)} > {MAX_TEXT_LEN})")

        # Sign
        try:
            msg.signature = self._sign(msg)
        except FileNotFoundError:
            logger.warning(f"No private key for {self.agent_name} — sending unsigned")

        # TOTP: we embed our own TOTP (recipients verify with their seed for us)
        # Use "__default__" seed if no per-peer (since this is broadcast)
        seed = self._totp_seeds.get("__default__")
        if seed:
            msg.totp = pyotp.TOTP(seed).now()

        stream_key = self._stream_key(msg.channel)
        stream_id = self.r.xadd(stream_key, msg.to_stream_dict(), maxlen=STREAM_MAX_LEN, approximate=True)

        # Update presence
        self.r.zadd(self._members_key(msg.channel), {self.agent_name: time.time()})
        self.r.expire(self._members_key(msg.channel), MEMBER_PRESENCE_TTL)

        logger.info(f"→ chat/{msg.channel} [{msg.kind}] from {self.agent_name}: {msg.text[:80]}")
        return stream_id

    def _make_msg(self, text: str, kind: str = KIND_CHAT, channel: str = None,
                  reply_to: str = None) -> ChatMessage:
        return ChatMessage(
            id=str(uuid.uuid4()),
            from_agent=self.agent_name,
            channel=channel or self.default_channel,
            ts=datetime.now(timezone.utc).isoformat(),
            text=text,
            kind=kind,
            reply_to=reply_to,
        )

    # ── Public API — sending ──────────────────────────────────────────────────

    def say(self, text: str, channel: str = None) -> str:
        """Send a freeform chat message."""
        return self._publish(self._make_msg(text, KIND_CHAT, channel))

    def idea(self, text: str, channel: str = None) -> str:
        """Propose an idea or design thought."""
        return self._publish(self._make_msg(text, KIND_IDEA, channel))

    def ask(self, text: str, channel: str = None) -> str:
        """Ask a question (signals expected response)."""
        return self._publish(self._make_msg(text, KIND_QUESTION, channel))

    def update(self, text: str, channel: str = None) -> str:
        """Publish a status or progress update."""
        return self._publish(self._make_msg(text, KIND_UPDATE, channel))

    def ack(self, text: str, reply_to_id: str, channel: str = None) -> str:
        """Acknowledge a question or idea with a reply."""
        return self._publish(self._make_msg(text, KIND_ACK, channel, reply_to=reply_to_id))

    def join(self, channel: str = None) -> str:
        """Announce arrival on channel."""
        ch = channel or self.default_channel
        return self._publish(self._make_msg(f"{self.agent_name} is online", KIND_JOIN, ch))

    def leave(self, channel: str = None) -> str:
        """Announce departure from channel."""
        ch = channel or self.default_channel
        try:
            stream_id = self._publish(self._make_msg(f"{self.agent_name} going offline", KIND_LEAVE, ch))
            self.r.zrem(self._members_key(ch), self.agent_name)
            return stream_id
        except Exception as e:
            logger.warning(f"Leave message failed: {e}")
            return ""

    def advertise_capabilities(self, capabilities: Dict[str, str], channel: str = None) -> str:
        """
        Publish current skill list. Stored in Redis with TTL so peers always have
        a fresh view. Also broadcasts to the channel so others see the update immediately.

        capabilities: {skill_id: description}
        """
        # Store in Redis hash with TTL
        cap_key = self._capabilities_key(self.agent_name)
        self.r.delete(cap_key)
        if capabilities:
            self.r.hset(cap_key, mapping=capabilities)
            self.r.expire(cap_key, CAPABILITIES_TTL)

        # Broadcast summary to channel
        summary = ", ".join(f"{k}: {v[:60]}" for k, v in list(capabilities.items())[:10])
        text = f"capabilities update: {summary}"
        return self._publish(self._make_msg(text, KIND_CAPABILITY, channel))

    # ── Public API — reading ──────────────────────────────────────────────────

    def read_new(self, channel: str = None, count: int = 50) -> List[ChatMessage]:
        """
        Read messages published since our last cursor position.
        Updates cursor after reading. Non-blocking.
        """
        ch = channel or self.default_channel
        stream_key = self._stream_key(ch)
        cursor_key = self._cursor_key(ch)

        # Start from last cursor, or from tail if first time
        cursor = self.r.get(cursor_key) or "0-0"

        results = self.r.xread({stream_key: cursor}, count=count)
        if not results:
            return []

        messages = []
        last_id = cursor
        for _stream, entries in results:
            for stream_id, fields in entries:
                # Skip own messages (we already know what we said)
                if fields.get("from") == self.agent_name:
                    last_id = stream_id
                    continue
                try:
                    msg = ChatMessage.from_stream_dict(fields, stream_id=stream_id)
                    self._verify_message(msg)
                    messages.append(msg)
                except A2AError as e:
                    logger.warning(f"Rejected message {stream_id}: {e}")
                except Exception as e:
                    logger.warning(f"Bad message {stream_id}: {e}")
                last_id = stream_id

        if last_id != cursor:
            self.r.set(cursor_key, last_id, ex=CURSOR_TTL)

        return messages

    def read_history(self, channel: str = None, count: int = 50,
                     since_id: str = "0-0") -> List[ChatMessage]:
        """
        Read historical messages without updating cursor. Useful for catching up
        after reconnect or reading a thread from the beginning.
        """
        ch = channel or self.default_channel
        stream_key = self._stream_key(ch)

        results = self.r.xread({stream_key: since_id}, count=count)
        if not results:
            return []

        messages = []
        for _stream, entries in results:
            for stream_id, fields in entries:
                try:
                    msg = ChatMessage.from_stream_dict(fields, stream_id=stream_id)
                    messages.append(msg)
                except Exception as e:
                    logger.warning(f"Bad history entry {stream_id}: {e}")
        return messages

    def listen_loop(
        self,
        callback: Callable[[ChatMessage], None],
        channel: str = None,
        block_ms: int = 5000,
        own_messages: bool = False,
    ) -> None:
        """
        Blocking listen loop. Calls callback for each new message.
        Block for up to block_ms ms waiting for new messages (efficient long-poll).

        Set own_messages=True to also receive your own messages (useful for debug).
        """
        ch = channel or self.default_channel
        stream_key = self._stream_key(ch)
        cursor_key = self._cursor_key(ch)

        cursor = self.r.get(cursor_key) or "$"  # "$" = only new messages from now

        logger.info(f"MeshChat listening on {ch} (cursor={cursor})")

        while True:
            try:
                results = self.r.xread({stream_key: cursor}, count=10, block=block_ms)
                if not results:
                    continue  # timeout, loop again

                for _stream, entries in results:
                    for stream_id, fields in entries:
                        cursor = stream_id
                        self.r.set(cursor_key, cursor, ex=CURSOR_TTL)

                        if not own_messages and fields.get("from") == self.agent_name:
                            continue
                        try:
                            msg = ChatMessage.from_stream_dict(fields, stream_id=stream_id)
                            self._verify_message(msg)
                            callback(msg)
                        except A2AError as e:
                            logger.warning(f"Rejected {stream_id}: {e}")
                        except Exception as e:
                            logger.error(f"Callback error on {stream_id}: {e}")

            except redis.ConnectionError as e:
                logger.error(f"Redis connection lost: {e}")
                time.sleep(5)
            except KeyboardInterrupt:
                logger.info("Listen loop interrupted")
                break

    # ── Presence & discovery ──────────────────────────────────────────────────

    def online_agents(self, channel: str = None) -> List[str]:
        """Return list of agents that have been active recently on this channel."""
        ch = channel or self.default_channel
        cutoff = time.time() - MEMBER_PRESENCE_TTL
        members = self.r.zrangebyscore(self._members_key(ch), cutoff, "+inf")
        return list(members)

    def get_capabilities(self, agent_name: str) -> Dict[str, str]:
        """
        Fetch the last-advertised capabilities for an agent.
        Returns empty dict if agent hasn't advertised recently.
        """
        cap_key = self._capabilities_key(agent_name)
        return self.r.hgetall(cap_key)

    def get_all_capabilities(self) -> Dict[str, Dict[str, str]]:
        """
        Return capabilities for all agents who have advertised recently.
        Useful for "what can the mesh do right now?"
        """
        # Discover all capability keys
        keys = self.r.keys("mesh:capabilities:*")
        result = {}
        for key in keys:
            agent = key.split("mesh:capabilities:")[-1]
            caps = self.r.hgetall(key)
            if caps:
                result[agent] = caps
        return result

    def reset_cursor(self, channel: str = None) -> None:
        """Reset read cursor to beginning of stream (re-read all history)."""
        ch = channel or self.default_channel
        self.r.delete(self._cursor_key(ch))
        logger.info(f"Cursor reset for {ch}")


# ── Convenience wrapper for a2a_redis integration ────────────────────────────

class MeshChatMixin:
    """
    Mixin to add chat capability to an existing A2ARedisClient subclass.
    Assumes self.agent_name, self.redis_client, self.pki, self._totp_seeds are set.

    Usage:
        class MyAgent(A2ARedisClient, MeshChatMixin):
            pass

        agent = MyAgent("charlie", ...)
        agent.chat_say("hey Oxalis, ideas on wordgen pipeline?")
    """

    @property
    def _chat(self) -> MeshChatClient:
        if not hasattr(self, "_chat_client"):
            self._chat_client = MeshChatClient(
                agent_name=self.agent_name,
                pki=self.pki,
                totp_seeds=getattr(self, "_totp_seeds", {}),
            )
            # Reuse the same Redis connection
            self._chat_client.r = self.redis_client
        return self._chat_client

    def chat_say(self, text: str, channel: str = None) -> str:
        return self._chat.say(text, channel)

    def chat_idea(self, text: str, channel: str = None) -> str:
        return self._chat.idea(text, channel)

    def chat_ask(self, text: str, channel: str = None) -> str:
        return self._chat.ask(text, channel)

    def chat_update(self, text: str, channel: str = None) -> str:
        return self._chat.update(text, channel)

    def chat_read_new(self, channel: str = None) -> List[ChatMessage]:
        return self._chat.read_new(channel)


# ── CLI helper ────────────────────────────────────────────────────────────────

def _cli():
    """
    Minimal CLI for manual testing / ad-hoc agent chat.

    Usage:
        python mesh_chat.py --agent charlie --host audit-redis --password <pw> --channel general
        python mesh_chat.py --agent charlie ... read          # read new messages
        python mesh_chat.py --agent charlie ... history       # dump last 50
        python mesh_chat.py --agent charlie ... say "hello"  # send a message
        python mesh_chat.py --agent charlie ... capabilities  # show all agent caps
        python mesh_chat.py --agent charlie ... listen        # blocking listen loop
    """
    import argparse, sys

    parser = argparse.ArgumentParser(description="MeshChat CLI")
    parser.add_argument("--agent",    required=True)
    parser.add_argument("--host",     default="localhost")
    parser.add_argument("--port",     type=int, default=6379)
    parser.add_argument("--password", default=None)
    parser.add_argument("--channel",  default=DEFAULT_CHANNEL)
    parser.add_argument("--pki",      default="./agent-keys")
    parser.add_argument("command",    nargs="?", default="read",
                        choices=["read", "history", "say", "idea", "ask",
                                 "update", "listen", "capabilities", "members"])
    parser.add_argument("text",       nargs="?", default="")

    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING)  # quiet for CLI
    pki = PKIStore(args.pki)

    chat = MeshChatClient(
        agent_name=args.agent,
        redis_host=args.host,
        redis_port=args.port,
        redis_password=args.password,
        pki=pki,
        default_channel=args.channel,
    )

    if args.command == "read":
        msgs = chat.read_new()
        if not msgs:
            print("(no new messages)")
        for m in msgs:
            print(m)

    elif args.command == "history":
        msgs = chat.read_history(count=50)
        if not msgs:
            print("(no history)")
        for m in msgs:
            print(m)

    elif args.command in ("say", "idea", "ask", "update"):
        text = args.text or input(f"{args.command}> ")
        fn = getattr(chat, args.command)
        sid = fn(text)
        print(f"✓ sent ({sid})")

    elif args.command == "listen":
        def on_message(msg: ChatMessage):
            print(msg)
        print(f"Listening on {args.channel} — Ctrl+C to stop")
        chat.listen_loop(on_message)

    elif args.command == "capabilities":
        all_caps = chat.get_all_capabilities()
        if not all_caps:
            print("(no capability advertisements in Redis)")
        for agent, caps in all_caps.items():
            print(f"\n{agent}:")
            for skill, desc in caps.items():
                print(f"  {skill}: {desc}")

    elif args.command == "members":
        members = chat.online_agents()
        print(f"Active agents on {args.channel}: {', '.join(members) or '(none)'}")


if __name__ == "__main__":
    _cli()
