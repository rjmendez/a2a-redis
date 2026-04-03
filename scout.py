"""
scout.py — Scout Layer for Agent Mesh

Lightweight client for scout processes that run under a parent agent's identity.
Scouts are task-specific sub-processes (persistent crawlers or ephemeral snapshots)
that inherit their host's PKI rather than managing their own keypairs.

Design goals:
  - Identity delegation: scouts sign as "{host}/{scout_id}" using host's private key
  - Ephemeral-friendly: one-shot scouts can publish findings and exit cleanly
  - Persistent-friendly: long-running scouts maintain cursors across restarts
  - Structured findings: typed result payloads alongside freeform mesh chat
  - Host relay: host agent controls what scout output reaches the shared mesh
  - Zero new key management: no keypairs per scout

Scout identity model:

    host agent (has keypair: alice)
    └── scout (signs as "alice/osint-crawler", using alice's private key)

Scouts are always attributable to their host. The mesh sees provenance clearly:
  from: "alice/osint-crawler"   — long-running OSINT crawler owned by alice
  from: "alice/snapshot-42a1"   — ephemeral snapshot, auto-ID

Message kinds (extends mesh_chat.py kinds):

  Inherited from mesh_chat:
    chat        — freeform text
    idea        — design proposal
    question    — expects response
    update      — status/progress
    join        — agent came online
    leave       — agent going offline
    capability  — skill advertisement
    ack         — reply/acknowledgement

  Added by scout.py:
    finding     — structured result with severity + evidence
    snapshot    — point-in-time data capture (structured or freeform)
    heartbeat   — scout liveness signal (periodic, not task-driven)
    error       — scout-reported error or failure condition
    task_start  — scout announcing it has begun a task
    task_done   — scout announcing task completion (with summary)

Redis keys:

  mesh:chat:{channel}                     — shared stream (same as mesh_chat.py)
  mesh:scouts:{host}                      — Hash: scout_id → last_seen ts
  mesh:scouts:{host}:{scout_id}:state     — Hash: arbitrary scout state (TTL managed)

Usage — ephemeral scout (one-shot):

    from scout import ScoutClient
    from a2a_redis import PKIStore

    pki = PKIStore("./agent-keys")

    with ScoutClient.ephemeral("alice", pki=pki) as scout:
        # do work...
        scout.finding(
            title="Exposed API key in public repo",
            severity="high",
            evidence={"repo": "example/repo", "file": "config.py", "line": 42},
        )
        scout.snapshot({"targets_checked": 150, "elapsed_s": 3.2})
        # context manager sends task_done + leave on exit

Usage — persistent scout:

    from scout import ScoutClient
    from a2a_redis import PKIStore

    pki = PKIStore("./agent-keys")
    scout = ScoutClient(
        host_agent="alice",
        scout_id="osint-crawler",
        pki=pki,
        redis_host="localhost",
        redis_port=6379,
    )
    scout.join()
    scout.advertise_capabilities({"web_crawl": "OSINT web crawling", "dns_enum": "DNS enumeration"})

    while running:
        result = do_work()
        scout.update(f"Processed {result.count} targets")
        if result.findings:
            for f in result.findings:
                scout.finding(title=f.title, severity=f.severity, evidence=f.data)

    scout.leave()

Host relay usage:

    from scout import HostRelay

    relay = HostRelay(
        host_agent="alice",
        local_redis=local_r,
        mesh_redis=mesh_r,
        pki=pki,
    )

    # Forward only high/critical findings to the shared mesh
    relay.relay_findings(min_severity="high", channel="findings")

    # Forward all scout updates to mesh ops channel
    relay.relay_updates(channel="ops")
"""

import os
import json
import uuid
import time
import base64
import logging
from datetime import datetime, timezone
from contextlib import contextmanager
from typing import Optional, Dict, Any, List, Callable

import redis
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from a2a_redis import PKIStore, A2AError, SignatureError, TOTPError
from mesh_chat import (
    MeshChatClient, ChatMessage,
    KIND_CHAT, KIND_IDEA, KIND_QUESTION, KIND_UPDATE,
    KIND_JOIN, KIND_LEAVE, KIND_CAPABILITY, KIND_ACK,
    DEFAULT_CHANNEL, STREAM_MAX_LEN, CURSOR_TTL,
    MESSAGE_MAX_AGE, CAPABILITIES_TTL,
)

import pyotp

logger = logging.getLogger(__name__)

# ── Scout message kinds ────────────────────────────────────────────────────────

KIND_FINDING    = "finding"     # structured result with severity + evidence
KIND_SNAPSHOT   = "snapshot"    # point-in-time data capture
KIND_HEARTBEAT  = "heartbeat"   # liveness signal
KIND_ERROR      = "error"       # scout-reported error or failure
KIND_TASK_START = "task_start"  # beginning a task
KIND_TASK_DONE  = "task_done"   # task complete

ALL_KINDS = [
    KIND_CHAT, KIND_IDEA, KIND_QUESTION, KIND_UPDATE,
    KIND_JOIN, KIND_LEAVE, KIND_CAPABILITY, KIND_ACK,
    KIND_FINDING, KIND_SNAPSHOT, KIND_HEARTBEAT,
    KIND_ERROR, KIND_TASK_START, KIND_TASK_DONE,
]

# Severity levels (for finding kind)
SEVERITY_LEVELS = ["info", "low", "medium", "high", "critical"]

# Scout presence TTL
SCOUT_PRESENCE_TTL = 3600  # 1 hour — scouts may be long-running

# Scout state TTL
SCOUT_STATE_TTL = 86400  # 24 hours


# ── ScoutClient ────────────────────────────────────────────────────────────────

class ScoutClient:
    """
    Lightweight mesh client for scouts running under a host agent's identity.

    Scouts sign as "{host_agent}/{scout_id}" using the host's private key.
    No separate keypair required — identity is derived from the host.
    """

    def __init__(
        self,
        host_agent: str,
        scout_id: Optional[str] = None,
        pki: Optional[PKIStore] = None,
        redis_host: str = "localhost",
        redis_port: int = 6379,
        redis_password: Optional[str] = None,
        totp_seeds: Optional[Dict[str, str]] = None,
        default_channel: str = DEFAULT_CHANNEL,
        ephemeral: bool = False,
    ):
        """
        Args:
            host_agent:  Parent agent name (must have a keypair in pki).
            scout_id:    Unique ID for this scout. Auto-generated if None.
                         Use a stable ID (e.g. "osint-crawler") for persistent scouts.
                         Ephemeral scouts get a short random suffix by default.
            pki:         PKI store containing the host agent's keypair.
            ephemeral:   If True, scout announces itself as ephemeral (no persistent cursor).
        """
        self.host_agent = host_agent
        self.scout_id = scout_id or (
            f"scout-{uuid.uuid4().hex[:8]}" if ephemeral else "scout"
        )
        self.agent_name = f"{host_agent}/{self.scout_id}"
        self.pki = pki or PKIStore()
        self._totp_seeds: Dict[str, str] = totp_seeds or {}
        self.default_channel = default_channel
        self.is_ephemeral = ephemeral

        self.r = redis.Redis(
            host=redis_host,
            port=redis_port,
            password=redis_password,
            decode_responses=True,
        )

        logger.info(f"ScoutClient initialized: {self.agent_name} (ephemeral={ephemeral})")

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _sign(self, msg: ChatMessage) -> Optional[str]:
        """Sign using host agent's private key."""
        try:
            private_key = self.pki.load_private_key(self.host_agent)
            sig_bytes = private_key.sign(
                msg.signing_payload().encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return base64.b64encode(sig_bytes).decode()
        except FileNotFoundError:
            logger.warning(f"No private key for host {self.host_agent} — sending unsigned")
            return None

    def _publish(self, text: str, kind: str, channel: Optional[str] = None,
                 extra: Optional[Dict[str, Any]] = None, reply_to: Optional[str] = None) -> str:
        """
        Build, sign, and push a message to the stream.
        `extra` fields are JSON-encoded into the `data` field for structured payloads.
        """
        ch = channel or self.default_channel
        stream_key = f"mesh:chat:{ch}"

        msg = ChatMessage(
            id=str(uuid.uuid4()),
            from_agent=self.agent_name,
            channel=ch,
            ts=datetime.now(timezone.utc).isoformat(),
            text=text,
            kind=kind,
            reply_to=reply_to,
        )

        msg.signature = self._sign(msg)

        seed = self._totp_seeds.get("__default__")
        if seed:
            msg.totp = pyotp.TOTP(seed).now()

        fields = msg.to_stream_dict()
        if extra:
            fields["data"] = json.dumps(extra)

        stream_id = self.r.xadd(stream_key, fields, maxlen=STREAM_MAX_LEN, approximate=True)

        # Update scout presence registry
        self.r.hset(
            f"mesh:scouts:{self.host_agent}",
            self.scout_id,
            datetime.now(timezone.utc).isoformat(),
        )
        self.r.expire(f"mesh:scouts:{self.host_agent}", SCOUT_PRESENCE_TTL)

        logger.debug(f"→ [{kind}] {self.agent_name}: {text[:80]}")
        return stream_id

    # ── Presence ──────────────────────────────────────────────────────────────

    def join(self, channel: Optional[str] = None) -> str:
        """Announce scout is online."""
        kind_label = "ephemeral" if self.is_ephemeral else "persistent"
        return self._publish(
            f"{self.agent_name} online ({kind_label})",
            KIND_JOIN, channel,
        )

    def leave(self, channel: Optional[str] = None) -> str:
        """Announce scout is going offline."""
        try:
            sid = self._publish(f"{self.agent_name} offline", KIND_LEAVE, channel)
            self.r.hdel(f"mesh:scouts:{self.host_agent}", self.scout_id)
            return sid
        except Exception as e:
            logger.warning(f"Leave message failed: {e}")
            return ""

    def heartbeat(self, status: Optional[str] = None, channel: Optional[str] = None) -> str:
        """Publish a liveness signal. Call periodically from long-running scouts."""
        text = status or f"{self.agent_name} alive"
        return self._publish(text, KIND_HEARTBEAT, channel)

    # ── Task lifecycle ────────────────────────────────────────────────────────

    def task_start(self, task: str, params: Optional[Dict] = None,
                   channel: Optional[str] = None) -> str:
        """Announce beginning of a task."""
        return self._publish(task, KIND_TASK_START, channel, extra=params)

    def task_done(self, summary: str, stats: Optional[Dict] = None,
                  channel: Optional[str] = None) -> str:
        """Announce task completion with optional stats."""
        return self._publish(summary, KIND_TASK_DONE, channel, extra=stats)

    # ── Output ────────────────────────────────────────────────────────────────

    def finding(
        self,
        title: str,
        severity: str = "info",
        evidence: Optional[Dict[str, Any]] = None,
        channel: Optional[str] = None,
    ) -> str:
        """
        Publish a structured finding.

        Args:
            title:     Short description of the finding.
            severity:  One of: info, low, medium, high, critical.
            evidence:  Arbitrary structured data supporting the finding.
            channel:   Target channel (default: self.default_channel).
        """
        if severity not in SEVERITY_LEVELS:
            raise ValueError(f"severity must be one of {SEVERITY_LEVELS}")

        extra = {"severity": severity}
        if evidence:
            extra["evidence"] = evidence

        return self._publish(title, KIND_FINDING, channel, extra=extra)

    def snapshot(
        self,
        data: Dict[str, Any],
        label: Optional[str] = None,
        channel: Optional[str] = None,
    ) -> str:
        """
        Publish a point-in-time data snapshot.

        Args:
            data:   Arbitrary dict of snapshot data.
            label:  Optional human-readable label for the snapshot.
            channel: Target channel.
        """
        text = label or f"snapshot from {self.agent_name}"
        return self._publish(text, KIND_SNAPSHOT, channel, extra=data)

    def update(self, text: str, channel: Optional[str] = None) -> str:
        """Publish a status or progress update."""
        return self._publish(text, KIND_UPDATE, channel)

    def error(self, message: str, detail: Optional[Dict] = None,
              channel: Optional[str] = None) -> str:
        """Report an error or failure condition."""
        return self._publish(message, KIND_ERROR, channel, extra=detail)

    def say(self, text: str, channel: Optional[str] = None) -> str:
        """Freeform chat message."""
        return self._publish(text, KIND_CHAT, channel)

    # ── State ─────────────────────────────────────────────────────────────────

    def set_state(self, key: str, value: str) -> None:
        """Store arbitrary persistent state for this scout."""
        state_key = f"mesh:scouts:{self.host_agent}:{self.scout_id}:state"
        self.r.hset(state_key, key, value)
        self.r.expire(state_key, SCOUT_STATE_TTL)

    def get_state(self, key: str) -> Optional[str]:
        """Retrieve persistent state value."""
        state_key = f"mesh:scouts:{self.host_agent}:{self.scout_id}:state"
        return self.r.hget(state_key, key)

    def get_all_state(self) -> Dict[str, str]:
        """Retrieve all persistent state for this scout."""
        state_key = f"mesh:scouts:{self.host_agent}:{self.scout_id}:state"
        return self.r.hgetall(state_key) or {}

    def clear_state(self) -> None:
        """Delete all persistent state for this scout."""
        self.r.delete(f"mesh:scouts:{self.host_agent}:{self.scout_id}:state")

    # ── Cursor-based reading (persistent scouts) ──────────────────────────────

    def read_new(self, channel: Optional[str] = None, count: int = 50) -> List[ChatMessage]:
        """
        Read new messages since last cursor (persistent scouts only).
        Ephemeral scouts should use MeshChatClient.read_history() directly.
        """
        ch = channel or self.default_channel
        stream_key = f"mesh:chat:{ch}"
        cursor_key = f"mesh:chat:{ch}:cursor:{self.agent_name}"

        cursor = self.r.get(cursor_key) or "0-0"
        results = self.r.xread({stream_key: cursor}, count=count)
        if not results:
            return []

        messages = []
        last_id = cursor
        for _stream, entries in results:
            for stream_id, fields in entries:
                if fields.get("from") == self.agent_name:
                    last_id = stream_id
                    continue
                try:
                    messages.append(ChatMessage.from_stream_dict(fields, stream_id=stream_id))
                except Exception as e:
                    logger.warning(f"Bad message {stream_id}: {e}")
                last_id = stream_id

        if last_id != cursor:
            self.r.set(cursor_key, last_id, ex=CURSOR_TTL)

        return messages

    # ── Context manager (ephemeral scouts) ───────────────────────────────────

    def __enter__(self) -> "ScoutClient":
        self.join()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if exc_type is not None:
            self.error(f"Scout exiting with error: {exc_val}")
        self.leave()

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def ephemeral(
        cls,
        host_agent: str,
        scout_id: Optional[str] = None,
        **kwargs,
    ) -> "ScoutClient":
        """
        Create an ephemeral (one-shot) scout.
        Best used as a context manager:

            with ScoutClient.ephemeral("alice", pki=pki) as scout:
                scout.finding("Found exposed key", severity="high", evidence={...})
        """
        return cls(host_agent=host_agent, scout_id=scout_id, ephemeral=True, **kwargs)


# ── HostRelay ──────────────────────────────────────────────────────────────────

class HostRelay:
    """
    Filters and forwards scout output from a local Redis to the shared mesh Redis.

    The host agent controls what scout findings are worth sharing with the mesh.
    This prevents noisy scout output from flooding shared channels while still
    surfacing important findings to peers.

    Relay runs as a one-shot batch (call from heartbeat/cron) or as a loop.
    """

    SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITY_LEVELS)}

    def __init__(
        self,
        host_agent: str,
        local_redis: redis.Redis,
        mesh_redis: redis.Redis,
        pki: Optional[PKIStore] = None,
        totp_seeds: Optional[Dict[str, str]] = None,
    ):
        self.host_agent = host_agent
        self.local = local_redis
        self.mesh = mesh_redis
        self.pki = pki or PKIStore()
        self._totp_seeds = totp_seeds or {}
        self._stats = {"relayed": 0, "filtered": 0}

    def _relay_stream(
        self,
        src_channel: str,
        dst_channel: str,
        filter_fn: Optional[Callable[[ChatMessage, Optional[Dict]], bool]] = None,
        cursor_suffix: str = "relay",
        batch: int = 100,
    ) -> int:
        """
        Read from local stream, apply filter, write matching messages to mesh stream.
        Returns number of messages relayed.
        """
        src_key = f"mesh:chat:{src_channel}"
        dst_key = f"mesh:chat:{dst_channel}"
        cursor_key = f"bridge:relay:cursor:{cursor_suffix}:{src_channel}"

        cursor = self.local.get(cursor_key) or "0-0"
        results = self.local.xread({src_key: cursor}, count=batch)
        if not results:
            return 0

        relayed = 0
        last_id = cursor

        for _stream, entries in results:
            for stream_id, fields in entries:
                last_id = stream_id
                try:
                    msg = ChatMessage.from_stream_dict(fields, stream_id=stream_id)
                    extra = json.loads(fields["data"]) if "data" in fields else None

                    if filter_fn and not filter_fn(msg, extra):
                        self._stats["filtered"] += 1
                        continue

                    # Re-stamp relay origin, preserve original sender
                    relay_fields = dict(fields)
                    relay_fields["relayed_by"] = self.host_agent
                    self.mesh.xadd(dst_key, relay_fields, maxlen=STREAM_MAX_LEN, approximate=True)
                    relayed += 1
                    self._stats["relayed"] += 1

                except Exception as e:
                    logger.warning(f"Relay error on {stream_id}: {e}")

        if last_id != cursor:
            self.local.set(cursor_key, last_id, ex=CURSOR_TTL)

        return relayed

    def relay_findings(
        self,
        min_severity: str = "medium",
        src_channel: str = DEFAULT_CHANNEL,
        dst_channel: str = "findings",
    ) -> int:
        """
        Forward findings at or above min_severity to the mesh findings channel.
        """
        min_level = self.SEVERITY_ORDER.get(min_severity, 0)

        def findings_filter(msg: ChatMessage, extra: Optional[Dict]) -> bool:
            if msg.kind != KIND_FINDING:
                return False
            if not extra:
                return True  # no severity data — pass through
            sev = extra.get("severity", "info")
            return self.SEVERITY_ORDER.get(sev, 0) >= min_level

        n = self._relay_stream(src_channel, dst_channel, findings_filter,
                               cursor_suffix=f"findings-{min_severity}")
        if n:
            logger.info(f"Relayed {n} findings (≥{min_severity}) → mesh:{dst_channel}")
        return n

    def relay_updates(
        self,
        src_channel: str = DEFAULT_CHANNEL,
        dst_channel: str = "ops",
        kinds: Optional[List[str]] = None,
    ) -> int:
        """
        Forward messages of specified kinds to the mesh.
        Defaults to: update, task_start, task_done, error, heartbeat.
        """
        target_kinds = set(kinds or [KIND_UPDATE, KIND_TASK_START, KIND_TASK_DONE,
                                     KIND_ERROR, KIND_HEARTBEAT])

        def updates_filter(msg: ChatMessage, extra: Optional[Dict]) -> bool:
            return msg.kind in target_kinds

        n = self._relay_stream(src_channel, dst_channel, updates_filter,
                               cursor_suffix="updates")
        if n:
            logger.info(f"Relayed {n} updates → mesh:{dst_channel}")
        return n

    def relay_all(
        self,
        src_channel: str = DEFAULT_CHANNEL,
        dst_channel: Optional[str] = None,
    ) -> int:
        """Relay everything — useful for debugging or trusted private meshes."""
        n = self._relay_stream(src_channel, dst_channel or src_channel,
                               filter_fn=None, cursor_suffix="all")
        if n:
            logger.info(f"Relayed {n} messages (unfiltered) → mesh:{dst_channel}")
        return n

    def stats(self) -> Dict[str, int]:
        return dict(self._stats)


# ── Scout registry helpers ─────────────────────────────────────────────────────

def list_scouts(r: redis.Redis, host_agent: str) -> Dict[str, str]:
    """Return {scout_id: last_seen_ts} for all scouts under a host agent."""
    return r.hgetall(f"mesh:scouts:{host_agent}") or {}


def list_all_scouts(r: redis.Redis) -> Dict[str, Dict[str, str]]:
    """Return all scout registrations across all host agents."""
    keys = r.keys("mesh:scouts:*")
    result = {}
    for key in keys:
        # Skip sub-keys like mesh:scouts:{host}:{scout_id}:state
        parts = key.split(":")
        if len(parts) != 3:
            continue
        host = parts[2]
        scouts = r.hgetall(key)
        if scouts:
            result[host] = scouts
    return result


# ── CLI ────────────────────────────────────────────────────────────────────────

def _cli():
    """
    Minimal CLI for manual scout testing.

    Usage:
        python scout.py --host alice --id osint-crawler --redis-host localhost finding \\
            --title "Exposed key" --severity high

        python scout.py --host alice --id crawler list-scouts
    """
    import argparse

    parser = argparse.ArgumentParser(description="Scout CLI")
    parser.add_argument("--host",       required=True, help="Host agent name")
    parser.add_argument("--id",         default=None,  help="Scout ID (default: auto)")
    parser.add_argument("--redis-host", default="localhost")
    parser.add_argument("--redis-port", type=int, default=6379)
    parser.add_argument("--redis-pass", default=None)
    parser.add_argument("--channel",    default=DEFAULT_CHANNEL)
    parser.add_argument("--pki",        default="./agent-keys")
    parser.add_argument("--ephemeral",  action="store_true")
    parser.add_argument("command", choices=[
        "join", "leave", "heartbeat", "update", "snapshot",
        "finding", "task-start", "task-done", "error",
        "list-scouts", "state-get", "state-set",
    ])
    parser.add_argument("text", nargs="?", default="")

    # finding-specific
    parser.add_argument("--title",    default="")
    parser.add_argument("--severity", default="info", choices=SEVERITY_LEVELS)
    parser.add_argument("--evidence", default=None, help="JSON string")

    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING)
    pki = PKIStore(args.pki)

    scout = ScoutClient(
        host_agent=args.host,
        scout_id=args.id,
        pki=pki,
        redis_host=args.redis_host,
        redis_port=args.redis_port,
        redis_password=args.redis_pass,
        default_channel=args.channel,
        ephemeral=args.ephemeral,
    )

    cmd = args.command

    if cmd == "join":
        print("✓", scout.join())
    elif cmd == "leave":
        print("✓", scout.leave())
    elif cmd == "heartbeat":
        print("✓", scout.heartbeat(args.text or None))
    elif cmd == "update":
        print("✓", scout.update(args.text))
    elif cmd == "finding":
        title = args.title or args.text
        evidence = json.loads(args.evidence) if args.evidence else None
        print("✓", scout.finding(title, args.severity, evidence))
    elif cmd == "snapshot":
        data = json.loads(args.text) if args.text else {}
        print("✓", scout.snapshot(data))
    elif cmd == "task-start":
        print("✓", scout.task_start(args.text))
    elif cmd == "task-done":
        print("✓", scout.task_done(args.text))
    elif cmd == "error":
        print("✓", scout.error(args.text))
    elif cmd == "list-scouts":
        import redis as redispy
        r = redispy.Redis(host=args.redis_host, port=args.redis_port,
                          password=args.redis_pass, decode_responses=True)
        all_scouts = list_all_scouts(r)
        if not all_scouts:
            print("(no scouts registered)")
        for host, scouts in all_scouts.items():
            print(f"\n{host}:")
            for sid, last_seen in scouts.items():
                print(f"  {sid}: last seen {last_seen}")
    elif cmd in ("state-get", "state-set"):
        parts = args.text.split("=", 1)
        if cmd == "state-set" and len(parts) == 2:
            scout.set_state(parts[0], parts[1])
            print(f"✓ set {parts[0]}")
        elif cmd == "state-get":
            print(scout.get_state(parts[0]))


if __name__ == "__main__":
    _cli()
