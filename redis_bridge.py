"""
redis_bridge.py — Offline-First Redis Mesh Bridge

Bidirectionally syncs two Redis instances so an agent can work locally
when disconnected and automatically catch up when the remote becomes reachable.

Use case: a portable agent (laptop, edge device) that has its own local Redis
and needs to stay in sync with a shared mesh Redis when connectivity allows.

Design:
  - Local Redis is always the source of truth for this agent
  - Remote Redis is the shared mesh backbone (may be unreachable)
  - Bidirectional sync over Redis Streams (mesh:chat:*) using cursor-based XREAD
  - Inbox queues (mesh:inbox:*) forwarded in both directions
  - When remote is unreachable: messages queue locally, bridge catches up on reconnect
  - Dedup via message ID tracking (no double-delivery)
  - Connectivity probe runs every PROBE_INTERVAL seconds
  - Lightweight: single process, no threads required (asyncio-based)

Configuration (env vars):

  LOCAL_REDIS_HOST         localhost
  LOCAL_REDIS_PORT         6379
  LOCAL_REDIS_PASSWORD     (optional)

  REMOTE_REDIS_HOST        (required)
  REMOTE_REDIS_PORT        6379
  REMOTE_REDIS_PASSWORD    (optional)

  BRIDGE_CHANNELS          general          comma-separated list of chat channels to sync
  BRIDGE_INBOX_AGENTS      agent1,agent2    agent inboxes to mirror (optional)
  BRIDGE_POLL_MS           500              poll interval when connected (ms)
  BRIDGE_PROBE_INTERVAL    10               connectivity probe interval (seconds)
  BRIDGE_LOG_LEVEL         INFO

Usage:

  # Basic: sync the "general" chat channel
  REMOTE_REDIS_HOST=192.168.1.100 REMOTE_REDIS_PASSWORD=secret python redis_bridge.py

  # Mirror inbox queues for specific agents too
  BRIDGE_INBOX_AGENTS=alice,bob REMOTE_REDIS_HOST=... python redis_bridge.py

  # Custom channels
  BRIDGE_CHANNELS=general,ops,findings REMOTE_REDIS_HOST=... python redis_bridge.py

Redis keys synced:

  mesh:chat:{channel}              — Redis Stream (bidirectional, cursor-based)
  mesh:chat:{channel}:members      — Sorted Set (merged, presence data)
  mesh:capabilities:{agent}        — Hash (remote→local only, read-only view of mesh)
  mesh:inbox:{agent}               — List queue (forwarded remote→local when agent is local)

Dedup keys (local only, not synced):

  bridge:seen:{message_id}         — TTL 10min, prevents double-delivery
  bridge:cursor:local:{channel}    — last stream ID read from local
  bridge:cursor:remote:{channel}   — last stream ID read from remote
"""

import os
import sys
import time
import logging
import signal
import asyncio
from datetime import datetime, timezone
from typing import Optional, List, Dict, Set

import redis
import redis.exceptions

# ── Configuration ──────────────────────────────────────────────────────────────

def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)

def _env_int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, default))
    except (ValueError, TypeError):
        return default

LOCAL_HOST      = _env("LOCAL_REDIS_HOST", "localhost")
LOCAL_PORT      = _env_int("LOCAL_REDIS_PORT", 6379)
LOCAL_PASSWORD  = _env("LOCAL_REDIS_PASSWORD") or None

REMOTE_HOST     = _env("REMOTE_REDIS_HOST")
REMOTE_PORT     = _env_int("REMOTE_REDIS_PORT", 6379)
REMOTE_PASSWORD = _env("REMOTE_REDIS_PASSWORD") or None

BRIDGE_CHANNELS      = [c.strip() for c in _env("BRIDGE_CHANNELS", "general").split(",") if c.strip()]
BRIDGE_INBOX_AGENTS  = [a.strip() for a in _env("BRIDGE_INBOX_AGENTS", "").split(",") if a.strip()]
POLL_MS              = _env_int("BRIDGE_POLL_MS", 500)
PROBE_INTERVAL       = _env_int("BRIDGE_PROBE_INTERVAL", 10)
LOG_LEVEL            = _env("BRIDGE_LOG_LEVEL", "INFO")

# Dedup TTL: how long to remember a forwarded message ID (seconds)
SEEN_TTL = 600

# Cursor TTL: persist read positions across restarts (1 week)
CURSOR_TTL = 86400 * 7

# Max messages to pull per poll cycle per channel
BATCH_SIZE = 100

# ── Logging ────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [bridge] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("redis_bridge")


# ── Bridge ─────────────────────────────────────────────────────────────────────

class RedisBridge:
    """
    Bidirectional Redis bridge with offline-first support.

    Syncs Redis Streams (chat) and List queues (inboxes) between a local
    and remote Redis instance. Tolerates remote unavailability gracefully.
    """

    def __init__(self):
        if not REMOTE_HOST:
            logger.error("REMOTE_REDIS_HOST is not set. Set it and retry.")
            sys.exit(1)

        self.local  = self._connect("local",  LOCAL_HOST,  LOCAL_PORT,  LOCAL_PASSWORD)
        self.remote: Optional[redis.Redis] = None
        self._remote_ok = False
        self._running = True
        self._stats = {
            "local_to_remote": 0,
            "remote_to_local": 0,
            "inbox_forwarded": 0,
            "dedup_skipped":   0,
            "reconnects":      0,
        }

    # ── Connection management ─────────────────────────────────────────────────

    def _connect(self, label: str, host: str, port: int, password: Optional[str]) -> redis.Redis:
        r = redis.Redis(host=host, port=port, password=password, decode_responses=True,
                        socket_connect_timeout=3, socket_timeout=5)
        logger.info(f"Redis client configured: {label} → {host}:{port}")
        return r

    def _probe_remote(self) -> bool:
        """Try to ping remote Redis. Returns True if reachable."""
        try:
            if self.remote is None:
                self.remote = self._connect(
                    "remote", REMOTE_HOST, REMOTE_PORT, REMOTE_PASSWORD
                )
            self.remote.ping()
            return True
        except (redis.exceptions.ConnectionError,
                redis.exceptions.TimeoutError,
                redis.exceptions.AuthenticationError,
                OSError) as e:
            logger.debug(f"Remote unreachable: {e}")
            self.remote = None
            return False

    def _ensure_remote(self) -> bool:
        """Return True if remote is currently reachable."""
        return self._remote_ok

    # ── Dedup ─────────────────────────────────────────────────────────────────

    def _seen(self, msg_id: str) -> bool:
        """Return True if we've already forwarded this message."""
        key = f"bridge:seen:{msg_id}"
        result = self.local.set(key, "1", nx=True, ex=SEEN_TTL)
        if result is None:
            # Key already existed
            self._stats["dedup_skipped"] += 1
            return True
        return False

    # ── Cursor management ─────────────────────────────────────────────────────

    def _get_cursor(self, direction: str, channel: str) -> str:
        """Load saved stream cursor. Returns '0-0' if none saved."""
        key = f"bridge:cursor:{direction}:{channel}"
        return self.local.get(key) or "0-0"

    def _save_cursor(self, direction: str, channel: str, stream_id: str) -> None:
        key = f"bridge:cursor:{direction}:{channel}"
        self.local.set(key, stream_id, ex=CURSOR_TTL)

    # ── Stream sync ───────────────────────────────────────────────────────────

    def _sync_stream_one_direction(
        self,
        src: redis.Redis,
        dst: redis.Redis,
        channel: str,
        cursor_key: str,
    ) -> int:
        """
        Read new messages from src stream and write them to dst stream.
        Returns number of messages forwarded.
        """
        stream_key = f"mesh:chat:{channel}"
        cursor = self._get_cursor(cursor_key, channel)

        try:
            results = src.xread({stream_key: cursor}, count=BATCH_SIZE)
        except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError):
            raise

        if not results:
            return 0

        forwarded = 0
        last_id = cursor

        for _stream, entries in results:
            for stream_id, fields in entries:
                last_id = stream_id
                msg_id = fields.get("id", stream_id)

                if self._seen(f"{cursor_key}:{msg_id}"):
                    continue

                try:
                    dst.xadd(stream_key, fields, maxlen=500, approximate=True)
                    forwarded += 1
                except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError):
                    raise
                except Exception as e:
                    logger.warning(f"Failed to forward message {msg_id}: {e}")

        if last_id != cursor:
            self._save_cursor(cursor_key, channel, last_id)

        return forwarded

    def sync_streams(self) -> None:
        """Bidirectional stream sync for all configured channels."""
        for channel in BRIDGE_CHANNELS:
            # local → remote
            try:
                n = self._sync_stream_one_direction(
                    self.local, self.remote, channel, "local"
                )
                if n:
                    self._stats["local_to_remote"] += n
                    logger.debug(f"↑ {channel}: forwarded {n} msgs local→remote")
            except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError) as e:
                logger.warning(f"Remote write failed during local→remote sync: {e}")
                self._remote_ok = False
                return

            # remote → local
            try:
                n = self._sync_stream_one_direction(
                    self.remote, self.local, channel, "remote"
                )
                if n:
                    self._stats["remote_to_local"] += n
                    logger.debug(f"↓ {channel}: forwarded {n} msgs remote→local")
            except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError) as e:
                logger.warning(f"Remote read failed during remote→local sync: {e}")
                self._remote_ok = False
                return

    # ── Inbox forwarding ──────────────────────────────────────────────────────

    def sync_inbox(self, agent: str) -> None:
        """
        Forward queued messages from remote inbox → local inbox for a given agent.
        Useful when an agent lives locally but receives messages sent to the remote mesh.
        """
        if not self._remote_ok:
            return

        inbox_key = f"mesh:inbox:{agent}"

        while True:
            try:
                msg_json = self.remote.lpop(inbox_key)
            except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError) as e:
                logger.warning(f"Remote unavailable during inbox sync for {agent}: {e}")
                self._remote_ok = False
                break

            if not msg_json:
                break

            # Extract message ID for dedup (best-effort JSON parse)
            try:
                import json
                msg_id = json.loads(msg_json).get("id", msg_json[:64])
            except Exception:
                msg_id = msg_json[:64]

            if self._seen(f"inbox:{msg_id}"):
                continue

            self.local.rpush(inbox_key, msg_json)
            self._stats["inbox_forwarded"] += 1
            logger.debug(f"↓ inbox/{agent}: forwarded message {msg_id[:8]}…")

    # ── Presence merge ────────────────────────────────────────────────────────

    def sync_presence(self, channel: str) -> None:
        """Merge remote member presence into local (remote → local only)."""
        if not self._remote_ok:
            return

        members_key = f"mesh:chat:{channel}:members"
        try:
            remote_members = self.remote.zrangebyscore(
                members_key, "-inf", "+inf", withscores=True
            )
            if remote_members:
                self.local.zadd(members_key, dict(remote_members))
        except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError):
            self._remote_ok = False

    # ── Capability sync ───────────────────────────────────────────────────────

    def sync_capabilities(self) -> None:
        """Pull remote agent capabilities into local Redis (read-only view of mesh)."""
        if not self._remote_ok:
            return

        try:
            keys = self.remote.keys("mesh:capabilities:*")
        except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError):
            self._remote_ok = False
            return

        for key in keys:
            try:
                caps = self.remote.hgetall(key)
                if caps:
                    ttl = self.remote.ttl(key)
                    self.local.hset(key, mapping=caps)
                    if ttl and ttl > 0:
                        self.local.expire(key, ttl)
            except Exception as e:
                logger.debug(f"Capability sync failed for {key}: {e}")

    # ── Stats ─────────────────────────────────────────────────────────────────

    def log_stats(self) -> None:
        s = self._stats
        status = "CONNECTED" if self._remote_ok else "OFFLINE"
        logger.info(
            f"[{status}] ↑{s['local_to_remote']} ↓{s['remote_to_local']} "
            f"inbox:{s['inbox_forwarded']} dedup:{s['dedup_skipped']} "
            f"reconnects:{s['reconnects']}"
        )

    # ── Main loop ─────────────────────────────────────────────────────────────

    def run(self) -> None:
        """Main bridge loop. Runs until SIGINT/SIGTERM."""
        logger.info(
            f"Bridge starting: local={LOCAL_HOST}:{LOCAL_PORT} "
            f"remote={REMOTE_HOST}:{REMOTE_PORT} "
            f"channels={BRIDGE_CHANNELS}"
        )

        signal.signal(signal.SIGINT,  lambda *_: self._stop())
        signal.signal(signal.SIGTERM, lambda *_: self._stop())

        last_probe  = 0.0
        last_stats  = 0.0
        poll_secs   = POLL_MS / 1000.0

        while self._running:
            now = time.monotonic()

            # Periodic connectivity probe
            if now - last_probe >= PROBE_INTERVAL:
                was_ok = self._remote_ok
                self._remote_ok = self._probe_remote()
                if self._remote_ok and not was_ok:
                    self._stats["reconnects"] += 1
                    logger.info("Remote Redis reconnected — catching up…")
                elif not self._remote_ok and was_ok:
                    logger.warning("Remote Redis went offline — buffering locally")
                last_probe = now

            # Sync if remote is available
            if self._remote_ok:
                try:
                    self.sync_streams()
                    for agent in BRIDGE_INBOX_AGENTS:
                        self.sync_inbox(agent)
                    for channel in BRIDGE_CHANNELS:
                        self.sync_presence(channel)
                    self.sync_capabilities()
                except Exception as e:
                    logger.error(f"Sync error: {e}", exc_info=False)

            # Log stats every 60s
            if now - last_stats >= 60:
                self.log_stats()
                last_stats = now

            time.sleep(poll_secs)

        logger.info("Bridge stopped.")
        self.log_stats()

    def _stop(self) -> None:
        logger.info("Shutdown requested…")
        self._running = False


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    bridge = RedisBridge()
    bridge.run()
