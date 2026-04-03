"""
Example: A2A Agent Worker Loop

Demonstrates a real agent that:
1. Listens for incoming A2A messages
2. Processes tasks (e.g., hashcat cracking)
3. Replies with results
4. Handles timeouts and errors gracefully
"""

import logging
import signal
import sys
import time
from typing import Optional, Dict, Any, Callable

from a2a_redis import A2ARedisClient, PKIStore, A2AError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class A2AAgent:
    """Base agent with handler registration and graceful shutdown."""

    def __init__(self, agent_name: str, redis_host: str, redis_port: int,
                 redis_password: Optional[str], totp_seeds: Optional[Dict[str, str]],
                 pki: PKIStore):
        self.agent_name = agent_name
        self.client = A2ARedisClient(
            agent_name=agent_name,
            redis_host=redis_host,
            redis_port=redis_port,
            redis_password=redis_password,
            totp_seeds=totp_seeds,
            pki=pki
        )
        self.handlers: Dict[str, Callable] = {}
        self._running = True

        # Graceful shutdown on SIGTERM/SIGINT
        signal.signal(signal.SIGTERM, self._shutdown)
        signal.signal(signal.SIGINT, self._shutdown)

    def _shutdown(self, signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        self._running = False

    def register_handler(self, method: str, func: Callable):
        """Register a handler for a specific method."""
        self.handlers[method] = func
        logger.info(f"✓ Registered handler: {method}")

    def handle_message(self, from_agent: str, method: str, params: Dict) -> Dict:
        """Route and process an incoming message."""
        if method not in self.handlers:
            return {"status": "error", "message": f"Unknown method: {method}",
                    "available": list(self.handlers.keys())}

        try:
            handler = self.handlers[method]
            result = handler(**params)
            return {"status": "ok", "result": result}
        except TypeError as e:
            # Bad params (missing/extra kwargs)
            logger.error(f"Bad params for {method}: {e}")
            return {"status": "error", "message": f"Invalid params: {e}"}
        except Exception as e:
            logger.error(f"Error handling {method}: {e}")
            return {"status": "error", "message": str(e)}

    def run(self, listen_timeout: int = 30):
        """Main loop: listen → process → reply."""
        # Health check
        if not self.client.ping():
            logger.error("Cannot connect to Redis. Exiting.")
            sys.exit(1)

        logger.info(f"✓ {self.agent_name} online, listening for A2A messages...")

        while self._running:
            try:
                result = self.client.listen(timeout_seconds=listen_timeout)

                if not result:
                    continue

                msg_id, from_agent, method, params = result

                # Process
                response = self.handle_message(from_agent, method, params)

                # Always reply (caller may or may not be waiting)
                self.client.reply(msg_id, from_agent, response)

            except A2AError as e:
                # Auth/replay/staleness errors — log and skip (don't crash)
                logger.warning(f"Rejected message: {e}")
            except Exception as e:
                logger.error(f"Unexpected error: {e}")
                time.sleep(1)  # Backoff

        logger.info(f"{self.agent_name} stopped.")


# ── Example Handlers ──────────────────────────────────────────────────────────

def crack_hash(target_hash: str, hash_type: int, wordlist: str = None) -> Dict:
    """Simulate hash cracking."""
    logger.info(f"Cracking hash {target_hash[:16]}... (type={hash_type})")
    time.sleep(0.5)
    return {"cracked": False, "attempts": 1000}


def reverse_binary(binary_path: str, analysis_level: int = 3) -> Dict:
    """Simulate binary reverse engineering."""
    logger.info(f"Analyzing {binary_path} (level={analysis_level})")
    time.sleep(1)
    return {"functions": 42, "strings": 120, "entropy": 7.2}


def scan_target(target: str, depth: int = 1) -> Dict:
    """Simulate reconnaissance scan."""
    logger.info(f"Scanning {target} (depth={depth})")
    time.sleep(2)
    return {"open_ports": [80, 443], "services": ["http", "https"]}


def get_status() -> Dict:
    """Return agent status."""
    return {"status": "online", "uptime": time.time()}


if __name__ == "__main__":
    import os

    agent_name = os.environ.get("AGENT_NAME", "worker-1")
    redis_host = os.environ.get("REDIS_HOST", "localhost")
    redis_port = int(os.environ.get("REDIS_PORT", 6379))
    redis_password = os.environ.get("REDIS_PASSWORD")
    pki_path = os.environ.get("PKI_PATH", "./agent-keys")

    # Per-peer TOTP seeds from environment (comma-separated key=value pairs)
    # Example: TOTP_SEEDS="alice=JBSWY3DPEHPK3PXP,bob=32EE5VTB5CL7BLJID4IBFZCXJMQKDH2W"
    totp_seeds = {}
    seeds_env = os.environ.get("TOTP_SEEDS", "")
    if seeds_env:
        for pair in seeds_env.split(","):
            if "=" in pair:
                peer, seed = pair.split("=", 1)
                totp_seeds[peer.strip()] = seed.strip()

    # Legacy: single seed for all peers
    legacy_seed = os.environ.get("TOTP_SEED")
    if legacy_seed and not totp_seeds:
        totp_seeds["__default__"] = legacy_seed

    pki = PKIStore(pki_path)
    agent = A2AAgent(agent_name, redis_host, redis_port, redis_password, totp_seeds, pki)

    agent.register_handler("crack_hash", crack_hash)
    agent.register_handler("reverse_binary", reverse_binary)
    agent.register_handler("scan_target", scan_target)
    agent.register_handler("get_status", get_status)

    agent.run(listen_timeout=30)
