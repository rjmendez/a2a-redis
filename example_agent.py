"""
Example: A2A Agent Worker Loop

This demonstrates a real agent that:
1. Listens for incoming A2A messages
2. Processes tasks (e.g., hashcat cracking)
3. Replies with results
4. Handles timeouts and errors gracefully
"""

import logging
import time
from typing import Optional, Tuple, Dict, Any

from a2a_redis import A2ARedisClient, PKIStore

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class A2AAgent:
    """Base agent for A2A communication."""
    
    def __init__(self, agent_name: str, redis_host: str, redis_port: int,
                 redis_password: Optional[str], totp_seed: str, pki: PKIStore):
        self.agent_name = agent_name
        self.client = A2ARedisClient(
            agent_name=agent_name,
            redis_host=redis_host,
            redis_port=redis_port,
            redis_password=redis_password,
            totp_seed=totp_seed,
            pki=pki
        )
        self.handlers = {}
    
    def register_handler(self, method: str, func):
        """Register a handler for a specific method."""
        self.handlers[method] = func
        logger.info(f"✓ Registered handler for {method}")
    
    def handle_message(self, msg_id: str, from_agent: str, method: str, params: Dict) -> Dict:
        """Process an incoming message."""
        if method not in self.handlers:
            return {"status": "error", "message": f"Unknown method: {method}"}
        
        try:
            handler = self.handlers[method]
            result = handler(**params)
            return {"status": "ok", "result": result}
        except Exception as e:
            logger.error(f"Error handling {method}: {e}")
            return {"status": "error", "message": str(e)}
    
    def run(self, listen_timeout: int = 30):
        """Main loop: listen for messages and reply."""
        logger.info(f"✓ {self.agent_name} listening for A2A messages...")
        
        while True:
            try:
                result = self.client.listen(timeout_seconds=listen_timeout)
                
                if not result:
                    logger.debug("Listen timeout (no messages)")
                    continue
                
                from_agent, method, params = result
                
                # Extract message ID (we need to track this)
                msg_id = params.pop("_msg_id", None)
                
                # Process
                response = self.handle_message(msg_id, from_agent, method, params)
                
                # Reply
                if msg_id:
                    self.client.reply(msg_id, from_agent, response)
                
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                time.sleep(1)  # Backoff before retry


# Example handlers

def crack_hash(target_hash: str, hash_type: int, wordlist: str = None) -> Dict:
    """Simulate hash cracking."""
    logger.info(f"Cracking hash {target_hash} (type={hash_type})")
    # In real implementation, call hashcat here
    time.sleep(0.5)  # Simulate work
    return {"cracked": False, "attempts": 1000}


def reverse_binary(binary_path: str, analysis_level: int = 3) -> Dict:
    """Simulate binary reverse engineering."""
    logger.info(f"Analyzing {binary_path} (level={analysis_level})")
    # In real implementation, call radare2 here
    time.sleep(1)  # Simulate work
    return {"functions": 42, "strings": 120, "entropy": 7.2}


def scan_target(target: str, depth: int) -> Dict:
    """Simulate reconnaissance scan."""
    logger.info(f"Scanning {target} (depth={depth})")
    time.sleep(2)  # Simulate work
    return {"open_ports": [80, 443], "services": ["http", "https"]}


if __name__ == "__main__":
    import os
    
    # Configuration
    agent_name = os.environ.get("AGENT_NAME", "worker-1")
    redis_host = os.environ.get("REDIS_HOST", "localhost")
    redis_port = int(os.environ.get("REDIS_PORT", 6379))
    redis_password = os.environ.get("REDIS_PASSWORD")
    totp_seed = os.environ.get("TOTP_SEED", "32EE5VTB5CL7BLJID4IBFZCXJMQKDH2W")
    pki_path = os.environ.get("PKI_PATH", "./agent-keys")
    
    # Initialize
    pki = PKIStore(pki_path)
    agent = A2AAgent(agent_name, redis_host, redis_port, redis_password, totp_seed, pki)
    
    # Register handlers
    agent.register_handler("crack_hash", crack_hash)
    agent.register_handler("reverse_binary", reverse_binary)
    agent.register_handler("scan_target", scan_target)
    
    # Run
    agent.run(listen_timeout=30)
