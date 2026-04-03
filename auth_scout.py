"""
Auth Scout — Local MFA handler for A2A agents

Handles human authentication challenges with zero network latency.
Runs as a persistent scout on the agent's machine, listening for auth requests,
verifying TOTP codes, and returning authenticated tokens.

Design:
  - Scout listens on mesh:inbox:auth_{agent_name}
  - Returns challenges with request_id
  - Human responds with code + request_id
  - Scout verifies and returns auth_token
  - Minimal latency (local process, no network roundtrip)
"""

import json
import time
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Tuple

from a2a_redis import A2ARedisClient, A2AMessage
from human_mfa import HumanMFAManager


class AuthScout:
    """Local MFA authentication handler for agents."""
    
    def __init__(self, agent_name: str, redis_host: str = "localhost",
                 redis_port: int = 6379, redis_password: str = "",
                 totp_seeds: Optional[Dict[str, str]] = None,
                 pki_path: str = None,
                 human_mfa_store: str = "~/.a2a/human-credentials",
                 window: int = 3):
        """
        Initialize auth scout.
        
        Args:
            agent_name: Parent agent name (e.g., "mrpink")
            redis_host: Redis host
            redis_port: Redis port
            redis_password: Redis password
            totp_seeds: Agent TOTP seeds for mesh communication
            pki_path: Path to PKI key store
            human_mfa_store: Path to human credentials store
            window: TOTP time window (default 3 = ±90 seconds)
        """
        self.agent_name = agent_name
        self.window = window
        self.mfa_manager = HumanMFAManager(credential_store_path=human_mfa_store)
        
        # A2A client for mesh communication
        from a2a_redis import PKIStore, generate_totp_seed
        pki = PKIStore(pki_path) if pki_path else None
        
        self.a2a = A2ARedisClient(
            agent_name=f"{agent_name}/auth",
            redis_host=redis_host,
            redis_port=redis_port,
            redis_password=redis_password,
            totp_seeds=totp_seeds or {"__default__": generate_totp_seed()},
            pki=pki
        )
        
        # Challenge tracking
        self.pending_challenges = {}  # request_id -> (human_id, timestamp)
        self.max_challenge_age = 300  # 5 minutes
    
    def start(self, timeout_seconds: int = 30):
        """
        Start the auth scout listener loop.
        
        Listens for auth challenges and responds with verification results.
        
        Args:
            timeout_seconds: Poll timeout (use smaller value for responsiveness)
        """
        print(f"[auth-scout] Starting listener for {self.agent_name}/auth")
        
        try:
            while True:
                # Listen for auth requests
                result = self.a2a.listen(timeout_seconds=timeout_seconds)
                
                if result is None:
                    # Timeout — cleanup stale challenges
                    self._cleanup_stale_challenges()
                    continue
                
                msg_id, from_agent, method, params = result
                
                if method == "challenge":
                    self._handle_challenge(from_agent, msg_id, params)
                elif method == "verify":
                    self._handle_verify(from_agent, msg_id, params)
                else:
                    print(f"[auth-scout] Unknown method: {method}")
        
        except KeyboardInterrupt:
            print(f"\n[auth-scout] Shutting down")
    
    def request_challenge(self, human_id: str, timeout_seconds: int = 120) -> Tuple[bool, Optional[str]]:
        """
        Request MFA challenge for a human.
        
        This is called by the agent when it needs to authenticate a human.
        
        Args:
            human_id: Human identifier (e.g., "RJMendez")
            timeout_seconds: How long to wait for verification (default 2 min)
        
        Returns:
            (authenticated: bool, auth_token: str or None)
        """
        # Generate challenge
        request_id = secrets.token_hex(8)
        challenge_code = secrets.randbelow(1000000)  # Random 6-digit number for display
        
        print(f"[auth-scout] Requesting challenge for {human_id} (req={request_id})")
        
        # Send challenge request to human
        self.a2a.send(
            to_agent=f"{human_id}/cli",  # Assume human has CLI interface
            method="mfa_challenge",
            params={
                "request_id": request_id,
                "human_id": human_id,
                "challenge_code": challenge_code,
                "expires_in_seconds": timeout_seconds
            },
            wait_for_reply=False
        )
        
        # Track challenge
        self.pending_challenges[request_id] = (human_id, time.time())
        
        # Wait for verification
        start = time.time()
        while time.time() - start < timeout_seconds:
            # Check if verification came back
            result = self._check_verification(request_id, human_id)
            if result:
                return True, request_id
            
            time.sleep(0.5)
        
        # Timeout
        self.pending_challenges.pop(request_id, None)
        print(f"[auth-scout] Challenge timeout for {human_id}")
        return False, None
    
    def _handle_challenge(self, from_agent: str, msg_id: str, params: Dict) -> None:
        """
        Handle an incoming MFA challenge request from another agent.
        
        Args:
            from_agent: Requesting agent
            msg_id: Message ID for reply
            params: Challenge parameters (human_id, request_id, etc.)
        """
        human_id = params.get("human_id")
        request_id = params.get("request_id")
        
        print(f"[auth-scout] Challenge from {from_agent} for {human_id}")
        
        # Check if human has MFA enabled
        creds = self.mfa_manager._load_credentials(human_id)
        if not creds or not creds.mfa_enabled:
            self.a2a.send(
                to_agent=from_agent,
                method="challenge_response",
                params={"request_id": request_id, "error": "MFA not enabled"},
                wait_for_reply=False
            )
            return
        
        # Store challenge
        self.pending_challenges[request_id] = (human_id, time.time())
        
        # Send back challenge token
        self.a2a.send(
            to_agent=from_agent,
            method="challenge_response",
            params={"request_id": request_id, "status": "waiting_code"},
            wait_for_reply=False
        )
    
    def _handle_verify(self, from_agent: str, msg_id: str, params: Dict) -> None:
        """
        Handle TOTP code verification.
        
        Args:
            from_agent: Agent sending verification
            msg_id: Message ID for reply
            params: Verification parameters (request_id, human_id, code)
        """
        request_id = params.get("request_id")
        human_id = params.get("human_id")
        code = params.get("code")
        
        if request_id not in self.pending_challenges:
            self.a2a.send(
                to_agent=from_agent,
                method="verify_response",
                params={"request_id": request_id, "error": "Challenge expired"},
                wait_for_reply=False
            )
            return
        
        # Verify TOTP code
        if self.mfa_manager.verify_human_totp(human_id, code, window=self.window):
            # Generate auth token
            auth_token = secrets.token_hex(32)
            
            print(f"[auth-scout] ✓ Verified {human_id} (req={request_id})")
            
            self.a2a.send(
                to_agent=from_agent,
                method="verify_response",
                params={
                    "request_id": request_id,
                    "authenticated": True,
                    "auth_token": auth_token,
                    "expires_in": 3600  # 1 hour
                },
                wait_for_reply=False
            )
            
            self.pending_challenges.pop(request_id, None)
        else:
            print(f"[auth-scout] ✗ Failed verification for {human_id}")
            
            self.a2a.send(
                to_agent=from_agent,
                method="verify_response",
                params={
                    "request_id": request_id,
                    "authenticated": False,
                    "error": "Invalid code"
                },
                wait_for_reply=False
            )
    
    def _check_verification(self, request_id: str, human_id: str) -> bool:
        """Check if verification came back for a request."""
        # In a full implementation, this would poll a result queue
        # For now, just check if challenge was cleared
        return request_id not in self.pending_challenges
    
    def _cleanup_stale_challenges(self) -> None:
        """Remove challenges older than max_challenge_age."""
        now = time.time()
        stale = [
            req_id for req_id, (_, timestamp) in self.pending_challenges.items()
            if now - timestamp > self.max_challenge_age
        ]
        
        for req_id in stale:
            self.pending_challenges.pop(req_id, None)
            print(f"[auth-scout] Cleaned up stale challenge {req_id}")


# ─────────────────────────────────────────────────────────────────────────────
# Example usage
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    
    agent_name = sys.argv[1] if len(sys.argv) > 1 else "mrpink"
    
    # Create auth scout
    scout = AuthScout(
        agent_name=agent_name,
        redis_host="localhost",
        redis_port=6379,
        window=3  # ±90 seconds
    )
    
    print(f"Starting auth scout for {agent_name}")
    print(f"TOTP window: 3 (±90 seconds)")
    print()
    
    # Start listening
    scout.start(timeout_seconds=5)
