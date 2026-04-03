"""
Example: Using Auth Scout for agent authentication

Shows how an agent can offload MFA verification to a local scout,
eliminating network latency from the authentication flow.
"""

from auth_scout import AuthScout
from a2a_redis import A2ARedisClient, PKIStore


def authenticate_human_with_auth_scout(agent_name: str, human_id: str,
                                       redis_host: str = "localhost",
                                       redis_port: int = 6379,
                                       redis_password: str = "") -> bool:
    """
    Authenticate a human using the local auth scout.
    
    This is called by the agent when it needs to verify a human's identity
    before allowing sensitive operations.
    
    Example:
        if authenticate_human_with_auth_scout("mrpink", "RJMendez"):
            print("✓ Human authenticated, proceeding with sensitive op")
        else:
            print("✗ Authentication failed")
    
    Args:
        agent_name: Name of the agent
        human_id: Human identifier
        redis_host: Redis host
        redis_port: Redis port
        redis_password: Redis password
    
    Returns:
        True if authenticated, False otherwise
    """
    
    # Create auth scout instance
    scout = AuthScout(
        agent_name=agent_name,
        redis_host=redis_host,
        redis_port=redis_port,
        redis_password=redis_password,
        window=3  # ±90 seconds for network latency
    )
    
    # Request challenge (blocks until human responds or timeout)
    authenticated, auth_token = scout.request_challenge(human_id, timeout_seconds=120)
    
    return authenticated


# ─────────────────────────────────────────────────────────────────────────────
# Example: Agent protecting a sensitive operation
# ─────────────────────────────────────────────────────────────────────────────

def sensitive_operation_requiring_auth(agent_name: str, human_id: str):
    """
    Example: Agent performs sensitive op only after MFA verification.
    
    Usage:
        sensitive_operation_requiring_auth("mrpink", "RJMendez")
    """
    
    print(f"[{agent_name}] Sensitive operation requested by {human_id}")
    print(f"[{agent_name}] Requesting MFA verification...")
    print()
    
    # Verify human identity
    if authenticate_human_with_auth_scout(agent_name, human_id):
        print(f"[{agent_name}] ✓ {human_id} authenticated")
        print(f"[{agent_name}] Proceeding with sensitive operation...")
        print()
        print("  - Accessing confidential data")
        print("  - Modifying system configuration")
        print("  - Executing privileged commands")
        print()
        print(f"[{agent_name}] Operation complete")
        return True
    else:
        print(f"[{agent_name}] ✗ Authentication failed")
        print(f"[{agent_name}] Denying sensitive operation")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Example: Running auth scout as a background service
# ─────────────────────────────────────────────────────────────────────────────

def run_auth_scout_service(agent_name: str):
    """
    Run auth scout as a persistent background service.
    
    This would typically be started alongside the agent:
        python3 auth_scout.py mrpink &
    
    Or run this function in a background thread within the agent.
    """
    scout = AuthScout(
        agent_name=agent_name,
        redis_host="localhost",
        redis_port=6379,
        window=3  # ±90 seconds
    )
    
    print(f"[auth-scout-service] Starting for {agent_name}")
    print(f"[auth-scout-service] Listening for MFA challenges...")
    print(f"[auth-scout-service] TOTP window: 3 (±90 seconds)")
    print()
    
    # Run indefinitely
    scout.start(timeout_seconds=5)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python auth_scout_example.py <agent_name> [human_id]")
        print()
        print("Examples:")
        print("  python auth_scout_example.py mrpink                    # Start service")
        print("  python auth_scout_example.py mrpink RJMendez          # Test auth")
        sys.exit(1)
    
    agent_name = sys.argv[1]
    human_id = sys.argv[2] if len(sys.argv) > 2 else None
    
    if human_id:
        # Test authentication
        print(f"Testing MFA authentication for {agent_name} ← {human_id}")
        print()
        sensitive_operation_requiring_auth(agent_name, human_id)
    else:
        # Start service
        run_auth_scout_service(agent_name)
