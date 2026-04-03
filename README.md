# A2A over Redis — PKI + TOTP Reference Implementation

Secure inter-agent communication framework using Redis as the transport layer with RSA/2048 signatures and TOTP-based time-locked authentication.

## Features

✅ **PKI Signing** — RSA/2048 message signatures (sender verification)
✅ **TOTP Authentication** — Time-based one-time passwords (rate limiting / replay protection)
✅ **Redis Transport** — Scalable pub/sub backbone
✅ **Request/Reply Pattern** — Synchronous or fire-and-forget
✅ **Message Correlation** — UUID-based request tracking
✅ **Timeout Handling** — Configurable wait-for-reply with TTL

## Installation

```bash
pip install redis cryptography pyotp
```

## Quick Start

### 1. Setup PKI

```python
from a2a_redis import PKIStore, example_agent_setup

pki = PKIStore("./agent-keys")
alice_seed = example_agent_setup("alice", pki)
bob_seed = example_agent_setup("bob", pki)
```

This generates:
- `agent-keys/alice.private.pem` — Alice's private key (keep secret)
- `agent-keys/alice.public.pem` — Alice's public key (can be shared)
- Returns TOTP seed for the agent (store in secrets)

### 2. Initialize A2A Clients

```python
from a2a_redis import A2ARedisClient

alice = A2ARedisClient(
    "alice",
    redis_host="localhost",
    redis_port=6379,
    redis_password=None,
    totp_seed="32EE5VTB5CL7BLJID4IBFZCXJMQKDH2W",
    pki=pki
)

bob = A2ARedisClient(
    "bob",
    redis_host="localhost",
    redis_port=6379,
    redis_password=None,
    totp_seed="32EE5VTB5CL7BLJID4IBFZCXJMQKDH2W",
    pki=pki
)
```

### 3. Send Message (Fire-and-Forget)

```python
# Alice sends to Bob (no reply expected)
alice.send(
    to_agent="bob",
    method="process_scan",
    params={"target": "example.com", "depth": 3}
)
```

### 4. Listen for Messages

```python
# Bob listens for incoming messages
from_agent, method, params = bob.listen(timeout_seconds=30)

if from_agent:
    print(f"Message from {from_agent}: {method}")
    print(f"Params: {params}")
    
    # Process and reply
    result = {"status": "ok", "findings": [...]}
    bob.reply(msg_id, from_agent, result)
```

### 5. Send with Reply (Synchronous)

```python
# Alice sends and waits for Bob's reply
result = alice.send(
    to_agent="bob",
    method="get_status",
    params={},
    wait_for_reply=True,
    timeout_seconds=10
)

print(f"Bob replied: {result}")
```

## Message Format

All messages are JSON with the following structure:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "from": "alice",
  "to": "bob",
  "timestamp": "2026-04-03T16:25:00Z",
  "method": "process_scan",
  "params": {
    "target": "example.com",
    "depth": 3
  },
  "signature": "base64-encoded-rsa-signature",
  "totp": "123456"
}
```

### Message Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Unique message identifier (for correlation) |
| `from` | string | Sender agent name |
| `to` | string | Recipient agent name |
| `timestamp` | ISO8601 | Message creation time (UTC) |
| `method` | string | Skill/method name to invoke |
| `params` | dict | Task parameters |
| `signature` | base64 | RSA/2048-PSS signature of {id, from, to, timestamp, method, params} |
| `totp` | string | 6-digit TOTP code (time-locked, ±1 window = 60s tolerance) |

## Authentication & Verification

### Signature Verification

1. Sender (Alice) signs the message body with her **private key**
2. Receiver (Bob) verifies the signature using Alice's **public key**
3. Any tampering with message fields invalidates the signature

```python
# Automatic verification during listen()
from_agent, method, params = bob.listen(verify_signature=True)
```

### TOTP Verification

1. Both agents share a **TOTP seed** (out-of-band setup)
2. Each message includes a 6-digit TOTP code based on current time
3. Receiver verifies code is within ±1 time window (±30 seconds)
4. Prevents: replay attacks, time-bomb payloads, stale requests

```python
# Automatic verification during listen()
from_agent, method, params = bob.listen(verify_totp=True)
```

## Redis Queue Model

### Queues

| Queue | Purpose | Pattern |
|-------|---------|---------|
| `mesh:inbox:{agent_name}` | Incoming messages | FIFO, BLPOP |
| `mesh:reply:{request_id}` | Reply from request | Temporary, TTL=5min |

### Message Flow

```
Alice (send)
    |
    v (RPUSH)
redis:mesh:inbox:bob
    |
    v (BLPOP by Bob)
Bob (listen)
    |
    v (verify signature + TOTP)
Bob (process)
    |
    v (RPUSH reply)
redis:mesh:reply:{request_id}
    |
    v (BLPOP by Alice, if wait_for_reply=True)
Alice (receive result)
```

### Timeouts & TTL

- **Reply queue TTL:** 5 minutes (auto-expired by Redis)
- **TOTP window:** ±30 seconds (time-locked)
- **Listen timeout:** Configurable (default 30s)

## Deployment

### Docker Compose Example

```yaml
redis:
  image: redis:7-alpine
  ports:
    - "6379:6379"
  command: redis-server --requirepass "your-password"

agent-alice:
  image: your-agent:latest
  environment:
    - AGENT_NAME=alice
    - REDIS_HOST=redis
    - REDIS_PORT=6379
    - REDIS_PASSWORD=your-password
    - TOTP_SEED=32EE5VTB5CL7BLJID4IBFZCXJMQKDH2W
    - PKI_PATH=/etc/agent-keys
  volumes:
    - ./agent-keys:/etc/agent-keys:ro
  depends_on:
    - redis

agent-bob:
  image: your-agent:latest
  environment:
    - AGENT_NAME=bob
    - REDIS_HOST=redis
    - REDIS_PORT=6379
    - REDIS_PASSWORD=your-password
    - TOTP_SEED=<BOB_TOTP_SEED>
    - PKI_PATH=/etc/agent-keys
  volumes:
    - ./agent-keys:/etc/agent-keys:ro
  depends_on:
    - redis
```

### Key Management

1. **Generate keypairs** once per agent:
   ```bash
   python3 -c "from a2a_redis import example_agent_setup, PKIStore; pki = PKIStore('./keys'); example_agent_setup('alice', pki)"
   ```

2. **Mount as read-only** in containers:
   ```yaml
   volumes:
     - ./agent-keys:/etc/agent-keys:ro
   ```

3. **TOTP seeds** should be stored in secrets management (e.g., HashiCorp Vault, Kubernetes Secrets):
   ```bash
   kubectl create secret generic agent-secrets --from-literal=alice-totp=...
   ```

## Security Considerations

### Signature Security

- **Algorithm:** RSA/2048-PSS with SHA-256
- **OAEP padding:** PSS with MGF1 (randomized, replay-resistant)
- **Key rotation:** Generate new keypairs periodically, announce public keys out-of-band

### TOTP Security

- **Time sync:** Agents must have NTP synchronized (±30s tolerance)
- **Seed protection:** TOTP seeds should be treated as secrets (store in vaults)
- **Rotation:** Regenerate TOTP seeds every 90 days
- **Rate limiting:** Combine with request-per-second limits to prevent brute-force

### Redis Transport

- **Encryption in transit:** Use Redis with TLS (redis-cli --tls)
- **Authentication:** Enable `requirepass` (or ACLs in Redis 6+)
- **Network isolation:** Keep Redis on private network, firewall external access

## Performance Notes

- **Signature verification:** ~1-2ms per message (RSA/2048)
- **TOTP verification:** <1ms per message
- **Redis round-trip:** ~0.5-2ms (local), ~5-50ms (remote)
- **Expected latency:** 10-100ms for inter-agent RPC

## Advanced Usage

### Custom Message Handlers

```python
def handle_scan_result(from_agent, method, params):
    """Process incoming scan result."""
    print(f"Got result from {from_agent}")
    return {"status": "processed"}

# Worker loop
while True:
    from_agent, method, params = agent.listen(timeout_seconds=30)
    
    if method == "scan_result":
        result = handle_scan_result(from_agent, method, params)
        agent.reply(msg_id, from_agent, result)
```

### Multi-Agent Patterns

**Request Broadcasting:**
```python
agents = ["alice", "bob", "charlie"]
for agent in agents:
    client.send(agent, "status_check", {}, wait_for_reply=False)
```

**Load Balancing:**
```python
# Round-robin to agents based on queue depth
agents = ["worker-1", "worker-2", "worker-3"]
target = agents[hash(task_id) % len(agents)]
client.send(target, "process", task, wait_for_reply=True)
```

## Troubleshooting

### Message Lost

**Symptom:** No reply received after `timeout_seconds`

**Causes:**
- Recipient agent not listening
- Redis connection dropped
- Network partition

**Solution:**
```python
try:
    result = alice.send(..., wait_for_reply=True, timeout_seconds=30)
except TimeoutError:
    logger.error("Timeout, retrying...")
    # Implement exponential backoff and circuit breaker
```

### Signature Verification Failed

**Symptom:** `ValueError: Signature verification failed`

**Causes:**
- Message was tampered with
- Wrong public key loaded
- Sender agent name mismatch

**Solution:**
```python
# Check agent name and public key
alice_pubkey = pki.load_public_key("alice")
logger.info(f"Alice's public key: {alice_pubkey.public_bytes(...)[:50]}...")
```

### TOTP Mismatch

**Symptom:** `ValueError: TOTP verification failed`

**Causes:**
- System clock skew (>30s difference)
- Wrong TOTP seed
- Message delayed >1 time window

**Solution:**
```bash
# Sync system clock
ntpdate -u pool.ntp.org

# Increase TOTP tolerance (not recommended)
totp.verify(code, valid_window=2)  # ±60s instead of ±30s
```

## See Also

- [pyotp documentation](https://pyauth.github.io/pyotp/)
- [cryptography RSA](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/)
- [Redis Pub/Sub model](https://redis.io/docs/interact/pubsub/)

