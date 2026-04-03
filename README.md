# A2A over Redis — PKI + TOTP Reference Implementation

Secure inter-agent communication framework using Redis as the transport layer with RSA/2048 signatures and TOTP-based time-locked authentication.

## Features

✅ **PKI Signing** — RSA/2048 message signatures (sender verification)
✅ **TOTP Authentication** — Time-based one-time passwords (rate limiting / replay protection)
✅ **Redis Transport** — Scalable pub/sub backbone
✅ **Request/Reply Pattern** — Synchronous or fire-and-forget (`a2a_redis.py`)
✅ **Offline-First Bridge** — Local Redis buffers when remote is unreachable, auto-syncs on reconnect (`redis_bridge.py`)
✅ **Scout Layer** — Sub-agents inherit host identity; ephemeral and persistent scouts, structured findings, host relay filtering (`scout.py`)
✅ **Freeform Collaboration** — Chat/idea/question pub/sub over Redis Streams (`mesh_chat.py`)
✅ **Capability Advertisement** — Agents self-advertise skills, discoverable by peers
✅ **Persistent Ring Buffer** — Last 500 messages per channel, cursor-based catch-up
✅ **Message Correlation** — UUID-based request tracking
✅ **Timeout Handling** — Configurable wait-for-reply with TTL

---

## MeshChat — Freeform Collaboration Layer

`mesh_chat.py` adds a **pub/sub collaboration channel** on top of the structured A2A RPC transport.
Use it for free-form conversation, design ideas, questions, and status updates between agents.
It uses the same RSA signing and TOTP auth as `a2a_redis.py`.

### Why

Structured A2A (`tasks/send` + skill handlers) is great for deterministic work.
But two agents working on the same problem need to be able to say:
- "hey, I'm thinking about X — what's your take?"
- "FYI, pipeline recovered, 9/9 workers healthy"
- "do you have hashcat_crack ready? I have 240 hashes"

That's what `MeshChatClient` is for.

### Quick Start (Alice side)

```python
from mesh_chat import MeshChatClient
from a2a_redis import PKIStore

pki = PKIStore("./agent-keys")
chat = MeshChatClient(
    agent_name="alice",
    redis_host="redis-host",
    redis_password="your-redis-password ",
    totp_seeds={"__default__": "YOUR_TOTP_SEED_HERE"},
    pki=pki,
)

# Announce online
chat.join()

# Freeform message
chat.say("Pipeline recovered — 9/9 workers healthy after health.py fix")

# Propose an idea (signals it's a design thought, not just chat)
chat.idea("What if we ran DistilBERT batch_classify on GPU directly? We have 240 hashes ready")

# Ask a question (signals expected response)
chat.ask("Do you have hashcat_crack ready on the RTX? I want to wire it into chunk scanner output")

# Publish a status update
chat.update("Chunk scanner: 327 chunks/hr, 107,840 pending, ~15 days ETA")

# Advertise skills so Bob knows what I can do
chat.advertise_capabilities({
    "pipeline_status":   "Real-time audit pipeline health, worker counts",
    "findings_query":    "Search scan_secrets DB — 25,512 secrets",
    "chunk_scanner":     "107,840 chunks, 327/hr, 8 workers",
    "model_routing":     "Route tasks to optimal LLM with cost optimization",
    "report_generation": "Generate security disclosures and audit reports",
})
```

### Quick Start (Bob side)

Bob should use the **same** Redis instance (`redis-host`) that Alice uses.
The channel is `mesh:chat:general` (default).

```python
from mesh_chat import MeshChatClient
from a2a_redis import PKIStore

pki = PKIStore("./agent-keys")  # must have sender.public.pem for sig verification
chat = MeshChatClient(
    agent_name="bob",
    redis_host="redis-host",          # same Redis as Alice
    redis_password="your-redis-password ",
    totp_seeds={"__default__": "YOUR_TOTP_SEED_HERE"},
    pki=pki,
)

chat.join()
chat.say("Online — RTX 4070 Ti available, Ollama running llama3.1:8b")
chat.advertise_capabilities({
    "hashcat_identify":  "Hash type identification via hashcat --identify",
    "hashcat_benchmark": "GPU benchmark across all hash modes",
    "gpu_inference":     "Local LLM inference — llama3.1:8b, mistral:7b (RTX 4070 Ti)",
    "docker_manage":     "Container/compose management on Windows host",
    "litellm_manage":    "LiteLLM proxy pool routing and spend tracking",
})

# Read messages from Alice
for msg in chat.read_new():
    print(msg)
    # msg.kind tells you what kind: "chat", "idea", "question", "update", etc.
    # msg.from_agent tells you who sent it
    # msg.text is the freeform content
```

### Message Kinds

| kind        | use when                                        |
|-------------|--------------------------------------------------|
| `chat`      | General freeform conversation                    |
| `idea`      | Design proposal or architectural thought         |
| `question`  | Explicit question — signals expected response    |
| `update`    | Status or progress notification                  |
| `ack`       | Reply/acknowledgement to a question or idea      |
| `join`      | Agent came online (auto-sent by `chat.join()`)   |
| `leave`     | Agent going offline                              |
| `capability`| Skill advertisement (auto-sent by `advertise_capabilities`) |

### Blocking Listen Loop

```python
def on_message(msg):
    if msg.kind == "question":
        # respond with ack
        chat.ack(f"On it — {msg.text}", reply_to_id=msg.id)
    else:
        print(f"[{msg.from_agent}/{msg.kind}] {msg.text}")

chat.listen_loop(callback=on_message)
```

### Discover What the Mesh Can Do

```python
# See all advertised skills from all agents
all_caps = chat.get_all_capabilities()
for agent, skills in all_caps.items():
    print(f"\n{agent}:")
    for skill_id, desc in skills.items():
        print(f"  {skill_id}: {desc}")

# See who's online
print("Online:", chat.online_agents())
```

### CLI (for manual testing)

```bash
# Read new messages
python mesh_chat.py --agent alice --host redis-host --password "..." read

# Send a message
python mesh_chat.py --agent alice ... say "hey Bob, what's GPU load?"

# Ask a question
python mesh_chat.py --agent alice ... ask "wordgen ready to wire into crawl pipeline?"

# Dump full channel history
python mesh_chat.py --agent alice ... history

# Show all advertised capabilities
python mesh_chat.py --agent alice ... capabilities

# Who's active
python mesh_chat.py --agent alice ... members

# Blocking listen
python mesh_chat.py --agent alice ... listen
```

### Redis Keys

| Key | Type | Purpose |
|-----|------|---------|
| `mesh:chat:{channel}` | Stream | Ring buffer of chat messages (max 500) |
| `mesh:chat:{channel}:cursor:{agent}` | String | Agent's last-read position |
| `mesh:capabilities:{agent}` | Hash | Agent's current skill list (TTL 5min) |
| `mesh:chat:{channel}:members` | Sorted Set | Active agents (by last-seen timestamp) |

### Integration with Existing A2A Servers

Add to your agent startup:

```python
# In _start_queue_worker() or on_startup
from mesh_chat import MeshChatClient
chat = MeshChatClient("alice", redis_host=REDIS_HOST, redis_password=REDIS_PASSWORD, pki=pki)
chat.join()
chat.advertise_capabilities(SKILL_HANDLERS.keys_with_descriptions())
```

Add to Bob's server startup similarly. That's it — both agents are now on `mesh:chat:general`.

---

---

## Redis Bridge — Offline-First Sync

`redis_bridge.py` keeps a **local Redis in sync with a remote mesh Redis** — even when connectivity is intermittent.

### Why

Some agents run on portable devices (laptops, edge hardware) that aren't always on the network. The local Redis acts as a write-ahead buffer: the agent keeps working normally when offline, and the bridge catches everything up when the remote becomes reachable again.

### How It Works

```
[local Redis] ←─────────────────────────────→ [remote Redis]
      │                                               │
      │   Connected: bidirectional stream sync        │
      │   Offline:   buffer locally, cursor saved     │
      │   Reconnect: cursor-based catch-up            │
```

- Syncs `mesh:chat:{channel}` streams in both directions using cursor-based `XREAD`
- Forwards `mesh:inbox:{agent}` queues from remote → local (for agents living on this device)
- Merges presence (`mesh:chat:{channel}:members`) and capabilities (`mesh:capabilities:*`) remote → local
- Deduplication via message ID tracking — no double-delivery on reconnect
- Connectivity probe every N seconds — reconnects automatically

### Quick Start

```bash
# Sync the default "general" channel
REMOTE_REDIS_HOST=192.168.1.100 \
REMOTE_REDIS_PASSWORD=your-password \
python redis_bridge.py

# Also mirror inbox queues for local agents
REMOTE_REDIS_HOST=192.168.1.100 \
REMOTE_REDIS_PASSWORD=your-password \
BRIDGE_INBOX_AGENTS=alice,bob \
python redis_bridge.py

# Multiple channels, custom poll interval
REMOTE_REDIS_HOST=192.168.1.100 \
BRIDGE_CHANNELS=general,ops,findings \
BRIDGE_POLL_MS=250 \
python redis_bridge.py
```

### Configuration

| Variable | Default | Description |
|---|---|---|
| `REMOTE_REDIS_HOST` | _(required)_ | Remote Redis hostname or IP |
| `REMOTE_REDIS_PORT` | `6379` | Remote Redis port |
| `REMOTE_REDIS_PASSWORD` | _(none)_ | Remote Redis password |
| `LOCAL_REDIS_HOST` | `localhost` | Local Redis hostname |
| `LOCAL_REDIS_PORT` | `6379` | Local Redis port |
| `LOCAL_REDIS_PASSWORD` | _(none)_ | Local Redis password |
| `BRIDGE_CHANNELS` | `general` | Comma-separated chat channels to sync |
| `BRIDGE_INBOX_AGENTS` | _(none)_ | Comma-separated agent names whose inboxes to mirror |
| `BRIDGE_POLL_MS` | `500` | Poll interval when connected (milliseconds) |
| `BRIDGE_PROBE_INTERVAL` | `10` | Connectivity probe interval (seconds) |
| `BRIDGE_LOG_LEVEL` | `INFO` | Log level (`DEBUG`, `INFO`, `WARNING`) |

### Redis Keys Synced

| Key | Direction | Notes |
|---|---|---|
| `mesh:chat:{channel}` | Bidirectional | Stream ring-buffer, cursor-based |
| `mesh:chat:{channel}:members` | Remote → Local | Presence data merged |
| `mesh:capabilities:{agent}` | Remote → Local | Read-only mesh view |
| `mesh:inbox:{agent}` | Remote → Local | Only for agents in `BRIDGE_INBOX_AGENTS` |
| `bridge:cursor:*` | Local only | Saved read positions (survive restarts) |
| `bridge:seen:*` | Local only | Dedup tracking (TTL 10min) |

### Running as a Service

```ini
# /etc/systemd/system/a2a-bridge.service
[Unit]
Description=A2A Redis Bridge
After=network.target redis.service

[Service]
EnvironmentFile=/etc/a2a-bridge.env
ExecStart=/usr/bin/python3 /opt/a2a-redis/redis_bridge.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

## Scout Layer — Sub-Agent Identity & Structured Output

`scout.py` lets task-specific sub-processes (scouts) participate in the mesh under their host agent's identity, without managing their own keypairs.

### Identity Model

```
alice (has keypair)
├── alice/osint-crawler      persistent, long-running
├── alice/github-watcher     persistent, long-running
└── alice/snapshot-42a1f3    ephemeral, one-shot
```

Scouts sign messages using the host's private key. The mesh sees full provenance (`from: "alice/osint-crawler"`) with no extra key management overhead.

### Message Kinds

Scouts extend the mesh_chat kinds with:

| kind | use when |
|---|---|
| `finding` | Structured result with severity + evidence dict |
| `snapshot` | Point-in-time data capture |
| `heartbeat` | Periodic liveness signal (persistent scouts) |
| `error` | Scout-reported failure or exception |
| `task_start` | Scout beginning a task |
| `task_done` | Task complete, with summary stats |

### Ephemeral Scout (one-shot)

```python
from scout import ScoutClient
from a2a_redis import PKIStore

pki = PKIStore("./agent-keys")

with ScoutClient.ephemeral("alice", pki=pki, redis_host="localhost") as scout:
    # join() sent automatically on enter
    scout.task_start("Scanning 50 targets")
    for target in targets:
        result = scan(target)
        if result.found:
            scout.finding(
                title=result.title,
                severity=result.severity,       # info/low/medium/high/critical
                evidence={"url": result.url, "detail": result.detail},
            )
    scout.task_done("Scan complete", stats={"checked": 50, "findings": 3})
    # leave() sent automatically on exit
```

### Persistent Scout

```python
scout = ScoutClient(
    host_agent="alice",
    scout_id="osint-crawler",       # stable ID for cursor persistence
    pki=pki,
    redis_host="localhost",
)
scout.join()
scout.advertise_capabilities(...)   # uses MeshChatClient under the hood

while running:
    scout.heartbeat(f"Processed {n} targets so far")
    results = do_work()
    for r in results:
        scout.finding(r.title, r.severity, r.evidence)

scout.leave()
```

### Scout State (persistent scouts)

```python
# Persist crawl position across restarts
scout.set_state("last_url", "https://example.com/page/42")
scout.set_state("items_processed", "1500")

# On restart: resume from saved position
last_url = scout.get_state("last_url")
```

### Host Relay

The host agent controls what scout output reaches the shared mesh. Local noisy output stays local; only curated signal is forwarded.

```python
from scout import HostRelay

relay = HostRelay(
    host_agent="alice",
    local_redis=local_r,    # your local Redis
    mesh_redis=mesh_r,      # shared mesh Redis
    pki=pki,
)

# Forward only high/critical findings to shared "findings" channel
relay.relay_findings(min_severity="high", dst_channel="findings")

# Forward task lifecycle + errors to shared "ops" channel
relay.relay_updates(dst_channel="ops")

# Forward everything (debug / trusted private mesh)
relay.relay_all()

print(relay.stats())  # {"relayed": 12, "filtered": 47}
```

### CLI

```bash
# One-shot finding
python scout.py --host alice --id crawl-1 --ephemeral finding \
    --title "Exposed API key" --severity high --evidence '{"repo":"example/repo"}'

# Heartbeat from persistent scout
python scout.py --host alice --id osint-crawler heartbeat "3,200 targets processed"

# List all registered scouts
python scout.py --host alice list-scouts

# Scout state
python scout.py --host alice --id osint-crawler state-set "last_url=https://example.com"
python scout.py --host alice --id osint-crawler state-get last_url
```

---

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
    totp_seed="YOUR_TOTP_SEED_HERE",
    pki=pki
)

bob = A2ARedisClient(
    "bob",
    redis_host="localhost",
    redis_port=6379,
    redis_password=None,
    totp_seed="YOUR_TOTP_SEED_HERE",
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
    - TOTP_SEED=YOUR_TOTP_SEED_HERE
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
agents = ["alice", "bob", "alice"]
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

