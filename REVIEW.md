# A2A Redis Code Review — 2026-04-03

## Bugs Found

### 🔴 BUG 1: `listen()` loses the message ID — replies can never work
**File:** `a2a_redis.py` line ~180, `example_agent.py` line ~55
**Severity:** Critical

`listen()` returns `(from_agent, method, params)` but **does not return the message ID**.
The caller has no way to call `reply(request_id, ...)` because `request_id` is lost.

In `example_agent.py` line 55, there's a hack: `msg_id = params.pop("_msg_id", None)` —
but nothing ever puts `_msg_id` into params. This means **replies never actually work**.

**Fix:** Return the message ID from `listen()` as a 4-tuple, or return the full message object.

---

### 🔴 BUG 2: `reply()` signature is computed over a different `id` than the original
**File:** `a2a_redis.py` line ~205
**Severity:** High

`reply()` creates a new `A2AMessage` (which generates a new UUID), then overrides
`msg.id = request_id`. But `sign()` calls `to_dict()` which uses `self.id` — and at
that point `self.id` is already the *new* UUID because the constructor ran first, then
`msg.id = request_id` runs *after* `A2AMessage.__init__`.

Wait — actually this is set before `sign()` is called, so the ordering is:
1. `msg = A2AMessage(...)` → `msg.id = <new uuid>`
2. `msg.id = request_id` → overrides to request_id
3. `msg.sign()` → signs with request_id in payload

This is actually correct. But it's fragile — the intent is unclear and easy to break.

**Fix:** Accept `message_id` parameter in `A2AMessage.__init__` instead of post-hoc override.

---

### 🔴 BUG 3: `send()` with `wait_for_reply=True` uses busy-polling with `lpop`
**File:** `a2a_redis.py` line ~170
**Severity:** Medium (performance)

The reply-wait loop does `lpop` + `time.sleep(0.1)` in a tight loop. This is wasteful
and adds up to 100ms of unnecessary latency on every reply.

**Fix:** Use `blpop` with timeout for the reply queue, same as `listen()`.

---

### 🟡 BUG 4: TOTP uses a single shared seed — not per-peer
**File:** `a2a_redis.py` throughout
**Severity:** Design flaw

Every agent has ONE `totp_seed`. The receiver verifies the TOTP using its *own* seed.
This means TOTP only works if all agents share the **same** seed — which defeats the
purpose of per-agent authentication. Any agent with the shared seed can impersonate
any other agent (TOTP-wise).

**Fix:** Use per-peer TOTP seeds. Store a mapping of `{peer_name: totp_seed}` so each
agent pair has a unique shared secret.

---

### 🟡 BUG 5: No message expiry / staleness check
**File:** `a2a_redis.py` `_verify_totp`
**Severity:** Medium

Messages include a `timestamp` field but it's never validated. An attacker who captures
a signed message could replay it hours later (the TOTP window helps slightly but only
covers ±30s). There's no check that the message timestamp is recent.

**Fix:** Reject messages where `timestamp` is older than a configurable `max_age` (e.g., 60s).

---

### 🟡 BUG 6: No nonce / dedup — replay within TOTP window is possible
**File:** `a2a_redis.py`
**Severity:** Medium

Within the ±30s TOTP window, an attacker who can read Redis traffic could replay
a signed message. The UUID `id` field is unique but nothing tracks seen IDs.

**Fix:** Add a Redis SET of recently seen message IDs with TTL, reject duplicates.

---

### 🟢 BUG 7: Unused imports `hmac` and `hashlib`
**File:** `a2a_redis.py` lines 28-29
**Severity:** Low (code quality)

`hmac` and `hashlib` are imported but never used anywhere.

**Fix:** Remove them.

---

### 🟢 BUG 8: Private key files written with default umask (potentially world-readable)
**File:** `a2a_redis.py` `save_keypair()`
**Severity:** Medium (security)

Private keys are written with `open(..., "wb")` which uses the process umask. On many
systems this results in `0644` permissions — world-readable private keys.

**Fix:** Use `os.open()` with `0o600` mode, or `os.chmod()` after writing.

---

### 🟢 BUG 9: `to_dict()` used for both signing and serialization — fragile
**File:** `a2a_redis.py`
**Severity:** Low (maintainability)

The same `to_dict()` is used for signing payload AND for the wire format. If someone
adds a field to `to_dict()` without understanding the signing contract, signatures break.

**Fix:** Separate `_signing_payload()` from `to_dict()` to make the contract explicit.

---

## Improvements

1. **Add `max_message_size` check** — reject oversized messages before parsing
2. **Connection pooling** — reuse Redis connections instead of creating per-client
3. **Structured errors** — custom exception classes instead of generic `ValueError`
4. **Async support** — `aioredis` variant for async agent loops
5. **Metrics** — message count, latency, error rate counters
6. **Key caching** — `PKIStore` reads disk on every sign/verify; cache loaded keys
7. **Health check endpoint** — `ping()` method to verify Redis connectivity
8. **Graceful shutdown** — signal handler for clean BLPOP interruption
