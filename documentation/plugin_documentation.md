# Fraud Guard — Plugin Documentation

## What It Does

Fraud Guard is a Kong Gateway plugin that evaluates every API request against Turkish banking regulation (BDDK) fraud detection rules in real time. It extracts transaction data from the request body/headers, runs 70+ detection rules, calculates a risk score (0–100), and either blocks the request (HTTP 403) or allows it through (HTTP 200) depending on the configured thresholds.

---

## Installation

### 1. Deploy the image to Kong

The plugin ships as a custom Kong Gateway image. Build and push:

```bash
docker buildx build --platform linux/amd64 --push \
  -t <your-acr>.azurecr.io/kong-fraud-guard:1.0.1 \
  -f Dockerfile.kong .
```

Update the Kong CP and DP deployments:

```bash
kubectl set image deployment/kong-cp-kong \
  proxy=<your-acr>.azurecr.io/kong-fraud-guard:1.0.1 -n kong

kubectl set image deployment/kong-dp-kong \
  proxy=<your-acr>.azurecr.io/kong-fraud-guard:1.0.1 -n kong
```

### 2. Enable the plugin on a service

```bash
curl -X POST http://<admin-url>/services/<service-name>/plugins \
  -H "Content-Type: application/json" \
  -d '{
    "name": "fraud-guard",
    "config": {
      "mode": "shadow",
      "fail_mode": "open",
      "thresholds": {
        "block_score": 70,
        "review_score": 30,
        "max_daily_transactions": 20,
        "max_daily_recipients": 5,
        "max_daily_amount": 100000
      },
      "redis": {
        "host": "localhost",
        "port": 6379,
        "timeout": 1000
      }
    }
  }'
```

Start in **shadow mode** to observe behaviour before enabling blocking.

---

## Configuration Reference

### Top-level fields

| Field | Type | Default | Description |
|---|---|---|---|
| `mode` | string | `"shadow"` | `"enforce"` blocks bad requests; `"shadow"` logs only |
| `fail_mode` | string | `"open"` | Behaviour when Redis is unreachable: `"open"` = allow, `"closed"` = block |
| `log_level` | string | `"info"` | Log verbosity: `debug`, `info`, `warn`, `error` |
| `pii_hash_salt` | string | — | Kong Vault reference for PII hashing salt (`vault://env/FRAUD_GUARD_HASH_SALT`) |
| `webhook_auth_header` | string | — | Auth header value for webhook calls (`vault://env/WEBHOOK_AUTH`) |

### `thresholds`

| Field | Type | Default | Description |
|---|---|---|---|
| `block_score` | integer | `70` | Score at or above which a transaction is blocked |
| `review_score` | integer | `30` | Score at or above which a transaction is flagged for review |
| `max_daily_transactions` | integer | `20` | Hard daily transaction limit per user (any overage → immediate block) |
| `max_daily_recipients` | integer | `5` | Max unique transfer recipients per day |
| `max_daily_amount` | integer | `100000` | Max total daily spend in TRY |
| `young_user_age_threshold` | integer | `20` | Age below which young-user rules apply |
| `new_account_days_threshold` | integer | `30` | Account age (days) below which new-account rules apply |

### `redis`

| Field | Type | Default | Description |
|---|---|---|---|
| `host` | string | `"127.0.0.1"` | Redis hostname |
| `port` | integer | `6379` | Redis port |
| `timeout` | integer | `1000` | Connection timeout (ms) |
| `password` | string | — | Redis password (supports Kong Vault reference) |
| `database` | integer | `0` | Redis database index |
| `keepalive_pool_size` | integer | `30` | Connection pool size per worker |
| `keepalive_timeout` | integer | `60000` | Idle keepalive timeout (ms) |

### `whitelists`

| Field | Type | Description |
|---|---|---|
| `user_ids` | array of strings | Users permanently exempted from all fraud checks |
| `merchant_ids` | array of strings | Merchants permanently exempted |
| `ip_ranges` | array of strings | CIDR ranges exempted (e.g. `"10.0.0.0/8"`) |

Whitelisted requests are returned immediately with `score=0` and `x-risk-level: whitelisted`.

### `rule toggles`

| Field | Default | Description |
|---|---|---|
| `enable_account_transfers` | `true` | Section 3.1.1 rules |
| `enable_pos_transactions` | `true` | Section 3.1.2 rules |
| `enable_bill_payments` | `true` | Section 3.1.3 rules |
| `enable_mobile_payments` | `true` | Section 3.1.4 rules |
| `enable_api_security` | `true` | Section 3.2 rules |

### Alerting

| Field | Type | Description |
|---|---|---|
| `alert_on_block` | boolean | Send webhook on every block |
| `alert_webhook_url` | string | HTTPS endpoint to POST alert JSON |
| `alert_min_score` | integer | Only alert if score ≥ this value |

Webhook calls use TLS verification and support an optional `Authorization` header via `webhook_auth_header`.

---

## Transaction Request Format

The plugin reads transaction data from the **JSON request body** and from **request headers**.

### Headers (read by plugin)

| Header | Description |
|---|---|
| `x-user-id` | User identifier (overrides body `user_id`) |
| `x-forwarded-for` | Source IP (set by load balancer) |
| `x-api-key` | API key (used by key-auth plugin, also visible to rule 3.2-1 when `hide_credentials: false`) |
| `x-request-id` | Request ID — must be UUID v4; rejected values are replaced with a fresh UUID |

### Body fields

| Field | Type | Description |
|---|---|---|
| `user_id` | string | **Required.** User identifier |
| `amount` | number | Transaction amount in TRY. Negative values are clipped to 0 |
| `currency` | string | Currency code (default: `TRY`) |
| `transaction_type` | string | `pos`, `transfer`, `bill_payment`, `mobile`, `auth` |
| `merchant_id` | string | Merchant identifier (POS transactions) |
| `merchant_category` | string | MCC category |
| `recipient_id` | string | Transfer recipient (transfer transactions) |
| `description` | string | Transaction description — scanned for suspicious keywords |
| `account_id` | string | Account identifier |
| `account_age_days` | integer | Age of the account in days |
| `user_age` | integer | Age of the user in years |
| `device_id` | string | Device fingerprint |
| `transaction_hour` | integer | Hour of transaction (0–23) |
| `is_weekend` | boolean | Whether the transaction occurs on a weekend |
| `card_bin` | string | First 6 digits of card number |
| `ip_address` | string | Client IP (usually extracted from `x-forwarded-for`) |

---

## Response Headers

Every request processed by the plugin receives these headers:

| Header | Example | Description |
|---|---|---|
| `x-fraud-score` | `45` | Risk score (0–100) |
| `x-risk-level` | `medium` | `low`, `medium`, `high`, `whitelisted` |
| `x-fraud-mode` | `enforce` | Active mode: `enforce` or `shadow` |
| `x-triggered-rules` | `3.1.1-1,3.1.1-9` | Comma-separated list of triggered rule IDs |
| `x-transaction-id` | `a3f2...` | UUID v4 assigned to this transaction |
| `x-execution-time-ms` | `14.00` | Plugin processing time in milliseconds |

Shadow mode adds:

| Header | Example | Description |
|---|---|---|
| `x-fraud-would-block` | `true` | Whether request would have been blocked in enforce mode |
| `x-fraud-shadow-decision` | `blocked` | Shadow decision: `blocked` or `allowed` |

---

## Blocked Response Body (HTTP 403)

```json
{
  "error": "Transaction blocked",
  "message": "High fraud risk detected",
  "reference": "FRD-2026-03-25-047821",
  "risk_score": 85,
  "risk_level": "high",
  "rules_triggered": "3.1.1-1,3.1.1-2,3.1.1-9",
  "blocked": true
}
```

The `reference` field is a cryptographically random reference ID for tracing the blocked transaction in compliance logs.

---

## Execution Modes

### Enforce mode

Normal production mode. Requests that exceed `block_score` or trigger a `blocked=true` rule receive HTTP 403. The backend never sees blocked requests.

```bash
curl -X PATCH /plugins/<id> -d '{"config":{"mode":"enforce"}}'
```

### Shadow mode

The plugin evaluates all rules and calculates a score, but **never blocks**. All requests pass through to the backend (HTTP 200). Headers still report the would-be score and decision. Use shadow mode when first deploying to calibrate thresholds.

```bash
curl -X PATCH /plugins/<id> -d '{"config":{"mode":"shadow"}}'
```

Shadow mode headers:
- `x-fraud-would-block: true` — request would have been blocked
- `x-fraud-shadow-decision: blocked` — shadow decision

---

## Fail Modes

Controls what happens if Redis is unavailable.

| Mode | Behaviour |
|---|---|
| `open` (default) | Allow all requests; velocity/pattern checks are skipped. Static rule checks (amounts, keywords) still apply. |
| `closed` | Return HTTP 503 to all requests until Redis recovers. Use in highly regulated environments. |

---

## Risk Scoring

Scores are additive. Each triggered rule contributes its `score` value. The total is capped at 100.

### Block conditions

A request is blocked when **either**:
1. Any violation has `blocked = true` (hard block — independent of total score), **or**
2. `total_score >= block_score` (threshold breach)

### Combo amplifier

Multi-dimensional attacks score higher than single-dimension ones. When violations span 2+ risk categories simultaneously:

| Active dimensions | Bonus |
|---|---|
| 2 | +10 |
| 3 | +20 |
| 4+ | +30 |

**Example:** A user exceeding their daily transaction limit (velocity) AND sending to 4 different recipients (diversity) triggers the 2-dimension bonus (+10), making the combined score harder to hide below the block threshold.

### Progressive daily limit (Rule 3.1.1-1)

The daily transaction limit is a **hard limit** — any overage results in `blocked=true`. The score also reflects severity:

| How far over limit | Score | Severity |
|---|---|---|
| 1.0x – 1.5x | 20 | MEDIUM |
| 1.5x – 2.0x | 35 | HIGH |
| 2.0x – 3.0x | 50 | CRITICAL |
| ≥ 3.0x | 70 | CRITICAL |

---

## Whitelist Management

Add users or merchants to the whitelist via Admin API:

```bash
# Add VIP user
curl -X PATCH /plugins/<id> \
  -H "Content-Type: application/json" \
  -d '{
    "config": {
      "whitelists": {
        "user_ids": ["vip_user_001", "vip_user_002"],
        "merchant_ids": [],
        "ip_ranges": ["10.0.0.0/8"]
      }
    }
  }'

# Clear whitelist
curl -X PATCH /plugins/<id> \
  -H "Content-Type: application/json" \
  -d '{"config":{"whitelists":{"user_ids":[],"merchant_ids":[],"ip_ranges":[]}}}'
```

---

## Alert Webhooks

When `alert_on_block: true`, the plugin sends a POST request to `alert_webhook_url` for every blocked transaction:

```json
{
  "event": "FRAUD_BLOCKED",
  "reference": "FRD-2026-03-25-047821",
  "user_id_hash": "a3f2b1c9d4e5...",
  "transaction_type": "transfer",
  "amount": 50000,
  "risk_score": 85,
  "rules_triggered": "3.1.1-1,3.1.1-2",
  "timestamp": "2026-03-25T14:32:00Z"
}
```

Webhooks use HTTPS with TLS certificate verification (`ssl_verify = true`). Private IP ranges and internal hostnames are blocked as SSRF protection (including `169.254.169.254`, `10.x`, `172.16–31.x`, `192.168.x`, `localhost`, `.local`, `.internal`, IPv6 loopback, octal/hex IP notation).

---

## Suspicious Keywords (Rule 3.1.1-15)

Transactions whose `description` or `merchant_id` contain any of the following keywords are **immediately and unconditionally blocked** (`blocked=true`, score=50, severity=CRITICAL) regardless of other rules:

```
kumar, bahis, bet, betting, casino, poker, slot,
jackpot, rulet, tombala, şans oyunu, lottery,
illegal, kaçakçılık, uyuşturucu
```

This implements BDDK circular requirements prohibiting gambling and illegal transaction facilitation.

---

## Compliance Logging

Every transaction produces a structured JSON log entry. PII fields are hashed:

```json
{
  "log_type": "TRANSACTION",
  "timestamp": "2026-03-25T14:32:00Z",
  "plugin_version": "1.0.1",
  "retention_days": 3650,
  "data": {
    "transaction": {
      "user_id_hash": "a3f2b1c9...",
      "account_id_hash": "d4e5f6a7...",
      "device_id_hash": "b8c9d0e1...",
      "amount": 1500,
      "currency": "TRY",
      "transaction_type": "transfer",
      "ip_address": "185.x.x.x"
    },
    "risk_score": 45,
    "risk_level": "medium",
    "blocked": false,
    "rules_triggered": "3.1.1-9",
    "execution_time_ms": 14
  }
}
```

The hash salt is read from `conf.pii_hash_salt` (a Kong Vault reference). If not configured, a development fallback salt is used — **always configure in production**.

---

## Quick Reference: Threshold Tuning

| Goal | Adjustment |
|---|---|
| Reduce false positives | Increase `block_score` (e.g. 70 → 80), increase `max_daily_transactions` |
| Increase sensitivity | Decrease `block_score` (e.g. 70 → 60), decrease `max_daily_amount` |
| Test new rules safely | Set `mode: shadow`, observe `x-fraud-would-block` header |
| Protect against Redis downtime | Set `fail_mode: closed` |
| Exempt internal systems | Add IP range to `whitelists.ip_ranges` |
| Exempt VIP customers | Add user ID to `whitelists.user_ids` |

---

## Integration Example

```bash
curl -X POST https://<kong-proxy>/payment/post \
  -H "Content-Type: application/json" \
  -H "x-api-key: <your-api-key>" \
  -H "x-user-id: user_12345" \
  -d '{
    "user_id": "user_12345",
    "amount": 2500,
    "currency": "TRY",
    "transaction_type": "transfer",
    "recipient_id": "recipient_abc",
    "account_age_days": 365,
    "user_age": 32,
    "device_id": "device_xyz",
    "transaction_hour": 14,
    "is_weekend": false
  }'
```

**Allowed response (HTTP 200):**
```
x-fraud-score: 0
x-risk-level: low
x-fraud-mode: enforce
x-transaction-id: 3f8a2c1d-4b5e-4f9a-8c7d-1e2f3a4b5c6d
x-execution-time-ms: 12.00
```

**Blocked response (HTTP 403):**
```json
{
  "error": "Transaction blocked",
  "reference": "FRD-2026-03-25-047821",
  "risk_score": 85
}
```
