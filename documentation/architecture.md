# Fraud Guard — Architecture

## Overview

Fraud Guard is a Kong Gateway plugin written in Lua (OpenResty) that intercepts every inbound request and evaluates it against a multi-layered fraud detection engine in real time. It runs entirely inside the Kong data plane — no external scoring service is required. Redis is the only external dependency for stateful velocity and pattern tracking.

---

## Component Map

```
kong/plugins/fraud-guard/
├── handler.lua                  Main plugin entry point (access phase)
├── schema.lua                   Config schema & validation
│
├── modules/
│   ├── transaction_extractor.lua   Parses request headers/body → transaction struct
│   ├── rule_engine.lua             Orchestrates rule execution, sorts & caps violations
│   ├── execution_mode.lua          Shadow vs Enforce response logic
│   ├── fail_mode.lua               Open/closed fail behaviour when Redis is down
│   └── ip_validator.lua            IP whitelist & SSRF-safe webhook URL validation
│
├── rules/
│   ├── account_rules.lua           Section 3.1.1 — 20 rules
│   ├── pos_rules.lua               Section 3.1.2 — 25 rules
│   ├── transfer_rules.lua          Section 3.1.3 — 10 rules
│   └── mobile_rules.lua            Section 3.1.4 — 15 sub-rules
│
├── detectors/
│   ├── velocity.lua                Time-window counters (Redis sorted sets)
│   ├── amount.lua                  Statistical amount anomaly detection
│   ├── pattern.lua                 Behavioral pattern analysis
│   └── geo.lua                     Location consistency checks
│
├── storage/
│   ├── redis_adapter.lua           Redis client with atomic operations
│   └── cache.lua                   nginx shared-memory L1 cache
│
└── utils/
    ├── scorer.lua                  Risk score calculation + combo amplifier
    └── logger.lua                  Compliance-grade structured logging (SHA-256 PII hashing)
```

---

## Request Processing Pipeline

```
Inbound Request
      │
      ▼
┌─────────────────────────────────────────────────────┐
│  1. TRANSACTION EXTRACTION  (transaction_extractor) │
│     Headers: x-user-id, x-forwarded-for, x-api-key │
│     Body:    amount, transaction_type, recipient_id │
│     → Assigns UUID v4 transaction_id               │
│     → Clips negative amounts to 0                  │
│     → Validates x-request-id (UUID v4 only)        │
└─────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────┐
│  2. WHITELIST CHECK  (handler.lua)                  │
│     user_ids / merchant_ids / ip_ranges             │
│     → If match: score=0, risk=whitelisted, HTTP 200 │
└─────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────┐
│  3. REDIS CONNECTION  (redis_adapter)               │
│     fail_mode=open  → continue without Redis        │
│     fail_mode=closed → return HTTP 503              │
└─────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────┐
│  4. RULE ENGINE  (rule_engine.lua)                  │
│     Runs enabled rule sets in parallel:             │
│       account_rules  → violations[]                 │
│       pos_rules      → violations[]                 │
│       transfer_rules → violations[]                 │
│       mobile_rules   → violations[]                 │
│     Sorts by severity, caps at 20 violations        │
└─────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────┐
│  5. RISK SCORING  (scorer.lua)                      │
│     Σ violation scores                              │
│     + combo bonus (multi-dimension amplifier)       │
│     → cap at 100                                    │
│     blocked = any(v.blocked) OR score >= block_score│
└─────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────┐
│  6. EXECUTION MODE  (execution_mode.lua)            │
│     enforce → blocked? HTTP 403, else HTTP 200      │
│     shadow  → always HTTP 200, set would-block hdr  │
└─────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────┐
│  7. COMPLIANCE LOG + ALERT  (logger / handler)      │
│     Kong logs: PII fields SHA-256 hashed            │
│     Webhook: POST to alert_webhook_url (TLS verify) │
└─────────────────────────────────────────────────────┘
      │
      ▼
   Response
```

---

## Scoring Model

### Base scoring

Each violation carries a `score` field (0–100) and a `severity` field. Scores are summed and capped at 100.

| Severity | Typical score range |
|----------|-------------------|
| CRITICAL | 40–70             |
| HIGH     | 25–35             |
| MEDIUM   | 15–25             |
| LOW      | 5–10              |

A violation may set `blocked = true` regardless of total score. If **any** violation has `blocked=true`, the request is blocked even if the total score is below `block_score`.

### Progressive scoring — Rule 3.1.1-1 (daily transaction limit)

The daily transaction limit is a **hard limit**. Any overage results in `blocked=true` immediately. The score also scales with how far over the limit the user is:

| Overage ratio | Score | Severity |
|---|---|---|
| 1.0x – 1.5x  | 20    | MEDIUM   |
| 1.5x – 2.0x  | 35    | HIGH     |
| 2.0x – 3.0x  | 50    | CRITICAL |
| ≥ 3.0x       | 70    | CRITICAL |

### Combo amplifier (scorer.lua)

When violations span **multiple risk dimensions simultaneously**, flat bonus points are added:

| Active risk dimensions | Bonus |
|---|---|
| 2 (e.g. velocity + recipient diversity) | +10 |
| 3                                        | +20 |
| 4+                                       | +30 |

Risk dimensions tracked: velocity, recipient diversity, amount anomaly, geo/device, behavioral patterns.

---

## Redis Data Structures

All keys are namespaced as `fg:{type}:{user_id}:{window}`.

### Sorted Sets — Velocity counters

Used for sliding-window time-based counting. Members are unique IDs (`{prefix}_{timestamp_us}_{worker_id}_{seq}`); scores are Unix timestamps.

| Key pattern | Purpose | TTL |
|---|---|---|
| `fg:txn:{user_id}:daily` | Daily transaction count per user | 86400s |
| `fg:txn:{user_id}:hourly` | Hourly transaction count | 3600s |
| `fg:burst:{user_id}` | Burst detection (60-second window) | 300s |
| `fg:merchant:{user_id}:{merchant_id}` | Per-merchant transaction frequency | 86400s |
| `fg:amount:{user_id}:daily` | Daily cumulative amount | 86400s |
| `fg:epin:{card_id}:hourly` | E-PIN card hourly usage | 3600s |
| `fg:repeated:{user_id}` | Repeated exact amounts in 1h window | 3600s |

### Sets — Unique value tracking

| Key pattern | Purpose | TTL |
|---|---|---|
| `fg:recipients:{user_id}:daily` | Unique recipient IDs per day | 86400s |
| `fg:devices:{user_id}` | Device IDs seen for user | 604800s |
| `fg:ips:{user_id}:daily` | Source IPs per day | 86400s |

### Hashes — Statistical baselines

| Key pattern | Purpose | Fields |
|---|---|---|
| `fg:stats:{user_id}` | User transaction statistics | `total`, `count`, `min`, `max`, `avg` |
| `fg:merchant_stats:{merchant_id}` | Merchant revenue baseline | `revenues` (serialized), `last_updated` |
| `fg:locations:{user_id}` | Location history | `{timestamp}` → `{country}:{city}` |
| `fg:device:{user_id}` | Device fingerprint history | `{device_id}` → `{last_seen}` |

### Strings — Simple counters & flags

| Key pattern | Purpose | TTL |
|---|---|---|
| `fg:daily_amount:{user_id}` | Total daily spend | 86400s |
| `fg:monthly_amount:{user_id}` | Total monthly spend | 2592000s |
| `fg:monthly_count:{user_id}` | Monthly transaction count | 2592000s |
| `fg:new_account_vol:{user_id}` | Volume tracking for new accounts | 2592000s |
| `fg:ip_rep:{ip}` | IP reputation score | 3600s |

---

## AKS Deployment Topology

```
                    ┌──────────────────────────────┐
                    │   Azure Container Registry   │
                    │  <your-acr>.azurecr.io    │
                    │  kong-fraud-guard:1.0.x       │
                    └─────────────┬────────────────┘
                                  │ pull
              ┌───────────────────┼────────────────────┐
              │                   │                    │
              ▼                   ▼                    ▼
   ┌─────────────────┐  ┌──────────────────┐  ┌──────────────────┐
   │  Kong CP Pod    │  │  Kong DP Pod     │  │  Redis Pod       │
   │  (Control Plane)│  │  (Data Plane)    │  │  (redis)         │
   │                 │  │                  │  │                  │
   │  Admin API      │  │  Proxy :443      │  │  Port 6379       │
   │  :8444          │  │  Plugins run here│  │                  │
   │                 │  │                  │  └──────────────────┘
   └────────┬────────┘  └────────┬─────────┘
            │                    │
            │ config push         │ Redis ops
            └────────────────────┘
                   hybrid mode
```

**Namespace:** `kong`
**Image:** `<your-acr>.azurecr.io/kong-fraud-guard:<version>`
**Redis host:** `localhost:6379`

Config changes made via Admin API are pushed from CP to DP. There is a **~3 second propagation delay** between a config PATCH and the DP picking it up.

---

## Config Propagation Flow

```
PATCH /plugins/{id}          POST /fraud-test/...
       │                              │
       ▼                              ▼
  Kong CP writes             Kong DP reads plugin
  to DB / cache              config from CP cache
       │                              │
       └─── ~3s push ────────────────►│
                                      ▼
                              New config active
```

Always wait at least **3 seconds** after a config change before testing the new behaviour.

---

## Caching (L1 — nginx shared memory)

The `storage/cache.lua` module provides an in-process cache backed by the `lua_shared_dict fraud_guard_cache` nginx directive. It is used to cache IP validation results and other per-worker transient state.

Default TTL: 300 seconds. Initialised in `init_worker()` phase via `cache.init()`.

---

## Compliance Logging

All logs are emitted to Kong's standard log pipeline (stdout / log-aggregator). PII fields are SHA-256 hashed before logging using a per-deployment salt stored in Kong Vault (`vault://env/FRAUD_GUARD_HASH_SALT`). If no vault reference is configured, a fallback development salt is used.

Hashed fields: `user_id`, `account_id`, `device_id`
Retained fields (not hashed): `ip_address`, `amount`, `merchant_id`, `transaction_type`

Log types: `TRANSACTION`, `BLOCKED_TRANSACTION`, `REVIEW_REQUIRED`, `RULE_VIOLATION`, `PERFORMANCE`, `WEBHOOK`, `HEALTH_CHECK`, `CONFIG_CHANGE`
