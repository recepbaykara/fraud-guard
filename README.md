# Fraud Guard — Kong Gateway Plugin

[![Version](https://img.shields.io/badge/version-1.0.3-blue.svg)](VERSION)
[![Kong](https://img.shields.io/badge/Kong-3.13.0.x-green.svg)](https://konghq.com/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Real-time fraud detection plugin for Kong Gateway. Implements 77 risk detection rules aligned with BDDK (Bankacılık Düzenleme ve Denetleme Kurumu) circular requirements. Runs entirely inside the Kong data plane — no external scoring service required.

---

## Documentation

| Document | Description |
|---|---|
| [architecture.md](documentation/architecture.md) | System architecture, request pipeline, Redis key types, AKS topology |
| [plugin_documentation.md](documentation/plugin_documentation.md) | Configuration reference, request/response format, scoring, modes |
| [rule_matrix.md](documentation/rule_matrix.md) | All 77 rules with scores, severities, auto-block flags |

---

## Quick Start

### 1. Deploy to AKS

```bash
# Build and push image
docker buildx build --platform linux/amd64 --push \
  -t <your-acr>.azurecr.io/kong-fraud-guard:1.0.1 \
  -f Dockerfile.kong .

# Update Kong pods
kubectl set image deployment/kong-cp-kong \
  proxy=<your-acr>.azurecr.io/kong-fraud-guard:1.0.1 -n kong

kubectl set image deployment/kong-dp-kong \
  proxy=<your-acr>.azurecr.io/kong-fraud-guard:1.0.1 -n kong
```

### 2. Enable the plugin

```bash
curl -X POST https://<admin-url>/services/<service>/plugins \
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

Start in **shadow mode** — the plugin evaluates all rules and sets response headers but never blocks. Switch to `enforce` once thresholds are calibrated.

### 3. Send a transaction

```bash
curl -X POST https://<kong-proxy>/fraud-test/post \
  -H "Content-Type: application/json" \
  -H "x-api-key: <your-key>" \
  -d '{
    "user_id": "user_12345",
    "amount": 2500,
    "currency": "TRY",
    "transaction_type": "transfer",
    "recipient_id": "recipient_abc",
    "account_age_days": 365,
    "user_age": 32
  }'
```

Response headers:

```
x-fraud-score: 0
x-risk-level: low
x-fraud-mode: shadow
x-transaction-id: 3f8a2c1d-4b5e-4f9a-8c7d-1e2f3a4b5c6d
x-execution-time-ms: 12.00
```

---

## How It Works

```
Request → Transaction Extraction → Whitelist Check → Redis Connect
       → Rule Engine (77 rules) → Risk Scoring → Execution Mode
       → Compliance Log + Webhook → Response
```

1. **Transaction Extraction** — Parses headers and JSON body into a transaction struct. Assigns a UUID v4 transaction ID. Clips negative amounts to zero.
2. **Whitelist Check** — Whitelisted users/merchants/IPs bypass all rules instantly (score=0).
3. **Rule Engine** — Runs 4 rule sets in parallel: account (3.1.1), POS (3.1.2), transfer (3.1.3), mobile (3.1.4).
4. **Risk Scoring** — Sums violation scores + combo bonus for multi-dimension attacks. Capped at 100.
5. **Execution Mode** — `enforce`: blocks if score ≥ block_score or any violation has blocked=true. `shadow`: always passes, sets would-block headers.
6. **Logging** — PII fields (user_id, account_id, device_id) are SHA-256 hashed before writing to Kong logs.

---

## Rule Summary

| Section | Rules | Auto-Block Rules |
|---|---|---|
| 3.1.1 Payment Account Services | 20 | 4 |
| 3.1.2 POS / Virtual POS | 25 | 3 |
| 3.1.3 Bill Payment & Transfer | 10 | 3 |
| 3.1.4 Mobile Payments | 15 | 2 |
| 3.2 API Security | 7 | 2 |
| **Total** | **77** | **14** |

Auto-block rules fire `blocked=true` and block the transaction regardless of total score. Key examples:

- **3.1.1-1** — Daily transaction limit exceeded → immediate block (hard limit)
- **3.1.1-2** — Transfer to 5+ unique recipients in one day → block
- **3.1.1-15** — Gambling/illegal keyword (`kumar`, `bahis`, etc.) in description → block
- **3.1.2-15** — E-PIN card: 3+ uses or > 15,000 TRY/hour → block
- **3.1.3-8** — Transfer to FATF blacklisted country → block
- **3.1.4-2h** — Mobile payment within 24h of SIM swap → block

Full rule details: [rule_matrix.md](documentation/rule_matrix.md)

---

## Scoring

Scores are additive and capped at 100.

**Block conditions** — either condition is sufficient:
- Total score ≥ `block_score` (default: 70)
- Any single violation sets `blocked = true`

**Progressive scoring** — rule 3.1.1-1 (daily limit) scales with overage:

| Overage | Score | Blocked |
|---|---|---|
| 1.0×–1.5× | 20 | Yes |
| 1.5×–2.0× | 35 | Yes |
| 2.0×–3.0× | 50 | Yes |
| ≥ 3.0× | 70 | Yes |

**Combo amplifier** — bonus points when violations span multiple risk dimensions:

| Dimensions active | Bonus |
|---|---|
| 2 | +10 |
| 3 | +20 |
| 4+ | +30 |

---

## Deployment Strategy

### Phase 1 — Shadow (week 1–2)

```json
{ "mode": "shadow", "fail_mode": "open" }
```

Observe `x-fraud-would-block` and `x-triggered-rules` headers. No requests are blocked.

### Phase 2 — Enforce with high threshold (week 3)

```json
{ "mode": "enforce", "thresholds": { "block_score": 85 } }
```

Block only the clearest fraud signals. Monitor block rate and adjust.

### Phase 3 — Full enforcement (week 4+)

```json
{ "mode": "enforce", "fail_mode": "closed", "thresholds": { "block_score": 70 } }
```

Full enforcement with fail-closed safety (Redis downtime → block all).

---

## Requirements

| Component | Version |
|---|---|
| Kong Gateway | 3.13.0.x |
| Redis | 5.0+ |
| Lua | 5.1 (OpenResty, bundled with Kong) |
| `lua-resty-jit-uuid` | latest |
| `lua-resty-string` | latest |

---

## Troubleshooting

**All transactions blocked unexpectedly**
- Check `fail_mode`: if set to `closed` and Redis is down, all requests are blocked. Switch to `open` temporarily.
- Run: `kubectl exec -n kong <redis-pod> -- redis-cli ping`

**High false positive rate**
- Switch to `shadow` mode and analyse `x-triggered-rules` headers.
- Increase `block_score` incrementally (e.g. 70 → 80).
- Add trusted users/IPs to `whitelists`.

**Config change not taking effect**
- Kong CP→DP propagation takes ~3 seconds. Wait before re-testing.

**Slow execution (> 50ms)**
- Check Redis latency: `redis-cli --latency -h <host>`
- Disable unused rule categories (`enable_pos_transactions: false`, etc.)
- Increase Redis keepalive pool: `redis.keepalive_pool_size: 50`

---

## Compliance

| Regulation | Coverage |
|---|---|
| BDDK Circular (Kasım 2025) | Real-time detection, daily limits, gambling prohibition, E-PIN controls, API auth |
| KVKK | PII hashing in logs, user data anonymisation API |
| FATF | High-risk country blocking (rule 3.1.3-8) |
| Bankacılık Kanunu 5411 | 10-year audit log retention (`retention_days: 3650`) |

---

## License

Proprietary. All rights reserved.
