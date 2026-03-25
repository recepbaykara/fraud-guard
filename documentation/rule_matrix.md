# Fraud Guard — Rule Matrix

Rules are organised per the BDDK (Bankacılık Düzenleme ve Denetleme Kurumu) fraud detection framework. Each rule maps to a section number, has a fixed score contribution, severity level, and may carry a hard `blocked=true` flag that triggers an immediate block regardless of total score.

**Legend**
- **Score** — Points added to total risk score when this rule fires
- **Severity** — CRITICAL / HIGH / MEDIUM / LOW
- **Auto-Block** — `✓` means `blocked=true`; transaction is blocked even if total score < `block_score`
- **Rule file** — Source file implementing this rule

---

## Section 3.1.1 — Payment Account Services (20 rules)

| Rule ID | Name | Trigger Condition | Score | Severity | Auto-Block | Notes |
|---|---|---|---|---|---|---|
| 3.1.1-1 | Daily transaction frequency | Daily tx count > `max_daily_transactions` | **20–70** ¹ | MEDIUM–CRITICAL | **✓** | Progressive: score scales with overage ratio |
| 3.1.1-2 | Multiple recipients | Transfer to ≥ `max_daily_recipients` unique recipients in one day | 40 | CRITICAL | **✓** | Only for `transaction_type=transfer` without `merchant_id` |
| 3.1.1-3 | Unusual hours + amount | Transaction between 22:00–06:00 AND amount > 1,000 TRY | 15 | MEDIUM | — | |
| 3.1.1-4 | Weekend anomaly | Unusual weekend pattern AND amount > 5,000 TRY | 10 | LOW | — | |
| 3.1.1-5 | Burst activity | > 5 transactions in 60 seconds | 30 | HIGH | — | |
| 3.1.1-6 | New account high volume | Account < 30 days OR user < 20 years AND monthly tx > 50 OR monthly amount > 27,500 TRY | 25 | HIGH | — | |
| 3.1.1-7 | Multiple accounts per IP | Same source IP used by 3+ different accounts on same day | 50 | CRITICAL | **✓** | Strong money mule / account takeover signal |
| 3.1.1-8 | Amount anomaly | Transaction amount > 3× user's historical average | 20 | MEDIUM | — | Requires at least 5 prior transactions for baseline |
| 3.1.1-9 | Velocity amount check | Young user (< 20) OR new account (< 30 days) with amount > 5,000 TRY | 25 | HIGH | — | |
| 3.1.1-10 | Repeated exact amounts | Same exact amount sent 3+ times within 1 hour | 20 | HIGH | — | Structuring / automated fraud signal |
| 3.1.1-11 | Impossible travel | Transactions from geographically distant locations within 1 hour | 35 | HIGH | — | Requires location history in Redis |
| 3.1.1-12 | Device switching | 3+ different device IDs used in 24 hours | 25 | HIGH | — | |
| 3.1.1-13 | IP hopping | 4+ different source IPs in 1 hour | 30 | HIGH | — | |
| 3.1.1-14 | Daily amount exceeded | User's cumulative daily amount > `max_daily_amount` | 35 | HIGH | — | |
| 3.1.1-15 | Suspicious keywords | `description` or `merchant_id` contains gambling/illegal keywords ² | 50 | CRITICAL | **✓** | BDDK mandatory |
| 3.1.1-16 | Structuring pattern | Multiple transfers just below reporting threshold (e.g. 9,500–9,999 TRY) | 35 | HIGH | — | |
| 3.1.1-17 | Incremental testing | Sequence of increasing-amount transactions in short window | 20 | MEDIUM | — | Card testing pattern |
| 3.1.1-18 | Merchant frequency spike | Unusual surge in transactions to same merchant | 15 | MEDIUM | — | |
| 3.1.1-19 | IP reputation | Known bad IP (high previous fraud score in Redis) | 25 | HIGH | — | |
| 3.1.1-20 | Account behaviour mismatch | Transaction pattern inconsistent with account history | 30 | HIGH | — | |

¹ **Progressive scoring for 3.1.1-1:**

| Overage ratio | Score | Severity | Auto-Block |
|---|---|---|---|
| 1.0× – 1.5× | 20 | MEDIUM | **✓** |
| 1.5× – 2.0× | 35 | HIGH | **✓** |
| 2.0× – 3.0× | 50 | CRITICAL | **✓** |
| ≥ 3.0× | 70 | CRITICAL | **✓** |

² **Keyword list for 3.1.1-15:**
`kumar`, `bahis`, `bet`, `betting`, `casino`, `poker`, `slot`, `jackpot`, `rulet`, `tombala`, `şans oyunu`, `lottery`, `illegal`, `kaçakçılık`, `uyuşturucu`

---

## Section 3.1.2 — POS / Virtual POS Services (25 rules)

| Rule ID | Name | Trigger Condition | Score | Severity | Auto-Block |
|---|---|---|---|---|---|
| 3.1.2-1 | Merchant amount anomaly | POS amount > 5× merchant's historical average revenue | 30 | HIGH | — |
| 3.1.2-2 | Abnormal refund ratio | Merchant refund rate > 30% in rolling window | 25 | HIGH | — |
| 3.1.2-3 | Unusual POS hours | POS transaction between 00:00–05:00 AND amount > 2,000 TRY | 15 | MEDIUM | — |
| 3.1.2-4 | Geographic inconsistency | POS location inconsistent with user's recent location history | 30 | HIGH | — |
| 3.1.2-5 | Card testing pattern | Multiple small POS transactions (< 10 TRY) within 5 minutes | 35 | HIGH | — |
| 3.1.2-6 | POS velocity spike | POS transaction count more than 3× normal hourly rate | 25 | HIGH | — |
| 3.1.2-7 | MCC category mismatch | Transaction category unusual for this user's history | 15 | MEDIUM | — |
| 3.1.2-8 | Excessive failed attempts | 5+ failed POS auth attempts in past hour | 30 | HIGH | — |
| 3.1.2-9 | High-risk merchant category | Transaction at blacklisted MCC (pawn shops, unlicensed FX) | 35 | HIGH | — |
| 3.1.2-10 | Cross-border POS | POS transaction at foreign merchant outside known travel pattern | 25 | HIGH | — |
| 3.1.2-11 | Rapid merchant switching | 5+ different merchants in 10 minutes | 30 | HIGH | — |
| 3.1.2-12 | Amount rounding | 95%+ of POS transactions are exact round numbers | 15 | MEDIUM | — |
| 3.1.2-13 | New merchant high value | First transaction at merchant AND amount > 10,000 TRY | 25 | HIGH | — |
| 3.1.2-14 | Weekend high-value POS | POS > 20,000 TRY on weekend with no prior weekend history | 20 | MEDIUM | — |
| 3.1.2-15 | E-PIN card abuse | 3+ E-PIN transactions in 1 hour OR total > 15,000 TRY/hour | 50 | CRITICAL | **✓** |
| 3.1.2-16 | Multiple cards per IP | 3+ different card BINs from same IP in 1 hour | 40 | CRITICAL | **✓** |
| 3.1.2-17 | Dormant card reactivation | Card unused for 90+ days, now high-value transaction | 25 | HIGH | — |
| 3.1.2-18 | High-value at low-avg merchant | Transaction > 10× merchant's average basket size | 30 | HIGH | — |
| 3.1.2-19 | Suspicious refund pattern | Refund immediately followed by equivalent purchase | 30 | HIGH | — |
| 3.1.2-20 | Blacklisted IP virtual POS | Virtual POS transaction from known malicious IP | 50 | CRITICAL | **✓** |
| 3.1.2-21 | POS daily velocity | Daily POS count > 2× normal for this user | 20 | MEDIUM | — |
| 3.1.2-22 | Card daily velocity | Same card used > 15 times in one day | 30 | HIGH | — |
| 3.1.2-23 | Merchant reputation | Merchant has elevated fraud incident rate in platform history | 20 | MEDIUM | — |
| 3.1.2-24 | Auth reversals | 3+ auth reversals within 1 hour | 25 | HIGH | — |
| 3.1.2-25 | Contactless anomaly | Contactless transaction > 500 TRY or outside normal location | 15 | MEDIUM | — |

---

## Section 3.1.3 — Bill Payment & Money Transfer (10 rules)

| Rule ID | Name | Trigger Condition | Score | Severity | Auto-Block |
|---|---|---|---|---|---|
| 3.1.3-1 | High-value transfer anomaly | Transfer amount > 3× user's historical average transfer | 25 | HIGH | — |
| 3.1.3-2 | Rapid transfer frequency | 5+ transfers in 1 hour | 30 | HIGH | — |
| 3.1.3-3 | Transfer to new beneficiary | First-ever transfer to this recipient AND amount > 10,000 TRY | 35 | HIGH | — |
| 3.1.3-4 | Split transfer (structuring) | 3+ transfers to same recipient within 1 hour totalling > threshold | 40 | CRITICAL | **✓** |
| 3.1.3-5 | Same-day roundtrip | Money sent out then returned to sender account same day | 35 | HIGH | — |
| 3.1.3-6 | Unusual biller | Bill payment to biller with no prior history AND high amount | 15 | MEDIUM | — |
| 3.1.3-7 | Transfer after deposit | Large transfer within 10 minutes of receiving equivalent deposit | 40 | CRITICAL | **✓** |
| 3.1.3-8 | High-risk country transfer | Transfer destination country on FATF grey/blacklist | 45 | CRITICAL | **✓** |
| 3.1.3-9 | Repeat beneficiary concentration | > 80% of monthly transfers go to same single recipient | 20 | MEDIUM | — |
| 3.1.3-10 | Non-business-hours large transfer | Transfer > 50,000 TRY outside 08:00–18:00 weekdays | 25 | HIGH | — |

---

## Section 3.1.4 — Mobile Payment Services (15 sub-rules)

### Group 3.1.4-1 — Device-specific indicators

| Sub-rule | Name | Trigger Condition | Score | Severity | Auto-Block |
|---|---|---|---|---|---|
| 3.1.4-1a | New device high-value | First payment from this device AND amount > 5,000 TRY | 30 | HIGH | — |
| 3.1.4-1b | Jailbroken/rooted device | Device fingerprint indicates compromised OS | 40 | CRITICAL | **✓** |
| 3.1.4-1c | Device-IP location mismatch | Device GPS location inconsistent with IP geolocation | 25 | HIGH | — |
| 3.1.4-1d | Mobile payment burst | 3+ mobile payments in 30 seconds | 35 | HIGH | — |
| 3.1.4-1e | Outdated app version | App version below minimum secure version | 15 | MEDIUM | — |
| 3.1.4-1f | Deep night payment | Mobile payment between 02:00–05:00 AND amount > 2,000 TRY | 20 | MEDIUM | — |
| 3.1.4-1g | Daily mobile limit | 50+ mobile payments in one day | 30 | HIGH | — |

### Group 3.1.4-2 — Behavioural anomalies

| Sub-rule | Name | Trigger Condition | Score | Severity | Auto-Block |
|---|---|---|---|---|---|
| 3.1.4-2a | Device fingerprint change | Device ID changed within last 24 hours, then payment | 25 | HIGH | — |
| 3.1.4-2b | Payment after password change | Mobile payment within 5 minutes of password change | 35 | HIGH | — |
| 3.1.4-2c | VPN/Proxy detected | Source IP identified as VPN, proxy, or Tor exit node | 25 | HIGH | — |
| 3.1.4-2d | Biometric bypass | Authentication method downgraded from biometric to PIN/password | 30 | HIGH | — |
| 3.1.4-2e | Velocity spike | Mobile payment rate 5× above user's normal | 25 | HIGH | — |
| 3.1.4-2f | Suspicious QR merchant | QR payment to merchant with no transaction history | 20 | MEDIUM | — |
| 3.1.4-2g | Rapid beneficiary change | Different recipient on each of 3+ consecutive payments | 30 | HIGH | — |
| 3.1.4-2h | SIM change + payment | Mobile payment within 24 hours of SIM swap event | 50 | CRITICAL | **✓** |

---

## Section 3.2 — API Security (7 requirements)

| Rule ID | Name | Trigger Condition | Score | Severity | Auto-Block |
|---|---|---|---|---|---|
| 3.2-1 | Missing authentication | `x-api-key` header absent | 30 | HIGH | — | ¹ |
| 3.2-2 | Invalid API key format | Key present but does not match expected format | 25 | HIGH | — |
| 3.2-3 | Token replay | Same token used from different IP within 1 minute | 40 | CRITICAL | **✓** |
| 3.2-4 | API rate limit | > 100 API calls/minute from same consumer | 30 | HIGH | — |
| 3.2-5 | Sensitive endpoint access | Request to `/admin`, `/internal`, `/debug` path | 35 | HIGH | — |
| 3.2-6 | Payload size abuse | Request body > 1 MB | 20 | MEDIUM | — |
| 3.2-7 | Credential stuffing | > 20 auth attempts in 5 minutes from same IP | 50 | CRITICAL | **✓** |
| 3.2-K1 | Auth enforcement | Delegated to **key-auth** Kong plugin | — | — | — | ² |
| 3.2-K2 | TLS enforcement | Delegated to Kong TLS termination | — | — | — | ² |

¹ Rule 3.2-1 requires key-auth plugin to be configured with `hide_credentials: false`. If `hide_credentials: true`, the header is stripped before fraud-guard sees it, causing every request to trigger this rule.

² Requirements handled by Kong infrastructure, not by the fraud-guard plugin itself.

---

## Auto-Block Rules Summary

These rules trigger an immediate block (`blocked=true`) regardless of total score:

| Rule | Condition | Score |
|---|---|---|
| 3.1.1-1 | Daily transaction limit exceeded (any amount) | 20–70 |
| 3.1.1-2 | Transfer to ≥ max_daily_recipients unique recipients | 40 |
| 3.1.1-7 | Same IP used by 3+ accounts in one day | 50 |
| 3.1.1-15 | Gambling/illegal keyword in description or merchant_id | 50 |
| 3.1.2-15 | E-PIN card: 3+ uses or > 15,000 TRY/hour | 50 |
| 3.1.2-16 | 3+ card BINs from same IP in 1 hour | 40 |
| 3.1.2-20 | Virtual POS from blacklisted IP | 50 |
| 3.1.3-4 | Split transfer structuring | 40 |
| 3.1.3-7 | Transfer within 10 min of equivalent deposit | 40 |
| 3.1.3-8 | Transfer to FATF blacklisted country | 45 |
| 3.1.4-1b | Jailbroken/rooted device | 40 |
| 3.1.4-2h | Mobile payment within 24h of SIM change | 50 |
| 3.2-3 | Token replay from different IP | 40 |
| 3.2-7 | Credential stuffing (20+ auth attempts / 5 min) | 50 |

---

## Rule Coverage Statistics

| Section | Total Rules | Auto-Block Rules | Max Score (single rule) |
|---|---|---|---|
| 3.1.1 Payment Account | 20 | 4 | 70 (3.1.1-1 at 3×) |
| 3.1.2 POS | 25 | 3 | 50 |
| 3.1.3 Transfer | 10 | 3 | 45 |
| 3.1.4 Mobile | 15 | 2 | 50 |
| 3.2 API Security | 7 (+2 Kong) | 2 | 50 |
| **Total** | **77** | **14** | — |

---

## Combo Score Examples

The scorer adds bonus points when violations span multiple risk dimensions simultaneously:

| Scenario | Rules | Base Score | Combo Bonus | Total | Outcome |
|---|---|---|---|---|---|
| Daily limit 1.2× + 3 recipients | 3.1.1-1 + 3.1.1-2 | 20+40=60 | +10 (2 dims) | 70 | BLOCKED (score + blocked flag) |
| Daily limit 2× + 3 recipients + young user | 3.1.1-1 + 3.1.1-2 + 3.1.1-9 | 50+40+25=115→100 | +20 (3 dims) | 100 | BLOCKED |
| Keyword "kumar" + young user | 3.1.1-15 + 3.1.1-9 | 50+25=75 | +10 (2 dims) | 85 | BLOCKED (keyword flag + score) |
| Normal POS, established account | — | 0 | 0 | 0 | ALLOWED |

---

## Regulatory Compliance Mapping

| Regulation | Requirement | Covered By |
|---|---|---|
| BDDK Circular (Nov 2025) | Real-time fraud detection | All rule sections |
| BDDK Circular (Nov 2025) | Gambling transaction prohibition | Rule 3.1.1-15 |
| BDDK Circular (Nov 2025) | Daily transaction limits | Rule 3.1.1-1 |
| BDDK Circular (Nov 2025) | Multi-recipient transfer limits | Rule 3.1.1-2 |
| BDDK Circular (Nov 2025) | E-PIN card controls | Rule 3.1.2-15 |
| BDDK Circular (Nov 2025) | API authentication | Section 3.2 |
| KVKK | PII data minimisation in logs | SHA-256 hashing in logger.lua |
| KVKK | User data deletion support | `anonymize_user_data()` in logger.lua |
| FATF | High-risk country monitoring | Rule 3.1.3-8 |
| Banking Law 5411 | 10-year audit log retention | `retention_days: 3650` in log entries |
