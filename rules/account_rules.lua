-- Account Services Rules (Section 3.1.1 - 20 rules)
-- Payment Account Services Risk Rules

local velocity = require "kong.plugins.fraud-guard.detectors.velocity"
local pattern = require "kong.plugins.fraud-guard.detectors.pattern"
local geo = require "kong.plugins.fraud-guard.detectors.geo"
local amount = require "kong.plugins.fraud-guard.detectors.amount"
local redis_adapter = require "kong.plugins.fraud-guard.storage.redis_adapter"

local _M = {}

-- Rule 3.1.1-1: Unusual transaction frequency (progressive scoring)
local function rule_1_1_1(conf, transaction, redis)
  local violations = {}

  -- Check daily transaction velocity
  local daily_count = velocity.check_daily_transactions(
    redis,
    transaction.user_id,
    conf.thresholds.max_daily_transactions,
    transaction.timestamp
  )

  local threshold = conf.thresholds.max_daily_transactions
  if daily_count > threshold then
    -- Progressive scoring: score scales with how far over the limit
    local ratio = daily_count / threshold  -- e.g. 1.5 = 50% over limit
    local score, severity, blocked

    -- Daily limit is a hard limit: any overage → blocked immediately.
    -- Score scales progressively so logs show severity level.
    blocked = true
    if ratio >= 3.0 then
      score = 70
      severity = "CRITICAL"
    elseif ratio >= 2.0 then
      score = 50
      severity = "CRITICAL"
    elseif ratio >= 1.5 then
      score = 35
      severity = "HIGH"
    else
      score = 20
      severity = "MEDIUM"
    end

    table.insert(violations, {
      rule = "3.1.1-1",
      score = score,
      severity = severity,
      description = string.format(
        "Unusual daily transaction frequency: %d transactions (%.1fx threshold of %d)",
        daily_count, ratio, threshold),
      blocked = blocked,
      metadata = {daily_count = daily_count, threshold = threshold, ratio = ratio}
    })
  end

  return violations
end

-- Rule 3.1.1-2: Transfer to 5+ different recipients in one day
local function rule_1_1_2(conf, transaction, redis)
  local violations = {}
  
  -- Only applies to transfers (exclude merchant payments)
  if transaction.transaction_type ~= "transfer" or transaction.merchant_id then
    return violations
  end
  
  if not transaction.recipient_id then
    return violations
  end
  
  local recipient_count, is_new = velocity.check_daily_recipients(
    redis,
    transaction.user_id,
    transaction.recipient_id,
    transaction.timestamp
  )
  
  local threshold = conf.thresholds.max_daily_recipients or 5
  
  if recipient_count >= threshold then
    table.insert(violations, {
      rule = "3.1.1-2",
      score = 40,  -- CRITICAL
      severity = "CRITICAL",
      description = string.format("Transfers to %d different recipients in one day (threshold: %d)", 
                                  recipient_count, threshold),
      blocked = true,
      metadata = {recipient_count = recipient_count, threshold = threshold}
    })
  end
  
  return violations
end

-- Rule 3.1.1-3: High-risk transaction times (late night/early morning)
local function rule_1_1_3(conf, transaction, redis)
  local violations = {}
  
  local hour = transaction.transaction_hour
  if hour >= 22 or hour <= 6 then
    local unusual, hour_count = pattern.check_unusual_hours(hour, transaction.user_id, redis)
    
    if unusual and transaction.amount > 1000 then
      table.insert(violations, {
        rule = "3.1.1-3",
        score = 15,
        severity = "MEDIUM",
        description = string.format("Transaction at unusual hour: %02d:00 with significant amount", hour),
        blocked = false,
        metadata = {hour = hour, hour_history = hour_count}
      })
    end
  end
  
  return violations
end

-- Rule 3.1.1-4: Weekend transaction anomalies
local function rule_1_1_4(conf, transaction, redis)
  local violations = {}
  
  if transaction.is_weekend then
    local is_unusual, reason = pattern.check_weekend_pattern(
      true,
      transaction.transaction_type,
      transaction.user_id,
      redis
    )
    
    if is_unusual and transaction.amount > 5000 then
      table.insert(violations, {
        rule = "3.1.1-4",
        score = 10,
        severity = "LOW",
        description = "Unusual weekend transaction pattern with high amount",
        blocked = false,
        metadata = {reason = reason}
      })
    end
  end
  
  return violations
end

-- Rule 3.1.1-5: Rapid successive transactions
local function rule_1_1_5(conf, transaction, redis)
  local violations = {}
  
  local burst_count = velocity.check_burst_activity(redis, transaction.user_id, 60, transaction.timestamp)
  
  if burst_count > 5 then
    table.insert(violations, {
      rule = "3.1.1-5",
      score = 30,
      severity = "HIGH",
      description = string.format("Burst activity detected: %d transactions in 60 seconds", burst_count),
      blocked = false,
      metadata = {burst_count = burst_count, window = "60s"}
    })
  end
  
  return violations
end

-- Rule 3.1.1-6: New account high volume (under age 20 OR account <30 days: 50+ transactions OR 27,500+ TL/month)
local function rule_1_1_6(conf, transaction, redis)
  local violations = {}
  
  local is_young = transaction.user_age and transaction.user_age < (conf.thresholds.young_user_age_threshold or 20)
  local is_new = transaction.account_age_days and transaction.account_age_days < (conf.thresholds.new_account_days_threshold or 30)
  
  if is_young or is_new then
    local monthly_stats = velocity.check_monthly_stats_for_new_account(
      redis,
      transaction.account_id,
      transaction.amount,
      transaction.account_age_days,
      transaction.timestamp
    )
    
    local txn_threshold = conf.thresholds.new_account_txn_limit or 50
    local amount_threshold = conf.thresholds.new_account_amount_limit or 27500
    
    if monthly_stats.transaction_count >= txn_threshold or 
       monthly_stats.total_amount >= amount_threshold then
      table.insert(violations, {
        rule = "3.1.1-6",
        score = 35,
        severity = "HIGH",
        description = string.format("New/young account high volume: %d transactions, %.2f TL in first month", 
                                    monthly_stats.transaction_count, monthly_stats.total_amount),
        blocked = false,
        metadata = {
          is_young_user = is_young,
          is_new_account = is_new,
          txn_count = monthly_stats.transaction_count,
          total_amount = monthly_stats.total_amount,
          txn_threshold = txn_threshold,
          amount_threshold = amount_threshold
        }
      })
    end
  end
  
  return violations
end

-- Rule 3.1.1-7: Multiple accounts from same IP (5+ accounts from same IP in one day)
local function rule_1_1_7(conf, transaction, redis)
  local violations = {}
  
  if not transaction.ip_address or not transaction.account_id then
    return violations
  end
  
  local account_count, is_new_account = pattern.check_accounts_per_ip(
    redis,
    transaction.ip_address,
    transaction.account_id,
    transaction.timestamp
  )
  
  local threshold = conf.thresholds.max_accounts_per_ip or 5
  
  if account_count >= threshold then
    table.insert(violations, {
      rule = "3.1.1-7",
      score = 45,  -- CRITICAL
      severity = "CRITICAL",
      description = string.format("%d different accounts accessed from IP %s today", 
                                  account_count, transaction.ip_address),
      blocked = true,
      metadata = {account_count = account_count, ip = transaction.ip_address, threshold = threshold}
    })
  end
  
  return violations
end

-- Rule 3.1.1-8: Transaction amount anomalies
local function rule_1_1_8(conf, transaction, redis)
  local violations = {}
  
  local is_anomalous, reason = amount.check_amount_anomaly(
    redis,
    transaction.user_id,
    transaction.amount
  )
  
  if is_anomalous and reason ~= "insufficient_history" then
    table.insert(violations, {
      rule = "3.1.1-8",
      score = 20,
      severity = "MEDIUM",
      description = string.format("Transaction amount anomaly: %s", reason),
      blocked = false,
      metadata = {reason = reason, amount = transaction.amount}
    })
  end
  
  return violations
end

-- Rule 3.1.1-9: Velocity of transaction amounts
local function rule_1_1_9(conf, transaction, redis)
  local violations = {}
  
  local daily_amount = velocity.check_daily_amount(
    redis,
    transaction.account_id,
    transaction.amount,
    transaction.timestamp
  )
  
  local max_daily = conf.thresholds.max_daily_amount or 100000
  
  if daily_amount > max_daily then
    table.insert(violations, {
      rule = "3.1.1-9",
      score = 25,
      severity = "HIGH",
      description = string.format("Daily amount limit exceeded: %.2f TL (limit: %d)", daily_amount, max_daily),
      blocked = false,
      metadata = {daily_amount = daily_amount, threshold = max_daily}
    })
  end
  
  return violations
end

-- Rule 3.1.1-10: Repeated exact amount transactions
local function rule_1_1_10(conf, transaction, redis)
  local violations = {}
  
  local is_repeated, count = velocity.check_repeated_amounts(
    redis,
    transaction.user_id,
    transaction.amount,
    3600,  -- 1 hour window
    transaction.timestamp
  )
  
  if count and count >= 3 then
    table.insert(violations, {
      rule = "3.1.1-10",
      score = 20,
      severity = "MEDIUM",
      description = string.format("Repeated exact amount: %.2f TL (%d times in 1 hour)", 
                                  transaction.amount, count),
      blocked = false,
      metadata = {amount = transaction.amount, count = count, window = "1h"}
    })
  end
  
  return violations
end

-- Rule 3.1.1-11: Location-based anomalies
local function rule_1_1_11(conf, transaction, redis)
  local violations = {}
  
  if not transaction.ip_address then
    return violations
  end
  
  local impossible, travel_info = geo.check_impossible_travel(
    redis,
    transaction.user_id,
    transaction.ip_address,
    transaction.timestamp
  )
  
  if impossible then
    table.insert(violations, {
      rule = "3.1.1-11",
      score = 40,
      severity = "CRITICAL",
      description = string.format("Impossible travel detected: %s", travel_info),
      blocked = false,
      metadata = {travel_info = travel_info}
    })
  end
  
  return violations
end

-- Rule 3.1.1-12: Device switching pattern
local function rule_1_1_12(conf, transaction, redis)
  local violations = {}
  
  if not transaction.device_id then
    return violations
  end
  
  local is_switching, device_count = pattern.check_device_switching(
    redis,
    transaction.user_id,
    transaction.device_id,
    transaction.timestamp
  )
  
  if is_switching then
    table.insert(violations, {
      rule = "3.1.1-12",
      score = 20,
      severity = "MEDIUM",
      description = string.format("Multiple devices: %d different devices in 24 hours", device_count),
      blocked = false,
      metadata = {device_count = device_count}
    })
  end
  
  return violations
end

-- Rule 3.1.1-13: IP hopping detection
local function rule_1_1_13(conf, transaction, redis)
  local violations = {}
  
  if not transaction.ip_address then
    return violations
  end
  
  local is_hopping, ip_count = geo.check_ip_hopping(
    redis,
    transaction.user_id,
    transaction.ip_address,
    transaction.timestamp
  )
  
  if is_hopping then
    table.insert(violations, {
      rule = "3.1.1-13",
      score = 30,
      severity = "HIGH",
      description = string.format("IP hopping: %d different IPs in 24 hours", ip_count),
      blocked = false,
      metadata = {ip_count = ip_count}
    })
  end
  
  return violations
end

-- Rule 3.1.1-14: Round amount pattern
local function rule_1_1_14(conf, transaction, redis)
  local violations = {}
  
  local is_round, amount = pattern.check_round_amounts(transaction.amount)
  
  if is_round and transaction.amount >= 5000 then
    table.insert(violations, {
      rule = "3.1.1-14",
      score = 10,
      severity = "LOW",
      description = string.format("Round amount transaction: %.2f TL", amount),
      blocked = false,
      metadata = {amount = amount}
    })
  end
  
  return violations
end

-- Rule 3.1.1-15: Suspicious keywords in transaction description or merchant name
-- BDDK / Turkish banking law: gambling/betting transactions must be directly blocked.
local function rule_1_1_15(conf, transaction, redis)
  local violations = {}

  if not conf.suspicious_keywords then
    return violations
  end

  -- Check description AND merchant_id so keyword detection fires even when
  -- description is absent (e.g. POS transactions that omit a free-text field).
  local fields_to_check = {}
  if transaction.description and transaction.description ~= "" then
    table.insert(fields_to_check, {value = transaction.description, field = "description"})
  end
  if transaction.merchant_id then
    table.insert(fields_to_check, {value = tostring(transaction.merchant_id), field = "merchant_id"})
  end

  if #fields_to_check == 0 then
    return violations
  end

  for _, entry in ipairs(fields_to_check) do
    local has_keyword, keyword = pattern.check_suspicious_keywords(
      entry.value,
      conf.suspicious_keywords
    )

    if has_keyword then
      table.insert(violations, {
        rule = "3.1.1-15",
        score = 50,
        severity = "CRITICAL",
        description = string.format(
          "Suspicious keyword '%s' detected in %s — gambling/betting transactions are prohibited",
          keyword, entry.field
        ),
        blocked = true,  -- Direct block: illegal per BDDK regulations
        metadata = {keyword = keyword, field = entry.field, value = entry.value}
      })
      break  -- One match is enough to block; no need to scan further fields
    end
  end

  return violations
end

-- Rule 3.1.1-16: Threshold avoidance (structuring)
local function rule_1_1_16(conf, transaction, redis)
  local violations = {}
  
  local is_avoiding, reason = amount.check_threshold_avoidance(transaction.amount)
  
  if is_avoiding then
    table.insert(violations, {
      rule = "3.1.1-16",
      score = 30,
      severity = "HIGH",
      description = string.format("Potential structuring: %s", reason),
      blocked = false,
      metadata = {reason = reason, amount = transaction.amount}
    })
  end
  
  return violations
end

-- Rule 3.1.1-17: Incremental testing pattern (card validation fraud)
local function rule_1_1_17(conf, transaction, redis)
  local violations = {}
  
  local is_testing, reason = amount.check_incremental_testing(
    redis,
    transaction.user_id,
    transaction.amount,
    transaction.timestamp
  )
  
  if is_testing then
    table.insert(violations, {
      rule = "3.1.1-17",
      score = 35,
      severity = "HIGH",
      description = string.format("Incremental card testing detected: %s", reason),
      blocked = false,
      metadata = {reason = reason}
    })
  end
  
  return violations
end

-- Rule 3.1.1-18: Multiple transactions at same merchant within 2 hours (5+)
local function rule_1_1_18(conf, transaction, redis)
  local violations = {}
  
  if not transaction.merchant_id then
    return violations
  end
  
  local txn_count = velocity.check_merchant_frequency(
    redis,
    transaction.user_id,
    transaction.merchant_id,
    7200,  -- 2 hours
    transaction.timestamp
  )
  
  local threshold = conf.thresholds.max_transactions_2hours_same_merchant or 5
  
  if txn_count >= threshold then
    table.insert(violations, {
      rule = "3.1.1-18",
      score = 25,
      severity = "HIGH",
      description = string.format("%d transactions at same merchant within 2 hours", txn_count),
      blocked = false,
      metadata = {txn_count = txn_count, merchant_id = transaction.merchant_id, threshold = threshold}
    })
  end
  
  return violations
end

-- Rule 3.1.1-19: Low reputation IP
local function rule_1_1_19(conf, transaction, redis)
  local violations = {}
  
  if not transaction.ip_address then
    return violations
  end
  
  local reputation = geo.get_ip_reputation(redis, transaction.ip_address)
  
  if reputation.score < 20 then
    table.insert(violations, {
      rule = "3.1.1-19",
      score = 25,
      severity = "HIGH",
      description = string.format("Low IP reputation: score %d", reputation.score),
      blocked = false,
      metadata = {
        reputation_score = reputation.score,
        ip = transaction.ip_address,
        blocked_count = reputation.blocked_count
      }
    })
  end
  
  return violations
end

-- Rule 3.1.1-20: Account behavior mismatch (new account, large transaction)
local function rule_1_1_20(conf, transaction, redis)
  local violations = {}
  
  if not transaction.account_age_days then
    return violations
  end
  
  local is_mismatch, reason = pattern.check_account_behavior_mismatch(
    transaction.account_age_days,
    transaction.amount,
    transaction.transaction_type
  )
  
  if is_mismatch then
    table.insert(violations, {
      rule = "3.1.1-20",
      score = 30,
      severity = "HIGH",
      description = string.format("Account behavior mismatch: %s", reason),
      blocked = false,
      metadata = {
        reason = reason,
        account_age_days = transaction.account_age_days,
        amount = transaction.amount
      }
    })
  end
  
  return violations
end

-- Main check function for all account rules
function _M.check(conf, transaction, redis)
  local all_violations = {}
  
  -- Execute all 20 rules
  local rules = {
    rule_1_1_1,   -- Unusual frequency
    rule_1_1_2,   -- 5+ recipients/day
    rule_1_1_3,   -- Late night transactions
    rule_1_1_4,   -- Weekend anomalies
    rule_1_1_5,   -- Burst activity
    rule_1_1_6,   -- New account high volume
    rule_1_1_7,   -- Multiple accounts per IP
    rule_1_1_8,   -- Amount anomalies
    rule_1_1_9,   -- Daily amount velocity
    rule_1_1_10,  -- Repeated amounts
    rule_1_1_11,  -- Impossible travel
    rule_1_1_12,  -- Device switching
    rule_1_1_13,  -- IP hopping
    rule_1_1_14,  -- Round amounts
    rule_1_1_15,  -- Suspicious keywords
    rule_1_1_16,  -- Structuring
    rule_1_1_17,  -- Incremental testing
    rule_1_1_18,  -- Same merchant frequency
    rule_1_1_19,  -- Low IP reputation
    rule_1_1_20   -- Account behavior mismatch
  }
  
  for _, rule_func in ipairs(rules) do
    local violations = rule_func(conf, transaction, redis)
    for _, v in ipairs(violations) do
      table.insert(all_violations, v)
    end
  end
  
  return all_violations
end

return _M
