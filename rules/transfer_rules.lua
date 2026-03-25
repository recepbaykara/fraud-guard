-- Bill Payment and Money Transfer Rules (Section 3.1.3 - 10 rules)
-- Transfer Services Risk Rules

local velocity = require "kong.plugins.fraud-guard.detectors.velocity"
local pattern = require "kong.plugins.fraud-guard.detectors.pattern"
local amount = require "kong.plugins.fraud-guard.detectors.amount"
local redis_adapter = require "kong.plugins.fraud-guard.storage.redis_adapter"

local _M = {}

-- Rule 3.1.3-1: High-value transfer anomaly
local function rule_1_3_1(conf, transaction, redis)
  local violations = {}
  
  if transaction.transaction_type ~= "transfer" and transaction.transaction_type ~= "bill_payment" then
    return violations
  end
  
  local is_anomalous, reason = amount.check_amount_anomaly(
    redis,
    transaction.user_id,
    transaction.amount
  )
  
  if is_anomalous and reason ~= "insufficient_history" and transaction.amount > 5000 then
    table.insert(violations, {
      rule = "3.1.3-1",
      score = 25,
      severity = "HIGH",
      description = string.format("High-value transfer anomaly: %s", reason),
      blocked = false,
      metadata = {reason = reason, amount = transaction.amount}
    })
  end
  
  return violations
end

-- Rule 3.1.3-2: Rapid transfer frequency
local function rule_1_3_2(conf, transaction, redis)
  local violations = {}
  
  if transaction.transaction_type ~= "transfer" then
    return violations
  end
  
  local hourly_count = velocity.check_hourly_transactions(
    redis,
    transaction.user_id,
    conf.thresholds.max_hourly_transactions or 20,
    transaction.timestamp
  )
  
  if hourly_count > 10 then  -- 10+ transfers in 1 hour
    table.insert(violations, {
      rule = "3.1.3-2",
      score = 30,
      severity = "HIGH",
      description = string.format("Rapid transfer frequency: %d transfers in 1 hour", hourly_count),
      blocked = false,
      metadata = {hourly_count = hourly_count}
    })
  end
  
  return violations
end

-- Rule 3.1.3-3: Transfer to new beneficiary with high amount
local function rule_1_3_3(conf, transaction, redis)
  local violations = {}
  
  if transaction.transaction_type ~= "transfer" or not transaction.recipient_id then
    return violations
  end
  
  local key = string.format("user:%s:beneficiary:%s:first_transfer", 
                           transaction.user_id, transaction.recipient_id)
  
  local first_transfer, _ = redis_adapter.get(redis, key)
  
  if not first_transfer and transaction.amount > 10000 then
    table.insert(violations, {
      rule = "3.1.3-3",
      score = 30,
      severity = "HIGH",
      description = string.format("First transfer to new beneficiary with high amount: %.2f TL", 
                                  transaction.amount),
      blocked = false,
      metadata = {amount = transaction.amount, recipient_id = transaction.recipient_id}
    })
    
    -- Mark as recorded
    redis_adapter.set(redis, key, transaction.timestamp, 86400 * 90)
  end
  
  return violations
end

-- Rule 3.1.3-4: Split transfer pattern (potential structuring)
local function rule_1_3_4(conf, transaction, redis)
  local violations = {}
  
  if transaction.transaction_type ~= "transfer" then
    return violations
  end
  
  local is_structuring, reason = pattern.check_structuring_pattern(
    redis,
    transaction.user_id,
    transaction.amount,
    transaction.timestamp
  )
  
  if is_structuring then
    table.insert(violations, {
      rule = "3.1.3-4",
      score = 35,
      severity = "HIGH",
      description = string.format("Potential structuring detected: %s", reason),
      blocked = false,
      metadata = {reason = reason}
    })
  end
  
  return violations
end

-- Rule 3.1.3-5: Same-day roundtrip transfers
local function rule_1_3_5(conf, transaction, redis)
  local violations = {}
  
  if transaction.transaction_type ~= "transfer" or not transaction.recipient_id then
    return violations
  end
  
  local date = os.date("%Y-%m-%d", transaction.timestamp)
  
  -- Check if reverse transfer exists (recipient transferred to user)
  local reverse_key = string.format("transfer_pair:%s:%s:%s", 
                                   transaction.recipient_id, transaction.user_id, date)
  
  local reverse_exists, _ = redis_adapter.get(redis, reverse_key)
  
  if reverse_exists then
    table.insert(violations, {
      rule = "3.1.3-5",
      score = 30,
      severity = "HIGH",
      description = "Same-day roundtrip transfer detected",
      blocked = false,
      metadata = {
        user_id = transaction.user_id,
        recipient_id = transaction.recipient_id
      }
    })
  end
  
  -- Record this transfer
  local forward_key = string.format("transfer_pair:%s:%s:%s", 
                                   transaction.user_id, transaction.recipient_id, date)
  redis_adapter.set(redis, forward_key, transaction.amount, 86400 * 2)
  
  return violations
end

-- Rule 3.1.3-6: Bill payment to unusual biller
local function rule_1_3_6(conf, transaction, redis)
  local violations = {}
  
  if transaction.transaction_type ~= "bill_payment" or not transaction.biller_id then
    return violations
  end
  
  local key = string.format("user:%s:usual_billers", transaction.user_id)
  
  local is_usual, _ = redis_adapter.sismember(redis, key, transaction.biller_id)
  
  if not is_usual and transaction.amount > 5000 then
    table.insert(violations, {
      rule = "3.1.3-6",
      score = 20,
      severity = "MEDIUM",
      description = "Bill payment to new/unusual biller with high amount",
      blocked = false,
      metadata = {
        biller_id = transaction.biller_id,
        amount = transaction.amount
      }
    })
  end
  
  -- Add to usual billers
  redis_adapter.sadd(redis, key, transaction.biller_id)
  redis_adapter.expire(redis, key, 86400 * 90)
  
  return violations
end

-- Rule 3.1.3-7: Transfer immediately after deposit
local function rule_1_3_7(conf, transaction, redis)
  local violations = {}
  
  if transaction.transaction_type ~= "transfer" then
    return violations
  end

  if not transaction.account_id then
    return violations
  end

  -- Check if there was a recent deposit
  local deposit_key = string.format("account:%s:recent_deposits", transaction.account_id)
  local minute_ago = transaction.timestamp - 300  -- 5 minutes
  
  local deposits, _ = redis_adapter.zrangebyscore(redis, deposit_key, minute_ago, transaction.timestamp)
  deposits = deposits or {}

  if #deposits > 0 and transaction.amount > 5000 then
    table.insert(violations, {
      rule = "3.1.3-7",
      score = 25,
      severity = "HIGH",
      description = "Large transfer within 5 minutes of deposit",
      blocked = false,
      metadata = {
        deposit_count = #deposits,
        transfer_amount = transaction.amount
      }
    })
  end
  
  return violations
end

-- Rule 3.1.3-8: Transfer to high-risk country
local function rule_1_3_8(conf, transaction, redis)
  local violations = {}
  
  if transaction.transaction_type ~= "transfer" then
    return violations
  end
  
  -- Check if recipient is in high-risk country
  if transaction.recipient_country then
    local high_risk_countries = {"KP", "IR", "MM", "SY"}  -- FATF high-risk list (example)
    
    for _, country in ipairs(high_risk_countries) do
      if transaction.recipient_country == country then
        table.insert(violations, {
          rule = "3.1.3-8",
          score = 40,
          severity = "CRITICAL",
          description = string.format("Transfer to high-risk country: %s", country),
          blocked = false,
          metadata = {
            recipient_country = transaction.recipient_country,
            amount = transaction.amount
          }
        })
        break
      end
    end
  end
  
  return violations
end

-- Rule 3.1.3-9: Multiple transfers to same beneficiary in short time
local function rule_1_3_9(conf, transaction, redis)
  local violations = {}
  
  if transaction.transaction_type ~= "transfer" or not transaction.recipient_id then
    return violations
  end
  
  local key = string.format("user:%s:transfers_to:%s", 
                           transaction.user_id, transaction.recipient_id)
  
  local hour_ago = transaction.timestamp - 3600
  redis_adapter.zremrangebyscore(redis, key, 0, hour_ago)
  
  local count, _ = redis_adapter.zcard(redis, key)
  
  redis_adapter.zadd(redis, key, transaction.timestamp, 
                    string.format("txn_%.2f_%d", transaction.amount, transaction.timestamp))
  redis_adapter.expire(redis, key, 3600)
  
  if count and count >= 5 then  -- 5+ transfers to same beneficiary in 1 hour
    table.insert(violations, {
      rule = "3.1.3-9",
      score = 25,
      severity = "HIGH",
      description = string.format("%d transfers to same beneficiary in 1 hour", count + 1),
      blocked = false,
      metadata = {
        transfer_count = count + 1,
        recipient_id = transaction.recipient_id
      }
    })
  end
  
  return violations
end

-- Rule 3.1.3-10: Large transfer during non-business hours
local function rule_1_3_10(conf, transaction, redis)
  local violations = {}
  
  if transaction.transaction_type ~= "transfer" then
    return violations
  end
  
  local hour = transaction.transaction_hour
  local is_non_business = (hour < 8 or hour >= 22) or transaction.is_weekend
  
  if is_non_business and transaction.amount > 50000 then
    table.insert(violations, {
      rule = "3.1.3-10",
      score = 25,
      severity = "HIGH",
      description = string.format("Large transfer (%.2f TL) during non-business hours", transaction.amount),
      blocked = false,
      metadata = {
        amount = transaction.amount,
        hour = hour,
        is_weekend = transaction.is_weekend
      }
    })
  end
  
  return violations
end

-- Main check function for all transfer/bill payment rules
function _M.check(conf, transaction, redis)
  local all_violations = {}
  
  -- Execute all 10 rules
  local rules = {
    rule_1_3_1,   -- High-value transfer anomaly
    rule_1_3_2,   -- Rapid transfer frequency
    rule_1_3_3,   -- New beneficiary high amount
    rule_1_3_4,   -- Structuring pattern
    rule_1_3_5,   -- Roundtrip transfers
    rule_1_3_6,   -- Unusual biller
    rule_1_3_7,   -- Transfer after deposit
    rule_1_3_8,   -- High-risk country
    rule_1_3_9,   -- Multiple to same beneficiary
    rule_1_3_10   -- Non-business hours large transfer
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
