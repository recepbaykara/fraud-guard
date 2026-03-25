-- POS/Virtual POS Rules (Section 3.1.2 - 25 rules)
-- Payment Instrument Acceptance Services

local velocity = require "kong.plugins.fraud-guard.detectors.velocity"
local pattern = require "kong.plugins.fraud-guard.detectors.pattern"
local geo = require "kong.plugins.fraud-guard.detectors.geo"
local amount = require "kong.plugins.fraud-guard.detectors.amount"
local redis_adapter = require "kong.plugins.fraud-guard.storage.redis_adapter"

local _M = {}

-- Rule 3.1.2-1: Merchant revenue anomalies (3 conditions)
local function rule_1_2_1(conf, transaction, redis)
  local violations = {}
  
  if not transaction.merchant_id then
    return violations
  end
  
  -- Get sector average for merchant category
  local sector_avg = conf.sector_averages and conf.sector_averages.default or 50000
  if transaction.merchant_category and conf.sector_averages then
    sector_avg = conf.sector_averages[transaction.merchant_category] or sector_avg
  end
  
  -- Check revenue anomalies
  local anomalies = amount.check_merchant_revenue_anomaly(
    redis,
    transaction.merchant_id,
    transaction.amount,
    sector_avg,
    transaction.timestamp
  )
  
  for _, anomaly in ipairs(anomalies) do
    local score = 30
    if anomaly.type == "4x_historical_average" then
      score = 35
    end
    
    table.insert(violations, {
      rule = "3.1.2-1",
      score = score,
      severity = "HIGH",
      description = string.format("Merchant revenue anomaly: %s", anomaly.type),
      blocked = false,
      metadata = anomaly
    })
  end
  
  return violations
end

-- Rule 3.1.2-2: High refund ratio
local function rule_1_2_2(conf, transaction, redis)
  local violations = {}
  
  if not transaction.merchant_id or transaction.transaction_type ~= "refund" then
    return violations
  end
  
  local date = os.date("%Y-%m-%d", transaction.timestamp)
  local sales_key = string.format("merchant:%s:daily_sales:%s", transaction.merchant_id, date)
  local refund_key = string.format("merchant:%s:daily_refunds:%s", transaction.merchant_id, date)
  
  -- Increment refund
  redis_adapter.hincrbyfloat(redis, refund_key, "total", transaction.amount)
  redis_adapter.hincrby(redis, refund_key, "count", 1)
  redis_adapter.expire(redis, refund_key, 86400 * 2)
  
  -- Get sales and refund totals
  local sales_total, _ = redis_adapter.hget(redis, sales_key, "total")
  local refund_total, _ = redis_adapter.hget(redis, refund_key, "total")
  
  sales_total = tonumber(sales_total) or 0
  refund_total = tonumber(refund_total) or 0
  
  if sales_total > 0 then
    local refund_ratio = refund_total / sales_total
    
    if refund_ratio > 0.3 then  -- 30% refund rate is suspicious
      table.insert(violations, {
        rule = "3.1.2-2",
        score = 30,
        severity = "HIGH",
        description = string.format("High refund ratio: %.1f%%", refund_ratio * 100),
        blocked = false,
        metadata = {
          refund_ratio = refund_ratio,
          sales_total = sales_total,
          refund_total = refund_total
        }
      })
    end
  end
  
  return violations
end

-- Rule 3.1.2-3: Unusual transaction time for merchant
local function rule_1_2_3(conf, transaction, redis)
  local violations = {}
  
  if not transaction.merchant_id then
    return violations
  end
  
  local hour = transaction.transaction_hour
  local key = string.format("merchant:%s:hourly_pattern", transaction.merchant_id)
  
  local hour_count, _ = redis_adapter.hget(redis, key, tostring(hour))
  hour_count = tonumber(hour_count) or 0
  
  -- Increment
  redis_adapter.hincrby(redis, key, tostring(hour), 1)
  redis_adapter.expire(redis, key, 86400 * 30)
  
  -- If first time at this hour and it's late night
  if hour_count == 0 and (hour >= 23 or hour <= 5) then
    table.insert(violations, {
      rule = "3.1.2-3",
      score = 20,
      severity = "MEDIUM",
      description = string.format("First transaction for merchant at unusual hour: %02d:00", hour),
      blocked = false,
      metadata = {hour = hour, merchant_id = transaction.merchant_id}
    })
  end
  
  return violations
end

-- Rule 3.1.2-4: Geographic inconsistency (merchant location vs transaction origin)
local function rule_1_2_4(conf, transaction, redis)
  local violations = {}
  
  if not transaction.merchant_id or not transaction.ip_address then
    return violations
  end
  
  -- Get merchant's usual countries
  local key = string.format("merchant:%s:usual_countries", transaction.merchant_id)
  local countries, _ = redis_adapter.smembers(redis, key)
  
  local txn_country = geo.get_country_code(transaction.ip_address)

  -- Only record known countries; sadd with nil would corrupt the set
  if txn_country then
    redis_adapter.sadd(redis, key, txn_country)
  end
  redis_adapter.expire(redis, key, 86400 * 90)
  
  -- If merchant has transactions from 5+ different countries
  if countries and #countries >= 5 and transaction.amount > 1000 then
    table.insert(violations, {
      rule = "3.1.2-4",
      score = 25,
      severity = "HIGH",
      description = string.format("Merchant transactions from %d different countries", #countries + 1),
      blocked = false,
      metadata = {country_count = #countries + 1}
    })
  end
  
  return violations
end

-- Rule 3.1.2-5: Card testing pattern (multiple small transactions)
local function rule_1_2_5(conf, transaction, redis)
  local violations = {}
  
  if transaction.amount > 100 then
    return violations  -- Only flag small amounts
  end
  
  local key = string.format("merchant:%s:small_txns", transaction.merchant_id)
  local hour_ago = transaction.timestamp - 3600
  
  redis_adapter.zremrangebyscore(redis, key, 0, hour_ago)
  local count, _ = redis_adapter.zcard(redis, key)
  
  redis_adapter.zadd(redis, key, transaction.timestamp, 
                    string.format("txn_%.2f_%d", transaction.amount, transaction.timestamp))
  redis_adapter.expire(redis, key, 3600)
  
  if count and count >= 10 then  -- 10+ small transactions in 1 hour
    table.insert(violations, {
      rule = "3.1.2-5",
      score = 35,
      severity = "HIGH",
      description = string.format("Card testing pattern: %d small transactions in 1 hour", count + 1),
      blocked = false,
      metadata = {small_txn_count = count + 1, merchant_id = transaction.merchant_id}
    })
  end
  
  return violations
end

-- Rule 3.1.2-6: Transaction velocity for specific merchant
local function rule_1_2_6(conf, transaction, redis)
  local violations = {}
  
  if not transaction.merchant_id then
    return violations
  end
  
  local hour_key = string.format("merchant:%s:hourly_txn_count:%d", 
                                transaction.merchant_id, 
                                transaction.timestamp - (transaction.timestamp % 3600))
  
  local hour_count, _ = redis_adapter.incr(redis, hour_key)
  redis_adapter.expire(redis, hour_key, 7200)
  
  -- Check against merchant's typical hourly volume
  local avg_key = string.format("merchant:%s:avg_hourly", transaction.merchant_id)
  local avg_hourly, _ = redis_adapter.get(redis, avg_key)
  avg_hourly = tonumber(avg_hourly) or 0
  
  if avg_hourly > 0 and hour_count > avg_hourly * 3 then
    table.insert(violations, {
      rule = "3.1.2-6",
      score = 25,
      severity = "HIGH",
      description = string.format("Merchant transaction velocity spike: %d vs avg %.1f", 
                                  hour_count, avg_hourly),
      blocked = false,
      metadata = {current = hour_count, average = avg_hourly}
    })
  end
  
  return violations
end

-- Rule 3.1.2-7: Unusual merchant category for user
local function rule_1_2_7(conf, transaction, redis)
  local violations = {}
  
  if not transaction.merchant_category then
    return violations
  end
  
  local is_unusual, reason = pattern.check_merchant_category_pattern(
    redis,
    transaction.user_id,
    transaction.merchant_category,
    transaction.amount
  )
  
  if is_unusual then
    table.insert(violations, {
      rule = "3.1.2-7",
      score = 15,
      severity = "MEDIUM",
      description = string.format("Unusual merchant category: %s", reason),
      blocked = false,
      metadata = {category = transaction.merchant_category, reason = reason}
    })
  end
  
  return violations
end

-- Rule 3.1.2-8: Multiple failed transactions before success
local function rule_1_2_8(conf, transaction, redis)
  local violations = {}
  
  if not transaction.card_bin then
    return violations
  end
  
  local key = string.format("card:%s:failed_attempts", transaction.card_bin)
  local failed_count, _ = redis_adapter.get(redis, key)
  failed_count = tonumber(failed_count) or 0
  
  -- If transaction is failed, increment
  if transaction.status == "failed" then
    redis_adapter.incr(redis, key)
    redis_adapter.expire(redis, key, 3600)
    return violations
  end
  
  -- If successful but had previous failures
  if failed_count >= 3 then
    table.insert(violations, {
      rule = "3.1.2-8",
      score = 30,
      severity = "HIGH",
      description = string.format("Success after %d failed attempts", failed_count),
      blocked = false,
      metadata = {failed_attempts = failed_count}
    })
    
    -- Reset counter
    redis_adapter.del(redis, key)
  end
  
  return violations
end

-- Rule 3.1.2-9: High-risk merchant category
local function rule_1_2_9(conf, transaction, redis)
  local violations = {}
  
  local high_risk_categories = {"gambling", "crypto", "dating", "adult", "epin"}
  
  if transaction.merchant_category then
    for _, risk_cat in ipairs(high_risk_categories) do
      if string.find(string.lower(transaction.merchant_category), risk_cat) then
        table.insert(violations, {
          rule = "3.1.2-9",
          score = 20,
          severity = "MEDIUM",
          description = string.format("High-risk merchant category: %s", transaction.merchant_category),
          blocked = false,
          metadata = {category = transaction.merchant_category}
        })
        break
      end
    end
  end
  
  return violations
end

-- Rule 3.1.2-10: Cross-border transaction
local function rule_1_2_10(conf, transaction, redis)
  local violations = {}
  
  -- Check if merchant country differs from transaction origin
  if transaction.merchant_country and transaction.ip_address then
    local txn_country = geo.get_country_code(transaction.ip_address)
    
    if transaction.merchant_country ~= txn_country and transaction.amount > 2000 then
      table.insert(violations, {
        rule = "3.1.2-10",
        score = 15,
        severity = "MEDIUM",
        description = string.format("Cross-border transaction: %s -> %s", 
                                    txn_country, transaction.merchant_country),
        blocked = false,
        metadata = {
          origin_country = txn_country,
          merchant_country = transaction.merchant_country
        }
      })
    end
  end
  
  return violations
end

-- Rule 3.1.2-11: Rapid merchant switching
local function rule_1_2_11(conf, transaction, redis)
  local violations = {}
  
  if not transaction.merchant_id then
    return violations
  end
  
  local key = string.format("user:%s:recent_merchants", transaction.user_id)
  local hour_ago = transaction.timestamp - 3600
  
  redis_adapter.zremrangebyscore(redis, key, 0, hour_ago)
  
  -- Count unique merchants
  local merchants, _ = redis_adapter.zrangebyscore(redis, key, hour_ago, transaction.timestamp)
  merchants = merchants or {}
  local unique_merchants = {}
  for _, entry in ipairs(merchants) do
    local merchant_id = string.match(entry, "merchant_([^_]+)_")
    if merchant_id then
      unique_merchants[merchant_id] = true
    end
  end
  
  redis_adapter.zadd(redis, key, transaction.timestamp, 
                    string.format("merchant_%s_%d", transaction.merchant_id, transaction.timestamp))
  redis_adapter.expire(redis, key, 3600)
  
  local merchant_count = 0
  for _ in pairs(unique_merchants) do
    merchant_count = merchant_count + 1
  end
  
  if merchant_count >= 10 then
    table.insert(violations, {
      rule = "3.1.2-11",
      score = 25,
      severity = "HIGH",
      description = string.format("Rapid merchant switching: %d merchants in 1 hour", merchant_count + 1),
      blocked = false,
      metadata = {merchant_count = merchant_count + 1}
    })
  end
  
  return violations
end

-- Rule 3.1.2-12: Amount pattern mismatch for merchant
local function rule_1_2_12(conf, transaction, redis)
  local violations = {}
  
  if not transaction.merchant_id then
    return violations
  end
  
  local is_mismatch, reason = amount.check_amount_category_mismatch(
    transaction.amount,
    transaction.merchant_category,
    transaction.transaction_type
  )
  
  if is_mismatch then
    table.insert(violations, {
      rule = "3.1.2-12",
      score = 20,
      severity = "MEDIUM",
      description = string.format("Amount-category mismatch: %s", reason),
      blocked = false,
      metadata = {reason = reason, category = transaction.merchant_category}
    })
  end
  
  return violations
end

-- Rule 3.1.2-13: New merchant high transaction
local function rule_1_2_13(conf, transaction, redis)
  local violations = {}
  
  if not transaction.merchant_id then
    return violations
  end
  
  local key = string.format("merchant:%s:first_seen", transaction.merchant_id)
  local first_seen, _ = redis_adapter.get(redis, key)
  
  if not first_seen then
    -- First transaction for this merchant
    redis_adapter.set(redis, key, transaction.timestamp, 86400 * 90)
    
    if transaction.amount > 10000 then
      table.insert(violations, {
        rule = "3.1.2-13",
        score = 25,
        severity = "HIGH",
        description = string.format("New merchant with large first transaction: %.2f TL", transaction.amount),
        blocked = false,
        metadata = {amount = transaction.amount, merchant_id = transaction.merchant_id}
      })
    end
  end
  
  return violations
end

-- Rule 3.1.2-14: Weekend POS anomaly
local function rule_1_2_14(conf, transaction, redis)
  local violations = {}
  
  if transaction.is_weekend and transaction.transaction_type == "pos" then
    local key = string.format("merchant:%s:weekend_avg", transaction.merchant_id)
    local weekend_avg, _ = redis_adapter.get(redis, key)
    weekend_avg = tonumber(weekend_avg) or 0
    
    if weekend_avg > 0 and transaction.amount > weekend_avg * 3 then
      table.insert(violations, {
        rule = "3.1.2-14",
        score = 20,
        severity = "MEDIUM",
        description = string.format("Weekend POS amount anomaly: %.2f vs avg %.2f", 
                                    transaction.amount, weekend_avg),
        blocked = false,
        metadata = {amount = transaction.amount, weekend_avg = weekend_avg}
      })
    end
  end
  
  return violations
end

-- Rule 3.1.2-15: E-PIN merchant specific rules (3+ transactions from same card in 1 hour OR total > 15,000 TL)
local function rule_1_2_15(conf, transaction, redis)
  local violations = {}
  
  -- Check if merchant is e-pin type
  if not transaction.merchant_category or 
     not string.find(string.lower(transaction.merchant_category), "epin") then
    return violations
  end
  
  if not transaction.card_bin then
    return violations
  end
  
  local epin_data = velocity.check_epin_card_usage(
    redis,
    transaction.card_bin,
    transaction.merchant_id,
    transaction.amount,
    transaction.timestamp
  )
  
  local txn_threshold = conf.thresholds.epin_card_txn_hour_limit or 3
  local amount_threshold = conf.thresholds.epin_card_amount_hour_limit or 15000
  
  if epin_data.hourly_transaction_count >= txn_threshold then
    table.insert(violations, {
      rule = "3.1.2-15",
      score = 45,  -- CRITICAL
      severity = "CRITICAL",
      description = string.format("E-PIN: %d transactions from same card in 1 hour (threshold: %d)", 
                                  epin_data.hourly_transaction_count, txn_threshold),
      blocked = true,
      metadata = {
        txn_count = epin_data.hourly_transaction_count,
        card_bin = transaction.card_bin,
        threshold = txn_threshold
      }
    })
  end
  
  if epin_data.hourly_total_amount > amount_threshold then
    table.insert(violations, {
      rule = "3.1.2-15",
      score = 45,  -- CRITICAL
      severity = "CRITICAL",
      description = string.format("E-PIN: Card hourly total %.2f TL exceeds limit %d TL", 
                                  epin_data.hourly_total_amount, amount_threshold),
      blocked = true,
      metadata = {
        total_amount = epin_data.hourly_total_amount,
        threshold = amount_threshold,
        card_bin = transaction.card_bin
      }
    })
  end
  
  return violations
end

-- Rules 3.1.2-16 through 3.1.2-25: Additional POS-specific checks
local function rule_1_2_16_to_25(conf, transaction, redis)
  local violations = {}
  
  -- Rule 3.1.2-16: Multiple cards from same IP
  if transaction.ip_address and transaction.card_bin then
    local key = string.format("ip:%s:cards_used:%s", transaction.ip_address, os.date("%Y-%m-%d"))
    
    redis_adapter.sadd(redis, key, transaction.card_bin)
    redis_adapter.expire(redis, key, 86400 * 2)
    
    local card_count, _ = redis_adapter.scard(redis, key)
    
    if card_count >= 5 then
      table.insert(violations, {
        rule = "3.1.2-16",
        score = 35,
        severity = "HIGH",
        description = string.format("%d different cards used from IP %s today", 
                                    card_count, transaction.ip_address),
        blocked = false,
        metadata = {card_count = card_count, ip = transaction.ip_address}
      })
    end
  end
  
  -- Rule 3.1.2-17: Dormant card suddenly active
  if transaction.card_bin then
    local key = string.format("card:%s:last_used", transaction.card_bin)
    local last_used, _ = redis_adapter.get(redis, key)
    
    if last_used then
      local days_dormant = (transaction.timestamp - tonumber(last_used)) / 86400
      
      if days_dormant > 90 and transaction.amount > 5000 then
        table.insert(violations, {
          rule = "3.1.2-17",
          score = 25,
          severity = "HIGH",
          description = string.format("Dormant card (%.0f days) with large transaction", days_dormant),
          blocked = false,
          metadata = {days_dormant = math.floor(days_dormant), amount = transaction.amount}
        })
      end
    end
    
    redis_adapter.set(redis, key, transaction.timestamp, 86400 * 180)
  end
  
  -- Rule 3.1.2-18: High-value transaction at low-average merchant
  if transaction.merchant_id and transaction.amount > 10000 then
    local avg_key = string.format("merchant:%s:avg_txn_amount", transaction.merchant_id)
    local merchant_avg, _ = redis_adapter.get(redis, avg_key)
    merchant_avg = tonumber(merchant_avg) or 0
    
    if merchant_avg > 0 and merchant_avg < 500 and transaction.amount > 10000 then
      table.insert(violations, {
        rule = "3.1.2-18",
        score = 30,
        severity = "HIGH",
        description = string.format("High-value txn at low-avg merchant: %.2f vs avg %.2f", 
                                    transaction.amount, merchant_avg),
        blocked = false,
        metadata = {amount = transaction.amount, merchant_avg = merchant_avg}
      })
    end
  end
  
  -- Rule 3.1.2-19: Suspicious refund pattern
  if transaction.transaction_type == "refund" then
    local refund_key = string.format("merchant:%s:refund_pattern", transaction.merchant_id)
    local hour_ago = transaction.timestamp - 3600
    
    redis_adapter.zremrangebyscore(redis, refund_key, 0, hour_ago)
    local refund_count, _ = redis_adapter.zcard(redis, refund_key)
    
    redis_adapter.zadd(redis, refund_key, transaction.timestamp, 
                      string.format("ref_%.2f_%d", transaction.amount, transaction.timestamp))
    redis_adapter.expire(redis, refund_key, 3600)
    
    if refund_count >= 5 then
      table.insert(violations, {
        rule = "3.1.2-19",
        score = 25,
        severity = "HIGH",
        description = string.format("%d refunds in 1 hour", refund_count + 1),
        blocked = false,
        metadata = {refund_count = refund_count + 1}
      })
    end
  end
  
  -- Rule 3.1.2-20: Virtual POS from blacklisted IP
  if transaction.ip_address and transaction.transaction_type == "virtual_pos" then
    if geo.is_blacklisted_ip(redis, transaction.ip_address) then
      table.insert(violations, {
        rule = "3.1.2-20",
        score = 50,
        severity = "CRITICAL",
        description = "Virtual POS from blacklisted IP",
        blocked = true,
        metadata = {ip = transaction.ip_address}
      })
    end
  end
  
  return violations
end

-- Main check function for all POS rules
function _M.check(conf, transaction, redis)
  local all_violations = {}
  
  -- Execute all 25 rules (individual rules 1-15, grouped rules 16-25)
  local rule_functions = {
    rule_1_2_1,   -- Merchant revenue anomaly
    rule_1_2_2,   -- High refund ratio
    rule_1_2_3,   -- Unusual merchant hour
    rule_1_2_4,   -- Geographic inconsistency
    rule_1_2_5,   -- Card testing
    rule_1_2_6,   -- Merchant velocity spike
    rule_1_2_7,   -- Unusual merchant category
    rule_1_2_8,   -- Multiple failed attempts
    rule_1_2_9,   -- High-risk category
    rule_1_2_10,  -- Cross-border transaction
    rule_1_2_11,  -- Rapid merchant switching
    rule_1_2_12,  -- Amount-category mismatch
    rule_1_2_13,  -- New merchant high value
    rule_1_2_14,  -- Weekend POS anomaly
    rule_1_2_15,  -- E-PIN specific rules (CRITICAL)
    rule_1_2_16_to_25  -- Additional POS checks (rules 16-25)
  }
  
  for _, rule_func in ipairs(rule_functions) do
    local violations = rule_func(conf, transaction, redis)
    for _, v in ipairs(violations) do
      table.insert(all_violations, v)
    end
  end
  
  return all_violations
end

return _M
