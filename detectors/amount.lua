-- Amount Analyzer for Fraud Guard
-- Transaction amount anomaly detection and analysis

local redis_adapter = require "kong.plugins.fraud-guard.storage.redis_adapter"

local _M = {}

-- Calculate user's typical transaction amount
function _M.get_typical_amount(redis, user_id)
  local key = string.format("user:%s:amount_stats", user_id)
  
  local stats, _ = redis_adapter.hgetall(redis, key)
  
  if not stats or not next(stats) then
    return {
      average = 0,
      max = 0,
      count = 0
    }
  end
  
  return {
    average = tonumber(stats.average) or 0,
    max = tonumber(stats.max) or 0,
    count = tonumber(stats.count) or 0
  }
end

-- Update user amount statistics
function _M.update_amount_stats(redis, user_id, amount)
  local key = string.format("user:%s:amount_stats", user_id)
  
  local stats = _M.get_typical_amount(redis, user_id)
  
  -- Update count
  local new_count = stats.count + 1
  
  -- Update average (running average)
  local new_average = ((stats.average * stats.count) + amount) / new_count
  
  -- Update max
  local new_max = math.max(stats.max, amount)
  
  -- Store updated stats
  redis_adapter.hset(redis, key, "average", new_average)
  redis_adapter.hset(redis, key, "max", new_max)
  redis_adapter.hset(redis, key, "count", new_count)
  redis_adapter.expire(redis, key, 86400 * 90)  -- 90 days
end

-- Check if amount is anomalous for user
function _M.check_amount_anomaly(redis, user_id, amount)
  local stats = _M.get_typical_amount(redis, user_id)
  
  -- Need at least 10 transactions for meaningful comparison
  if stats.count < 10 then
    -- Update stats
    _M.update_amount_stats(redis, user_id, amount)
    return false, "insufficient_history"
  end

  -- Guard: skip ratio checks when the baseline is zero or near-zero to avoid
  -- false positives where every positive amount would be "5× above average".
  if stats.average > 0 then
    -- Check if amount is significantly higher than average
    if amount > stats.average * 5 then
      _M.update_amount_stats(redis, user_id, amount)
      return true, string.format("5x_average: %.2f vs %.2f", amount, stats.average)
    end
  end

  -- Check if amount is new maximum (only when we have a meaningful max)
  if stats.max > 0 and amount > stats.max * 1.5 then
    _M.update_amount_stats(redis, user_id, amount)
    return true, string.format("new_maximum: %.2f vs %.2f", amount, stats.max)
  end
  
  -- Update stats
  _M.update_amount_stats(redis, user_id, amount)
  
  return false, "normal"
end

-- Check if amount is just below regulatory threshold (structuring)
function _M.check_threshold_avoidance(amount, thresholds)
  thresholds = thresholds or {10000, 15000, 50000}  -- Common reporting thresholds
  
  for _, threshold in ipairs(thresholds) do
    -- Check if amount is 70-95% of threshold
    if amount >= threshold * 0.7 and amount < threshold * 0.95 then
      return true, string.format("near_threshold: %.2f (~%.0f%% of %d)", 
                                 amount, (amount/threshold)*100, threshold)
    end
  end
  
  return false, nil
end

-- Check for incremental amount testing (card validation fraud)
function _M.check_incremental_testing(redis, user_id, amount, timestamp)
  local key = string.format("user:%s:amount_sequence", user_id)
  
  -- Get recent amounts (last hour)
  local hour_ago = timestamp - 3600
  redis_adapter.zremrangebyscore(redis, key, 0, hour_ago)
  
  local recent, _ = redis_adapter.zrangebyscore(redis, key, hour_ago, timestamp)
  recent = recent or {}

  -- Parse amounts
  local amounts = {}
  for _, entry in ipairs(recent) do
    local amt = tonumber(string.match(entry, "amt_([%d%.]+)_"))
    if amt then
      table.insert(amounts, amt)
    end
  end
  
  -- Add current amount
  redis_adapter.zadd(redis, key, timestamp, string.format("amt_%.2f_%d", amount, timestamp))
  redis_adapter.expire(redis, key, 3600)
  
  -- Check if amounts are incrementally increasing
  if #amounts >= 3 then
    local is_incremental = true
    local diffs = {}
    
    for i = 2, #amounts do
      local diff = amounts[i] - amounts[i-1]
      if diff <= 0 then
        is_incremental = false
        break
      end
      table.insert(diffs, diff)
    end
    
    -- Check if increments are consistent (card testing pattern)
    if is_incremental and #diffs >= 2 then
      local avg_diff = 0
      for _, d in ipairs(diffs) do
        avg_diff = avg_diff + d
      end
      avg_diff = avg_diff / #diffs
      
      -- Consistent small increments
      if avg_diff < 100 and avg_diff > 0 then
        return true, string.format("incremental_testing: avg_increment=%.2f", avg_diff)
      end
    end
  end
  
  return false, nil
end

-- Check for repeated exact amounts (suspicious pattern)
function _M.check_repeated_exact_amount(redis, user_id, amount, window_seconds, timestamp)
  local rounded_amount = math.floor(amount * 100) / 100
  local key = string.format("user:%s:amount_%.2f:occurrences", user_id, rounded_amount)
  
  local window_start = timestamp - window_seconds
  redis_adapter.zremrangebyscore(redis, key, 0, window_start)
  
  local count, _ = redis_adapter.zcard(redis, key)
  count = count or 0

  redis_adapter.zadd(redis, key, timestamp, string.format("txn_%d", timestamp))
  redis_adapter.expire(redis, key, window_seconds * 2)

  -- 3+ identical amounts in time window is suspicious
  if count >= 2 then
    return true, count + 1
  end

  return false, count + 1
end

-- Check for small test transactions followed by large one
function _M.check_test_then_large_pattern(redis, user_id, amount, timestamp)
  local key = string.format("user:%s:recent_amounts_pattern", user_id)
  
  -- Get amounts from last 6 hours
  local hours_ago = timestamp - (6 * 3600)
  redis_adapter.zremrangebyscore(redis, key, 0, hours_ago)
  
  local recent, _ = redis_adapter.zrangebyscore(redis, key, hours_ago, timestamp)
  recent = recent or {}

  -- Parse amounts
  local amounts = {}
  for _, entry in ipairs(recent) do
    local amt = tonumber(string.match(entry, "amt_([%d%.]+)_"))
    if amt then
      table.insert(amounts, amt)
    end
  end
  
  -- Add current
  redis_adapter.zadd(redis, key, timestamp, string.format("amt_%.2f_%d", amount, timestamp))
  redis_adapter.expire(redis, key, 6 * 3600)
  
  -- Check pattern: small amounts (<100) followed by large (>1000)
  if amount > 1000 and #amounts > 0 then
    local had_small = false
    for _, amt in ipairs(amounts) do
      if amt < 100 then
        had_small = true
        break
      end
    end
    
    if had_small then
      return true, "small_test_before_large"
    end
  end
  
  return false, nil
end

-- Check amount vs merchant category expectations
function _M.check_amount_category_mismatch(amount, merchant_category, transaction_type)
  -- Define expected ranges per category (simplified)
  local category_ranges = {
    grocery = {min = 10, max = 2000},
    restaurant = {min = 20, max = 1000},
    fuel = {min = 50, max = 1500},
    electronics = {min = 100, max = 50000},
    jewelry = {min = 500, max = 100000},
    epin = {min = 10, max = 5000}
  }
  
  if merchant_category and category_ranges[merchant_category] then
    local range = category_ranges[merchant_category]
    
    if amount > range.max * 2 then
      return true, string.format("exceeds_category_max: %.2f > %d", amount, range.max)
    end
  end
  
  return false, nil
end

-- Maximum number of daily-revenue entries read in a single baseline query.
-- Prevents unbounded Lua table growth for high-volume merchants.
local MAX_BASELINE_ENTRIES = 90  -- matches the 90-day retention window

-- Calculate merchant revenue baseline
function _M.get_merchant_baseline(redis, merchant_id, period_days)
  period_days = period_days or 30
  local key = string.format("merchant:%s:revenue_history", merchant_id)

  -- Get daily revenues for period, capped to MAX_BASELINE_ENTRIES.
  -- redis_adapter.zrangebyscore must accept an optional LIMIT clause; here we
  -- pass the cap via the standard redis LIMIT offset count syntax.
  local cutoff = os.time() - (period_days * 86400)
  local revenues, _ = redis_adapter.zrangebyscore(
    redis, key, cutoff, os.time(), "LIMIT", 0, MAX_BASELINE_ENTRIES
  )

  if not revenues or #revenues == 0 then
    return {
      daily_average = 0,
      daily_max = 0,
      count = 0
    }
  end

  local total = 0
  local max_daily = 0

  for _, entry in ipairs(revenues) do
    local revenue = tonumber(string.match(entry, "rev_([%d%.]+)_"))
    if revenue then
      total = total + revenue
      max_daily = math.max(max_daily, revenue)
    end
  end

  return {
    daily_average = #revenues > 0 and (total / #revenues) or 0,
    daily_max = max_daily,
    count = #revenues
  }
end

-- Update merchant daily revenue
function _M.update_merchant_revenue(redis, merchant_id, amount, timestamp)
  timestamp = timestamp or os.time()
  local date = os.date("%Y-%m-%d", timestamp)
  
  -- Update daily total
  local daily_key = string.format("merchant:%s:daily_revenue:%s", merchant_id, date)
  redis_adapter.hincrbyfloat(redis, daily_key, "total", amount)
  redis_adapter.hincrby(redis, daily_key, "count", 1)
  redis_adapter.expire(redis, daily_key, 86400 * 2)
  
  -- Update history (for baseline calculation)
  local history_key = string.format("merchant:%s:revenue_history", merchant_id)
  local daily_total, _ = redis_adapter.hget(redis, daily_key, "total")
  daily_total = tonumber(daily_total) or amount
  
  redis_adapter.zadd(redis, history_key, timestamp, 
                    string.format("rev_%.2f_%s", daily_total, date))
  redis_adapter.expire(redis, history_key, 86400 * 90)  -- 90 days
end

-- Check merchant revenue anomaly (Rule 3.1.2-1)
function _M.check_merchant_revenue_anomaly(redis, merchant_id, amount, sector_average, timestamp)
  -- Update revenue
  _M.update_merchant_revenue(redis, merchant_id, amount, timestamp)
  
  local date = os.date("%Y-%m-%d", timestamp or os.time())
  local daily_key = string.format("merchant:%s:daily_revenue:%s", merchant_id, date)
  
  local daily_data, _ = redis_adapter.hgetall(redis, daily_key)
  -- hgetall returns nil when key doesn't exist or Redis errors; guard before field access
  local daily_total = (daily_data and tonumber(daily_data.total)) or 0
  
  local anomalies = {}
  
  -- Check vs sector average
  if sector_average and daily_total > sector_average then
    table.insert(anomalies, {
      type = "exceeds_sector_average",
      daily_revenue = daily_total,
      sector_average = sector_average,
      ratio = daily_total / sector_average
    })
  end
  
  -- Check vs historical baseline
  local baseline = _M.get_merchant_baseline(redis, merchant_id, 30)
  if baseline.count >= 10 and baseline.daily_average and baseline.daily_average > 0
     and daily_total > baseline.daily_average * 4 then
    table.insert(anomalies, {
      type = "4x_historical_average",
      daily_revenue = daily_total,
      historical_avg = baseline.daily_average,
      ratio = daily_total / baseline.daily_average
    })
  end
  
  return anomalies
end

-- Comprehensive amount analysis
function _M.analyze_amount_risk(redis, transaction, conf)
  local amount_risks = {}
  
  if not transaction.amount or transaction.amount <= 0 then
    return amount_risks
  end
  
  -- Check amount anomaly for user
  local is_anomalous, anomaly_reason = _M.check_amount_anomaly(
    redis,
    transaction.user_id,
    transaction.amount
  )
  
  if is_anomalous and anomaly_reason ~= "insufficient_history" then
    table.insert(amount_risks, {
      type = "amount_anomaly",
      details = anomaly_reason,
      severity = "medium"
    })
  end
  
  -- Check threshold avoidance
  local is_avoiding, avoid_reason = _M.check_threshold_avoidance(transaction.amount)
  if is_avoiding then
    table.insert(amount_risks, {
      type = "threshold_avoidance",
      details = avoid_reason,
      severity = "high"
    })
  end
  
  -- Check incremental testing
  local is_testing, test_reason = _M.check_incremental_testing(
    redis,
    transaction.user_id,
    transaction.amount,
    transaction.timestamp
  )
  
  if is_testing then
    table.insert(amount_risks, {
      type = "incremental_testing",
      details = test_reason,
      severity = "high"
    })
  end
  
  -- Check repeated exact amounts
  local is_repeated, repeat_count = _M.check_repeated_exact_amount(
    redis,
    transaction.user_id,
    transaction.amount,
    3600,  -- 1 hour window
    transaction.timestamp
  )
  
  if is_repeated then
    table.insert(amount_risks, {
      type = "repeated_exact_amount",
      count = repeat_count,
      severity = "medium"
    })
  end
  
  -- Check test-then-large pattern
  local has_pattern, pattern_type = _M.check_test_then_large_pattern(
    redis,
    transaction.user_id,
    transaction.amount,
    transaction.timestamp
  )
  
  if has_pattern then
    table.insert(amount_risks, {
      type = "test_then_large_pattern",
      severity = "high"
    })
  end
  
  return amount_risks
end

return _M
