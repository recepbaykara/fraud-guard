-- Pattern Detector for Fraud Guard
-- Detects behavioral anomalies and suspicious patterns

local redis_adapter = require "kong.plugins.fraud-guard.storage.redis_adapter"

local _M = {}

-- Check for suspicious keywords in transaction description (Rule 3.1.1-15)
function _M.check_suspicious_keywords(description, keywords_list)
  if not description or description == "" then
    return false, nil
  end
  
  local description_lower = string.lower(description)
  
  for _, keyword in ipairs(keywords_list) do
    local keyword_lower = string.lower(keyword)
    if string.find(description_lower, keyword_lower, 1, true) then
      return true, keyword
    end
  end
  
  return false, nil
end

-- Detect unusual transaction times (late night/early morning)
function _M.check_unusual_hours(transaction_hour, user_id, redis)
  -- Hours 22:00 - 06:00 are considered unusual
  local is_unusual = (transaction_hour >= 22 or transaction_hour <= 6)
  
  if not is_unusual then
    return false, 0
  end
  
  -- Check if user typically transacts at this hour
  local key = string.format("user:%s:hourly_pattern", user_id)
  local hour_count, _ = redis_adapter.hget(redis, key, tostring(transaction_hour))
  hour_count = tonumber(hour_count) or 0
  
  -- Increment count for this hour
  redis_adapter.hincrby(redis, key, tostring(transaction_hour), 1)
  redis_adapter.expire(redis, key, 86400 * 30)  -- 30 days
  
  -- If first time in unusual hour, flag it
  return hour_count < 3, hour_count + 1
end

-- Check weekend transaction pattern
function _M.check_weekend_pattern(is_weekend, transaction_type, user_id, redis)
  if not is_weekend then
    return false, nil
  end
  
  -- Different transaction types have different weekend patterns
  local key = string.format("user:%s:weekend_pattern:%s", user_id, transaction_type)
  local weekend_count, _ = redis_adapter.get(redis, key)
  weekend_count = tonumber(weekend_count) or 0
  
  redis_adapter.incr(redis, key)
  redis_adapter.expire(redis, key, 86400 * 30)
  
  -- Transfers on weekends can be suspicious for business accounts
  if transaction_type == "transfer" and weekend_count < 2 then
    return true, "unusual_weekend_transfer"
  end
  
  return false, nil
end

-- Detect multiple accounts from same IP (Rule 3.1.1-7)
function _M.check_accounts_per_ip(redis, ip_address, account_id, current_timestamp)
  local date = os.date("%Y-%m-%d", current_timestamp or os.time())
  local key = string.format("ip:%s:accounts:%s", ip_address, date)
  
  -- Get current count
  local count, _ = redis_adapter.scard(redis, key)
  
  -- sismember returns true when account is ALREADY in the set (i.e. not a new account)
  local already_exists, _ = redis_adapter.sismember(redis, key, account_id)

  if not already_exists then
    redis_adapter.sadd(redis, key, account_id)
    redis_adapter.expire(redis, key, 86400 * 2)
    count = count + 1
  end

  -- Return (unique_account_count, is_new_account) — callers expect second value as "is new"
  return count, not already_exists
end

-- Detect round amount patterns (e.g., 1000, 5000 - common in fraud)
function _M.check_round_amounts(amount)
  -- Check if amount is a round number
  if amount % 1000 == 0 or amount % 500 == 0 or amount % 100 == 0 then
    return true, amount
  end
  return false, 0
end

-- Check for sequential transaction pattern
function _M.check_sequential_pattern(redis, user_id, amount, timestamp)
  local key = string.format("user:%s:recent_amounts", user_id)
  
  -- Get last 5 transaction amounts
  local recent, _ = redis_adapter.zrangebyscore(redis, key, timestamp - 3600, timestamp)
  recent = recent or {}

  if #recent >= 3 then
    -- Check if amounts are increasing sequentially (card testing pattern)
    -- Format stored: "amt_%.2f_%d" — match amount between "amt_" and "_<timestamp>"
    local amounts = {}
    for _, amount_str in ipairs(recent) do
      local amt = tonumber(string.match(amount_str, "^amt_([%d%.]+)_"))
      if amt then
        table.insert(amounts, amt)
      end
    end
    
    if #amounts >= 3 then
      local is_sequential = true
      for i = 2, #amounts do
        if amounts[i] <= amounts[i-1] then
          is_sequential = false
          break
        end
      end
      
      if is_sequential then
        return true, "sequential_increasing_amounts"
      end
    end
  end
  
  -- Add current transaction
  local member = string.format("amt_%.2f_%d", amount, timestamp)
  redis_adapter.zadd(redis, key, timestamp, member)
  redis_adapter.expire(redis, key, 3600)
  
  return false, nil
end

-- Detect merchant category mismatch
function _M.check_merchant_category_pattern(redis, user_id, merchant_category, amount)
  local key = string.format("user:%s:merchant_categories", user_id)
  
  -- Get user's typical merchant categories
  local cat_count, _ = redis_adapter.hget(redis, key, merchant_category)
  cat_count = tonumber(cat_count) or 0
  
  -- Increment
  redis_adapter.hincrby(redis, key, merchant_category, 1)
  redis_adapter.expire(redis, key, 86400 * 30)
  
  -- If first time in this category with high amount, flag it
  if cat_count == 0 and amount > 5000 then
    return true, "new_merchant_category_high_amount"
  end
  
  return false, nil
end

-- Check for split transaction pattern (structuring)
function _M.check_structuring_pattern(redis, user_id, amount, timestamp)
  -- Structuring: multiple transactions just below reporting threshold
  local threshold = 9000  -- Common structuring threshold
  
  if amount >= threshold * 0.7 and amount < threshold then
    -- Check for similar transactions in last hour
    local key = string.format("user:%s:near_threshold_txns", user_id)
    local hour_ago = timestamp - 3600
    
    redis_adapter.zremrangebyscore(redis, key, 0, hour_ago)
    local count, _ = redis_adapter.zcard(redis, key)
    
    redis_adapter.zadd(redis, key, timestamp, string.format("%.2f_%d", amount, timestamp))
    redis_adapter.expire(redis, key, 3600)
    
    -- 3+ transactions near threshold in 1 hour is suspicious
    if count >= 2 then
      return true, "potential_structuring"
    end
  end
  
  return false, nil
end

-- Detect location change pattern (rapid geo changes)
function _M.check_rapid_location_change(redis, user_id, current_ip, timestamp)
  local key = string.format("user:%s:recent_ips", user_id)
  
  -- Get IPs from last hour
  local hour_ago = timestamp - 3600
  redis_adapter.zremrangebyscore(redis, key, 0, hour_ago)
  
  local recent_ips, _ = redis_adapter.zrangebyscore(redis, key, hour_ago, timestamp)
  recent_ips = recent_ips or {}

  -- Count unique IPs
  local unique_ips = {}
  for _, ip_entry in ipairs(recent_ips) do
    local ip = string.match(ip_entry, "ip_([^_]+)_")
    if ip then
      unique_ips[ip] = true
    end
  end
  
  -- Add current IP
  redis_adapter.zadd(redis, key, timestamp, string.format("ip_%s_%d", current_ip, timestamp))
  redis_adapter.expire(redis, key, 3600)
  
  local unique_count = 0
  for _ in pairs(unique_ips) do
    unique_count = unique_count + 1
  end
  
  -- 3+ different IPs in 1 hour is suspicious
  if unique_count >= 3 then
    return true, unique_count + 1
  end
  
  return false, unique_count + 1
end

-- Check device switching pattern
function _M.check_device_switching(redis, user_id, device_id, timestamp)
  if not device_id then
    return false, 0
  end
  
  local key = string.format("user:%s:recent_devices", user_id)
  local day_ago = timestamp - 86400
  
  redis_adapter.zremrangebyscore(redis, key, 0, day_ago)
  local device_count, _ = redis_adapter.zcard(redis, key)
  
  -- Check if this is a new device
  local devices, _ = redis_adapter.zrangebyscore(redis, key, day_ago, timestamp)
  devices = devices or {}
  local is_new_device = true
  
  for _, dev_entry in ipairs(devices) do
    if string.find(dev_entry, device_id, 1, true) then
      is_new_device = false
      break
    end
  end
  
  redis_adapter.zadd(redis, key, timestamp, string.format("dev_%s_%d", device_id, timestamp))
  redis_adapter.expire(redis, key, 86400)
  
  -- Using 4+ different devices in 24 hours is suspicious
  if is_new_device then
    device_count = device_count + 1
  end
  
  if device_count >= 4 then
    return true, device_count
  end
  
  return false, device_count
end

-- Check for account age vs transaction pattern mismatch
function _M.check_account_behavior_mismatch(account_age_days, amount, transaction_type)
  -- Very new accounts with large transactions
  if account_age_days < 7 then
    if amount > 10000 then
      return true, "new_account_large_transaction"
    end
    
    if transaction_type == "transfer" and amount > 5000 then
      return true, "new_account_large_transfer"
    end
  end
  
  return false, nil
end

-- Detect velocity pattern change (sudden increase in activity)
function _M.check_velocity_change(redis, user_id, timestamp)
  -- Get transaction counts for last 7 days
  local counts = {}
  
  for i = 1, 7 do
    local date = os.date("%Y-%m-%d", timestamp - (i * 86400))
    local key = string.format("user:%s:daily_txns:%s", user_id, date)
    local count, _ = redis_adapter.zcard(redis, key)
    table.insert(counts, count)
  end
  
  -- Calculate average of previous 6 days
  local sum = 0
  for i = 2, #counts do
    sum = sum + counts[i]
  end
  local avg = sum / math.max(#counts - 1, 1)
  
  -- Check if today is significantly higher
  local today_count = counts[1] or 0
  if avg > 0 and today_count > avg * 3 then
    return true, string.format("3x_daily_average: %d vs %.1f", today_count, avg)
  end
  
  return false, nil
end

-- Comprehensive pattern analysis
function _M.analyze_patterns(redis, transaction, conf)
  local patterns_detected = {}
  
  -- Suspicious keywords
  if conf.suspicious_keywords and conf.rule_toggles.enable_keyword_detection then
    local has_keyword, keyword = _M.check_suspicious_keywords(
      transaction.description,
      conf.suspicious_keywords
    )
    
    if has_keyword then
      table.insert(patterns_detected, {
        type = "suspicious_keyword",
        keyword = keyword,
        severity = "high"
      })
    end
  end
  
  -- Unusual hours
  local unusual_hour, hour_count = _M.check_unusual_hours(
    transaction.transaction_hour,
    transaction.user_id,
    redis
  )
  
  if unusual_hour then
    table.insert(patterns_detected, {
      type = "unusual_hour",
      hour = transaction.transaction_hour,
      severity = "low"
    })
  end
  
  -- Round amounts
  local is_round, rounded_amt = _M.check_round_amounts(transaction.amount)
  if is_round and transaction.amount >= 5000 then
    table.insert(patterns_detected, {
      type = "round_amount",
      amount = rounded_amt,
      severity = "low"
    })
  end
  
  -- Rapid location change
  if transaction.ip_address then
    local rapid_change, ip_count = _M.check_rapid_location_change(
      redis,
      transaction.user_id,
      transaction.ip_address,
      transaction.timestamp
    )
    
    if rapid_change then
      table.insert(patterns_detected, {
        type = "rapid_location_change",
        ip_count = ip_count,
        severity = "high"
      })
    end
  end
  
  -- Device switching
  if transaction.device_id then
    local device_switch, dev_count = _M.check_device_switching(
      redis,
      transaction.user_id,
      transaction.device_id,
      transaction.timestamp
    )
    
    if device_switch then
      table.insert(patterns_detected, {
        type = "device_switching",
        device_count = dev_count,
        severity = "medium"
      })
    end
  end
  
  return patterns_detected
end

return _M
