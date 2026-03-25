-- Velocity Detector for Fraud Guard
-- Detects time-based frequency anomalies (transactions per hour/day)

local redis_adapter = require "kong.plugins.fraud-guard.storage.redis_adapter"

local _M = {}

-- Generate a collision-resistant member ID for sorted-set entries.
-- Combines microsecond timestamp + worker ID + per-worker counter so that
-- two concurrent requests in the same millisecond cannot produce the same key.
local _seq = 0
local function unique_member_id(prefix)
  _seq = (_seq + 1) % 0xFFFF
  local worker_id = (ngx and ngx.worker and ngx.worker.id()) or 0
  local ts_us = (ngx and ngx.now and math.floor(ngx.now() * 1000000)) or os.time()
  return string.format("%s_%d_%d_%d", prefix, ts_us, worker_id, _seq)
end

-- Check daily transaction velocity for user
function _M.check_daily_transactions(redis, user_id, threshold, current_timestamp)
  local ts = current_timestamp or os.time()
  local date = os.date("%Y-%m-%d", ts)
  local key = string.format("user:%s:daily_txns:%s", user_id, date)

  -- Add current transaction FIRST (atomic write), then read count.
  -- unique_member_id() guarantees no collision across workers/goroutines.
  redis_adapter.zadd(redis, key, ts, unique_member_id("txn"))
  redis_adapter.expire(redis, key, 86400 * 2)  -- Keep for 2 days

  local count, err = redis_adapter.zcard(redis, key)
  if err then
    kong.log.err("Failed to get daily transaction count: ", err)
    return 1
  end

  return count
end

-- Check hourly transaction velocity
function _M.check_hourly_transactions(redis, user_id, threshold, current_timestamp)
  current_timestamp = current_timestamp or os.time()
  local hour_start = current_timestamp - (current_timestamp % 3600)
  local key = string.format("user:%s:hourly_txns:%d", user_id, hour_start)
  
  local count, err = redis_adapter.incr(redis, key)
  if err then
    kong.log.err("Failed to increment hourly transaction count: ", err)
    return 0
  end
  
  redis_adapter.expire(redis, key, 7200)  -- Keep for 2 hours
  
  return count
end

-- Check transactions to same merchant within time window
function _M.check_merchant_frequency(redis, user_id, merchant_id, window_seconds, current_timestamp)
  current_timestamp = current_timestamp or os.time()
  local window_start = current_timestamp - window_seconds
  
  local key = string.format("user:%s:merchant:%s:txns", user_id, merchant_id)
  
  -- Remove old transactions outside window
  redis_adapter.zremrangebyscore(redis, key, 0, window_start)
  
  -- Get count within window
  local count, err = redis_adapter.zcount(redis, key, window_start, current_timestamp)
  if err or count == nil then
    kong.log.err("Failed to count merchant transactions: ", tostring(err))
    return 0
  end

  -- Add current transaction with collision-resistant ID
  redis_adapter.zadd(redis, key, current_timestamp, unique_member_id("txn"))
  redis_adapter.expire(redis, key, window_seconds * 2)

  return count + 1
end

-- Check daily unique recipients for transfers
function _M.check_daily_recipients(redis, user_id, current_recipient, current_timestamp)
  local date = os.date("%Y-%m-%d", current_timestamp or os.time())
  local key = string.format("user:%s:daily_recipients:%s", user_id, date)
  
  -- Get current count
  local count, err = redis_adapter.scard(redis, key)
  if err then
    kong.log.err("Failed to get daily recipients count: ", err)
    return 0, false
  end
  
  -- sismember returns true if the recipient is ALREADY in the set (not a new recipient)
  local already_exists, err = redis_adapter.sismember(redis, key, current_recipient)
  if err then
    kong.log.err("Failed to check recipient membership: ", err)
  end

  local is_new_recipient = not already_exists

  -- Add only if this is a new recipient today
  if is_new_recipient then
    redis_adapter.sadd(redis, key, current_recipient)
    redis_adapter.expire(redis, key, 86400 * 2)
    count = count + 1
  end

  return count, is_new_recipient  -- (total unique recipients today, whether current is new)
end

-- Check transaction amount velocity (total amount in time window)
function _M.check_amount_velocity(redis, user_id, amount, window_seconds, current_timestamp)
  current_timestamp = current_timestamp or os.time()
  local window_start = current_timestamp - window_seconds

  local key = string.format("user:%s:amount_velocity:%d", user_id, window_start)

  local total, err = redis_adapter.get(redis, key)
  if err then
    kong.log.err("Failed to get amount velocity for user ", user_id, ": ", err)
  end
  total = tonumber(total) or 0

  total = total + amount
  redis_adapter.set(redis, key, total, window_seconds + 3600)

  return total
end

-- Check daily amount for account
function _M.check_daily_amount(redis, account_id, amount, current_timestamp)
  local date = os.date("%Y-%m-%d", current_timestamp or os.time())
  local key = string.format("account:%s:daily_amount:%s", account_id, date)

  local total, err = redis_adapter.get(redis, key)
  if err then
    kong.log.err("Failed to get daily amount for account ", account_id, ": ", err)
  end
  total = tonumber(total) or 0

  total = total + amount
  redis_adapter.set(redis, key, total, 86400 * 2)

  return total
end

-- Check monthly totals for new accounts (Rule 3.1.1-6)
function _M.check_monthly_stats_for_new_account(redis, account_id, amount, account_age_days, current_timestamp)
  -- Only check if account is under 30 days old
  if account_age_days > 30 then
    return {
      transaction_count = 0,
      total_amount = 0,
      is_new_account = false
    }
  end
  
  local key_prefix = string.format("account:%s:monthly", account_id)
  
  -- Transaction count
  local txn_key = key_prefix .. ":txn_count"
  local txn_count, _ = redis_adapter.incr(redis, txn_key)
  redis_adapter.expire(redis, txn_key, 86400 * 31)
  
  -- Total amount
  local amount_key = key_prefix .. ":total_amount"
  local current_total, _ = redis_adapter.get(redis, amount_key)
  current_total = tonumber(current_total) or 0
  current_total = current_total + amount
  redis_adapter.set(redis, amount_key, current_total, 86400 * 31)
  
  return {
    transaction_count = txn_count,
    total_amount = current_total,
    is_new_account = true,
    account_age_days = account_age_days
  }
end

-- Check card usage at e-pin merchant (Rule 3.1.2-15)
function _M.check_epin_card_usage(redis, card_bin, merchant_id, amount, current_timestamp)
  current_timestamp = current_timestamp or os.time()
  local hour_start = current_timestamp - 3600  -- Last hour
  
  local key = string.format("epin:card:%s:merchant:%s", card_bin, merchant_id)
  
  -- Get transactions in last hour
  redis_adapter.zremrangebyscore(redis, key, 0, hour_start)
  local txn_count, _ = redis_adapter.zcard(redis, key)
  
  -- Get total amount in last hour
  local amount_key = key .. ":amount"
  local total_amount, _ = redis_adapter.get(redis, amount_key)
  total_amount = tonumber(total_amount) or 0
  
  -- Add current transaction with collision-resistant ID
  redis_adapter.zadd(redis, key, current_timestamp, unique_member_id("txn"))
  redis_adapter.expire(redis, key, 7200)
  
  -- Update amount
  total_amount = total_amount + amount
  redis_adapter.set(redis, amount_key, total_amount, 7200)
  
  return {
    hourly_transaction_count = txn_count + 1,
    hourly_total_amount = total_amount
  }
end

-- Check repeated same-amount transactions (potential card testing)
function _M.check_repeated_amounts(redis, user_id, amount, window_seconds, current_timestamp)
  current_timestamp = current_timestamp or os.time()
  local window_start = current_timestamp - window_seconds
  
  -- Round amount to avoid floating point issues
  local rounded_amount = math.floor(amount * 100) / 100
  
  local key = string.format("user:%s:repeated_amount:%.2f", user_id, rounded_amount)
  
  -- Remove old entries
  redis_adapter.zremrangebyscore(redis, key, 0, window_start)
  
  -- Get count (nil on Redis error → treat as 0 to fail-open)
  local count, _ = redis_adapter.zcard(redis, key)
  count = count or 0

  -- Add current with collision-resistant ID
  redis_adapter.zadd(redis, key, current_timestamp, unique_member_id("txn"))
  redis_adapter.expire(redis, key, window_seconds * 2)

  return count + 1
end

-- Check burst transactions (many transactions in very short time)
function _M.check_burst_activity(redis, user_id, burst_window_seconds, current_timestamp)
  current_timestamp = current_timestamp or os.time()
  burst_window_seconds = burst_window_seconds or 60  -- Default 1 minute
  local window_start = current_timestamp - burst_window_seconds
  
  local key = string.format("user:%s:burst_txns", user_id)
  
  -- Clean old entries
  redis_adapter.zremrangebyscore(redis, key, 0, window_start)
  
  -- Get burst count (nil on Redis error → treat as 0 to fail-open)
  local count, _ = redis_adapter.zcount(redis, key, window_start, current_timestamp)
  count = count or 0
  
  -- Add current with collision-resistant ID
  redis_adapter.zadd(redis, key, current_timestamp, unique_member_id("txn"))
  redis_adapter.expire(redis, key, burst_window_seconds * 2)

  return count + 1
end

-- Check velocity across multiple dimensions
function _M.check_multi_dimensional_velocity(redis, transaction, thresholds)
  local violations = {}
  
  -- Daily transactions
  if thresholds.max_daily_transactions then
    local daily_count = _M.check_daily_transactions(
      redis, 
      transaction.user_id, 
      thresholds.max_daily_transactions,
      transaction.timestamp
    )
    
    if daily_count > thresholds.max_daily_transactions then
      table.insert(violations, {
        type = "daily_transaction_limit",
        count = daily_count,
        threshold = thresholds.max_daily_transactions,
        severity = "medium"
      })
    end
  end
  
  -- Hourly transactions
  if thresholds.max_hourly_transactions then
    local hourly_count = _M.check_hourly_transactions(
      redis,
      transaction.user_id,
      thresholds.max_hourly_transactions,
      transaction.timestamp
    )
    
    if hourly_count > thresholds.max_hourly_transactions then
      table.insert(violations, {
        type = "hourly_transaction_limit",
        count = hourly_count,
        threshold = thresholds.max_hourly_transactions,
        severity = "high"
      })
    end
  end
  
  -- Burst detection (>10 transactions in 1 minute is suspicious)
  local burst_count = _M.check_burst_activity(redis, transaction.user_id, 60, transaction.timestamp)
  if burst_count > 10 then
    table.insert(violations, {
      type = "burst_activity",
      count = burst_count,
      window = "60 seconds",
      severity = "critical"
    })
  end
  
  return violations
end

return _M
