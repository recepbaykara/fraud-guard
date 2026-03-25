-- Redis Adapter for Fraud Guard
-- Handles all Redis operations with connection pooling and error handling
-- Implements atomic operations for velocity tracking

local redis = require "resty.redis"

local _M = {}

-- Default connection settings
local DEFAULT_TIMEOUT = 1000  -- 1 second
local DEFAULT_CONNECT_TIMEOUT = 500  -- 500ms
local DEFAULT_SEND_TIMEOUT = 1000
local DEFAULT_READ_TIMEOUT = 1000
local DEFAULT_KEEPALIVE_TIMEOUT = 60000  -- 60 seconds
local DEFAULT_POOL_SIZE = 30

-- Connect to Redis with configuration and advanced timeout handling
function _M.connect(config)
  local red = redis:new()
  
  -- Set granular timeouts
  red:set_timeouts(
    config.connect_timeout or DEFAULT_CONNECT_TIMEOUT,
    config.send_timeout or DEFAULT_SEND_TIMEOUT,
    config.read_timeout or DEFAULT_READ_TIMEOUT
  )
  
  local ok, err = red:connect(config.host, config.port)
  if not ok then
    return nil, "Failed to connect to Redis: " .. tostring(err)
  end
  
  -- Authenticate if password provided
  if config.password and config.password ~= "" then
    local res, err = red:auth(config.password)
    if not res then
      return nil, "Redis authentication failed: " .. tostring(err)
    end
  end
  
  -- Select database
  if config.db and config.db > 0 then
    local res, err = red:select(config.db)
    if not res then
      return nil, "Redis DB selection failed: " .. tostring(err)
    end
  end
  
  return red, nil
end

-- Close connection and return to pool (with proper error handling)
function _M.close(red, config)
  if not red then
    return true
  end
  
  local ok, err = red:set_keepalive(
    (config and config.keepalive_idle_timeout) or DEFAULT_KEEPALIVE_TIMEOUT,
    (config and config.keepalive_pool_size) or DEFAULT_POOL_SIZE
  )
  
  if not ok then
    kong.log.warn("Failed to set Redis keepalive: ", err)
    -- Force close connection
    local close_ok, close_err = red:close()
    if not close_ok then
      kong.log.err("Failed to close Redis connection: ", close_err)
    end
    return false
  end
  
  return true
end

-- Get single key
function _M.get(red, key)
  local res, err = red:get(key)
  if err then
    return nil, err
  end
  if res == ngx.null then
    return nil, nil
  end
  return res, nil
end

-- Set key with optional TTL
function _M.set(red, key, value, ttl)
  local res, err
  if ttl then
    res, err = red:setex(key, ttl, value)
  else
    res, err = red:set(key, value)
  end
  return res, err
end

-- Increment counter
function _M.incr(red, key)
  return red:incr(key)
end

-- Set expiration
function _M.expire(red, key, ttl)
  return red:expire(key, ttl)
end

-- Set operations
function _M.sadd(red, key, member)
  return red:sadd(key, member)
end

function _M.scard(red, key)
  local res, err = red:scard(key)
  if err then
    return 0, err
  end
  return tonumber(res) or 0, nil
end

function _M.sismember(red, key, member)
  local res, err = red:sismember(key, member)
  if err then
    return false, err
  end
  return res == 1, nil
end

function _M.smembers(red, key)
  return red:smembers(key)
end

-- Sorted set operations
function _M.zadd(red, key, score, member)
  return red:zadd(key, score, member)
end

function _M.zcard(red, key)
  local res, err = red:zcard(key)
  if err then
    return 0, err
  end
  return tonumber(res) or 0, nil
end

function _M.zcount(red, key, min, max)
  local res, err = red:zcount(key, min, max)
  if err then
    return 0, err
  end
  return tonumber(res) or 0, nil
end

function _M.zrangebyscore(red, key, min, max)
  local res, err = red:zrangebyscore(key, min, max)
  if err then
    -- Always return a table so callers can safely use # and ipairs without nil checks
    return {}, err
  end
  -- Normalise: Redis returns ngx.null for empty sets in some versions; ensure a table
  if res == nil or res == ngx.null then
    return {}, nil
  end
  return res, nil
end

function _M.zremrangebyscore(red, key, min, max)
  return red:zremrangebyscore(key, min, max)
end

-- Hash operations
function _M.hget(red, key, field)
  local res, err = red:hget(key, field)
  if err then
    return nil, err
  end
  if res == ngx.null then
    return nil, nil
  end
  return res, nil
end

function _M.hset(red, key, field, value)
  return red:hset(key, field, value)
end

function _M.hgetall(red, key)
  local res, err = red:hgetall(key)
  if err then
    return nil, err
  end
  
  -- Convert array response to table
  local hash = {}
  for i = 1, #res, 2 do
    hash[res[i]] = res[i + 1]
  end
  return hash, nil
end

function _M.hincrby(red, key, field, increment)
  return red:hincrby(key, field, increment)
end

function _M.hincrbyfloat(red, key, field, increment)
  return red:hincrbyfloat(key, field, increment)
end

-- Delete key
function _M.del(red, key)
  return red:del(key)
end

-- Check if key exists
function _M.exists(red, key)
  local res, err = red:exists(key)
  if err then
    return false, err
  end
  return res == 1, nil
end

-- Pipeline operations for performance
function _M.init_pipeline(red)
  red:init_pipeline()
end

function _M.commit_pipeline(red)
  return red:commit_pipeline()
end

-- Multi-command operations
function _M.multi(red)
  return red:multi()
end

function _M.exec(red)
  return red:exec()
end

-- TTL management
function _M.ttl(red, key)
  local res, err = red:ttl(key)
  if err then
    return -1, err
  end
  return tonumber(res) or -1, nil
end

-- Batch operations for performance
function _M.batch_get(red, keys)
  if #keys == 0 then
    return {}, nil
  end
  
  red:init_pipeline()
  for _, key in ipairs(keys) do
    red:get(key)
  end
  
  local results, err = red:commit_pipeline()
  if err then
    return nil, err
  end
  
  -- Convert ngx.null to nil
  for i, v in ipairs(results) do
    if v == ngx.null then
      results[i] = nil
    end
  end
  
  return results, nil
end

-- Get current date string (YYYY-MM-DD)
function _M.get_date_key()
  return os.date("%Y-%m-%d")
end

-- Get current hour key (YYYY-MM-DD-HH)
function _M.get_hour_key()
  return os.date("%Y-%m-%d-%H")
end

-- Get current timestamp
function _M.get_timestamp()
  return os.time()
end

-- Build standardized keys
function _M.build_key(prefix, ...)
  local parts = {prefix}
  for _, part in ipairs({...}) do
    table.insert(parts, tostring(part))
  end
  return table.concat(parts, ":")
end

-- Clean up expired data (run periodically)
function _M.cleanup_expired(red, pattern, max_age_seconds)
  local cursor = "0"
  local deleted = 0
  local current_time = os.time()
  
  repeat
    local res, err = red:scan(cursor, "MATCH", pattern, "COUNT", 100)
    if err then
      return deleted, err
    end
    
    cursor = res[1]
    local keys = res[2]
    
    for _, key in ipairs(keys) do
      local ttl_res, ttl_err = red:ttl(key)
      if not ttl_err and tonumber(ttl_res) == -1 then
        -- No TTL set, check if we should delete based on age
        -- This is a safety mechanism
        red:del(key)
        deleted = deleted + 1
      end
    end
  until cursor == "0"
  
  return deleted, nil
end

-- Atomic counter increment with TTL (sliding window)
-- Returns the new count after increment
function _M.incr_with_ttl(red, key, ttl)
  -- Use MULTI/EXEC for atomicity
  red:multi()
  red:incr(key)
  red:expire(key, ttl)
  
  local results, err = red:exec()
  if err then
    return nil, err
  end
  
  -- First result is the INCR value
  return tonumber(results[1]) or 0, nil
end

-- Atomic sliding window counter using sorted sets
-- Adds current timestamp and removes old entries atomically
function _M.sliding_window_incr(red, key, window_seconds, current_timestamp)
  current_timestamp = current_timestamp or os.time()
  local window_start = current_timestamp - window_seconds
  
  -- Lua script for atomic sliding window operation
  local script = [[
    local key = KEYS[1]
    local window_start = tonumber(ARGV[1])
    local current_time = tonumber(ARGV[2])
    local ttl = tonumber(ARGV[3])
    local member = ARGV[4]
    
    -- Remove old entries
    redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)
    
    -- Add current entry
    redis.call('ZADD', key, current_time, member)
    
    -- Set TTL
    redis.call('EXPIRE', key, ttl)
    
    -- Return count in window
    return redis.call('ZCARD', key)
  ]]
  
  local member = string.format("txn_%d_%d", current_timestamp, ngx.worker.pid())
  local count, err = red:eval(script, 1, key, window_start, current_timestamp, window_seconds * 2, member)
  
  if err then
    kong.log.err("Sliding window script failed: ", err)
    return nil, err
  end
  
  return tonumber(count) or 0, nil
end

-- Atomic rate limit check using token bucket algorithm
-- Returns: remaining_tokens, retry_after_seconds
function _M.token_bucket_check(red, key, max_tokens, refill_rate, refill_interval)
  local script = [[
    local key = KEYS[1]
    local max_tokens = tonumber(ARGV[1])
    local refill_rate = tonumber(ARGV[2])
    local refill_interval = tonumber(ARGV[3])
    local current_time = tonumber(ARGV[4])
    
    local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
    local tokens = tonumber(bucket[1]) or max_tokens
    local last_refill = tonumber(bucket[2]) or current_time
    
    -- Calculate refill
    local time_passed = current_time - last_refill
    local refills = math.floor(time_passed / refill_interval)
    if refills > 0 then
      tokens = math.min(max_tokens, tokens + (refills * refill_rate))
      last_refill = last_refill + (refills * refill_interval)
    end
    
    -- Check if token available
    if tokens >= 1 then
      tokens = tokens - 1
      redis.call('HMSET', key, 'tokens', tokens, 'last_refill', last_refill)
      redis.call('EXPIRE', key, refill_interval * 2)
      return {tokens, 0}
    else
      -- Calculate retry after
      local retry_after = refill_interval - time_passed
      return {tokens, retry_after}
    end
  ]]
  
  local result, err = red:eval(script, 1, key, max_tokens, refill_rate, refill_interval, ngx.now())
  if err then
    return nil, 0, err
  end
  
  return tonumber(result[1]) or 0, tonumber(result[2]) or 0, nil
end

-- Batch atomic increments (useful for multiple velocity counters)
function _M.batch_incr_with_ttl(red, keys_and_ttls)
  red:multi()
  
  for _, item in ipairs(keys_and_ttls) do
    red:incr(item.key)
    red:expire(item.key, item.ttl)
  end
  
  local results, err = red:exec()
  if err then
    return nil, err
  end
  
  -- Extract counts from results (every 2nd result is INCR value)
  local counts = {}
  for i = 1, #results, 2 do
    table.insert(counts, tonumber(results[i]) or 0)
  end
  
  return counts, nil
end

return _M
