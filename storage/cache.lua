-- Cache Layer for Fraud Guard
-- Implements shared dict caching for performance optimization

local _M = {}

local CACHE_NAME = "fraud_guard_cache"

-- Default TTL is set here so callers that skip init() still get a safe value.
_M.default_ttl = 300  -- 5 minutes

-- Initialize cache.
-- Must be called from the plugin's init_worker() phase so the shared-dict
-- availability warning is emitted exactly once per worker at startup.
-- If init() is never called the cache still degrades gracefully, but the
-- startup warning is suppressed and default_ttl stays at 300 s.
function _M.init(cache_ttl)
  _M.default_ttl = cache_ttl or 300

  local cache = ngx.shared[CACHE_NAME]
  if not cache then
    ngx.log(ngx.WARN,
      "[fraud-guard] Shared dict '" .. CACHE_NAME .. "' not found. " ..
      "Cache layer is DISABLED. Add the following to your Kong nginx template: " ..
      "  lua_shared_dict " .. CACHE_NAME .. " 10m;" ..
      "  (restart Kong after adding this directive)")
  else
    ngx.log(ngx.INFO,
      "[fraud-guard] Cache initialised — shared dict '" .. CACHE_NAME ..
      "', TTL=" .. tostring(_M.default_ttl) .. "s")
  end
end

-- No-op clear helper used in unit tests to reset module-level state.
function _M.clear_for_test()
  _M.default_ttl = 300
end

-- Get value from cache
function _M.get(key)
  local cache = ngx.shared[CACHE_NAME]
  if not cache then
    return nil, "Cache not available"
  end
  
  local value, flags = cache:get(key)
  if value then
    kong.log.debug("Cache hit: ", key)
    return value, nil
  end
  
  kong.log.debug("Cache miss: ", key)
  return nil, nil
end

-- Set value in cache
function _M.set(key, value, ttl)
  local cache = ngx.shared[CACHE_NAME]
  if not cache then
    return false, "Cache not available"
  end
  
  ttl = ttl or _M.default_ttl
  
  local success, err, forcible = cache:set(key, value, ttl)
  if not success then
    kong.log.warn("Cache set failed for key ", key, ": ", err)
    return false, err
  end
  
  if forcible then
    kong.log.debug("Cache evicted entries to make room")
  end
  
  return true, nil
end

-- Delete value from cache
function _M.delete(key)
  local cache = ngx.shared[CACHE_NAME]
  if not cache then
    return false, "Cache not available"
  end
  
  cache:delete(key)
  return true, nil
end

-- Get or set (with loader function)
function _M.get_or_set(key, loader_fn, ttl)
  -- Try cache first
  local value, err = _M.get(key)
  if value then
    return value, nil
  end
  
  -- Cache miss - load value
  value, err = loader_fn()
  if err then
    return nil, err
  end
  
  -- Store in cache
  _M.set(key, value, ttl)
  
  return value, nil
end

-- Increment counter in cache
function _M.incr(key, value, ttl)
  local cache = ngx.shared[CACHE_NAME]
  if not cache then
    return nil, "Cache not available"
  end
  
  value = value or 1
  ttl = ttl or _M.default_ttl
  
  local newval, err = cache:incr(key, value, 0)  -- Initialize to 0 if not exists
  if not newval then
    return nil, err
  end

  -- Set TTL on first increment (ngx.shared.DICT has no expire(), use set instead)
  if newval == value then
    local ok, set_err = cache:set(key, newval, ttl)
    if not ok then
      kong.log.warn("Cache incr: failed to set TTL for key ", key, ": ", tostring(set_err),
                    " — counter incremented but key may persist until eviction")
    end
  end

  return newval, nil
end

-- Flush all cache entries
function _M.flush_all()
  local cache = ngx.shared[CACHE_NAME]
  if not cache then
    return false, "Cache not available"
  end
  
  cache:flush_all()
  kong.log.info("Cache flushed")
  return true, nil
end

-- Get cache statistics
function _M.stats()
  local cache = ngx.shared[CACHE_NAME]
  if not cache then
    return nil, "Cache not available"
  end
  
  return {
    capacity = cache:capacity(),
    free_space = cache:free_space(),
    keys = cache:get_keys(0)  -- Get all keys
  }
end

-- Build cache key for sector averages
function _M.build_sector_avg_key(sector, period)
  return string.format("sector_avg:%s:%s", sector, period)
end

-- Build cache key for merchant data
function _M.build_merchant_key(merchant_id, data_type)
  return string.format("merchant:%s:%s", merchant_id, data_type)
end

-- Build cache key for whitelist
function _M.build_whitelist_key(type, id)
  return string.format("whitelist:%s:%s", type, id)
end

-- Build cache key for user metadata
function _M.build_user_key(user_id, data_type)
  return string.format("user:%s:%s", user_id, data_type)
end

-- Build cache key for IP data
function _M.build_ip_key(ip, data_type)
  return string.format("ip:%s:%s", ip, data_type)
end

-- Cache sector average
function _M.cache_sector_average(sector, period, value, ttl)
  local key = _M.build_sector_avg_key(sector, period)
  return _M.set(key, value, ttl or 3600)  -- 1 hour default for sector data
end

-- Get cached sector average
function _M.get_sector_average(sector, period)
  local key = _M.build_sector_avg_key(sector, period)
  return _M.get(key)
end

-- Cache merchant baseline
function _M.cache_merchant_baseline(merchant_id, baseline_data, ttl)
  local key = _M.build_merchant_key(merchant_id, "baseline")
  local value = require("cjson").encode(baseline_data)
  return _M.set(key, value, ttl or 3600)
end

-- Get cached merchant baseline
function _M.get_merchant_baseline(merchant_id)
  local key = _M.build_merchant_key(merchant_id, "baseline")
  local value, err = _M.get(key)
  if not value then
    return nil, err
  end
  return require("cjson").decode(value), nil
end

-- Cache whitelist check result
function _M.cache_whitelist_result(type, id, is_whitelisted, ttl)
  local key = _M.build_whitelist_key(type, id)
  return _M.set(key, is_whitelisted and "1" or "0", ttl or 300)
end

-- Get cached whitelist result
function _M.get_whitelist_result(type, id)
  local key = _M.build_whitelist_key(type, id)
  local value, err = _M.get(key)
  if not value then
    return nil, err
  end
  return value == "1", nil
end

-- Batch cache operations
function _M.mget(keys)
  local cache = ngx.shared[CACHE_NAME]
  if not cache then
    return nil, "Cache not available"
  end
  
  local results = {}
  for _, key in ipairs(keys) do
    local value = cache:get(key)
    table.insert(results, value)
  end
  
  return results, nil
end

-- Cache warmup function (called on plugin init)
function _M.warmup(conf)
  kong.log.info("Warming up cache...")
  
  -- Cache suspicious keywords
  if conf.suspicious_keywords then
    local key = "config:suspicious_keywords"
    local value = require("cjson").encode(conf.suspicious_keywords)
    _M.set(key, value, 3600)
  end
  
  -- Cache sector averages
  if conf.sector_averages then
    for sector, avg in pairs(conf.sector_averages) do
      _M.cache_sector_average(sector, "daily", avg, 3600)
    end
  end
  
  -- Cache thresholds
  local thresholds_key = "config:thresholds"
  local thresholds_value = require("cjson").encode(conf.thresholds)
  _M.set(thresholds_key, thresholds_value, 3600)
  
  kong.log.info("Cache warmup complete")
end

return _M
