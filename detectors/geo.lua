-- Geo Location Detector for Fraud Guard
-- IP-based location verification and anomaly detection

local redis_adapter = require "kong.plugins.fraud-guard.storage.redis_adapter"

local _M = {}

-- Try to load GeoIP module (lua-resty-maxminddb or resty.geoip)
local geoip_lib
local geoip_ok, maxminddb = pcall(require, "maxminddb")
if geoip_ok then
  geoip_lib = maxminddb
else
  geoip_ok, maxminddb = pcall(require, "resty.maxminddb")
  if geoip_ok then
    geoip_lib = maxminddb
  end
end

local _geoip_warned = false
local function warn_geoip_unavailable()
  if not _geoip_warned then
    _geoip_warned = true
    ngx.log(ngx.WARN, "[fraud-guard] GeoIP database not available. Country-based fraud detection (impossible travel, " ..
            "high-risk country checks) is DISABLED. Install lua-resty-maxminddb and set geoip_database_path in config.")
  end
end

-- Check if IP is a private/local address
local function is_private_ip(ip)
  return string.match(ip, "^10%.") or
         string.match(ip, "^192%.168%.") or
         string.match(ip, "^172%.1[6-9]%.") or
         string.match(ip, "^172%.2%d%.") or
         string.match(ip, "^172%.3[0-1]%.") or
         string.match(ip, "^127%.") or
         string.match(ip, "^::1$")
end

-- Get country code for IP — returns nil when GeoIP is unavailable (never defaults to "TR")
function _M.get_country_code(ip_address)
  if not ip_address then
    return nil
  end

  -- Private/local IPs return a special marker
  if is_private_ip(ip_address) then
    return "LOCAL"
  end

  if geoip_lib then
    local ok, result = pcall(geoip_lib.lookup, ip_address)
    if ok and result then
      local country = result.country or (result.registered_country)
      if country and country.iso_code then
        return country.iso_code
      end
    end
  end

  warn_geoip_unavailable()
  return nil  -- Unknown — do NOT default to "TR", that breaks all geo-based fraud rules
end

-- Check if IP is from Turkey
function _M.is_turkish_ip(ip_address)
  -- Allow private/local IPs for development
  if is_private_ip(ip_address) then
    return true
  end

  local country = _M.get_country_code(ip_address)
  -- If GeoIP is unavailable (nil), allow the request (fail-open for Turkish check)
  return country == nil or country == "TR"
end

-- Check if IP is on blacklist
function _M.is_blacklisted_ip(redis, ip_address)
  local key = "blacklist:ips"
  local is_blacklisted, _ = redis_adapter.sismember(redis, key, ip_address)
  return is_blacklisted
end

-- Check if IP range is on blacklist
function _M.is_blacklisted_ip_range(redis, ip_address)
  -- Check /24 subnet
  local subnet = string.match(ip_address, "^(%d+%.%d+%.%d+)%.")
  if subnet then
    local key = "blacklist:subnets"
    local is_blacklisted, _ = redis_adapter.sismember(redis, key, subnet)
    if is_blacklisted then
      return true, subnet
    end
  end
  
  return false, nil
end

-- Track IP reputation score
function _M.get_ip_reputation(redis, ip_address)
  local key = string.format("ip:%s:reputation", ip_address)
  
  local reputation, _ = redis_adapter.hgetall(redis, key)
  
  if not reputation or not next(reputation) then
    return {
      score = 50,  -- Neutral
      transaction_count = 0,
      blocked_count = 0,
      flagged_count = 0
    }
  end
  
  return {
    score = tonumber(reputation.score) or 50,
    transaction_count = tonumber(reputation.transaction_count) or 0,
    blocked_count = tonumber(reputation.blocked_count) or 0,
    flagged_count = tonumber(reputation.flagged_count) or 0
  }
end

-- Update IP reputation based on transaction result
function _M.update_ip_reputation(redis, ip_address, was_blocked, was_flagged)
  local key = string.format("ip:%s:reputation", ip_address)
  
  -- Increment counters
  redis_adapter.hincrby(redis, key, "transaction_count", 1)
  
  if was_blocked then
    redis_adapter.hincrby(redis, key, "blocked_count", 1)
    -- Decrease score for blocked transactions
    redis_adapter.hincrbyfloat(redis, key, "score", -5)
  elseif was_flagged then
    redis_adapter.hincrby(redis, key, "flagged_count", 1)
    redis_adapter.hincrbyfloat(redis, key, "score", -2)
  else
    -- Increase score for clean transactions (but cap at 100)
    redis_adapter.hincrbyfloat(redis, key, "score", 0.5)
  end
  
  redis_adapter.expire(redis, key, 86400 * 90)  -- 90 days
end

-- Check for proxy/VPN usage (basic detection)
function _M.is_proxy_or_vpn(ip_address, user_agent)
  -- In production, use a proxy detection service
  -- This is a placeholder for common patterns
  
  -- Check known VPN IP ranges (would need actual database)
  -- For now, just check for localhost/private
  if string.match(ip_address, "^127%.") then
    return false  -- Localhost is not a concern
  end
  
  -- Check user agent for VPN client indicators
  if user_agent then
    local ua_lower = string.lower(user_agent)
    if string.match(ua_lower, "vpn") or 
       string.match(ua_lower, "proxy") or
       string.match(ua_lower, "tor") then
      return true
    end
  end
  
  return false
end

-- Detect impossible travel (transactions from distant locations too quickly)
function _M.check_impossible_travel(redis, user_id, current_ip, timestamp)
  local key = string.format("user:%s:location_history", user_id)
  
  -- Get last location
  local last_location, _ = redis_adapter.hgetall(redis, key)
  
  if not last_location or not next(last_location) then
    -- First transaction, record location
    local country_code = _M.get_country_code(current_ip)
    redis_adapter.hset(redis, key, "ip", current_ip)
    redis_adapter.hset(redis, key, "timestamp", timestamp)
    -- Only store country when GeoIP returned a real value; storing nil breaks Redis hset
    if country_code then
      redis_adapter.hset(redis, key, "country", country_code)
    end
    redis_adapter.expire(redis, key, 86400)
    return false, nil
  end

  local last_ip = last_location.ip
  local last_timestamp = tonumber(last_location.timestamp) or timestamp
  -- Do NOT default to "TR": unknown country must stay nil so the guard below skips the check
  local last_country = last_location.country  -- nil when GeoIP was unavailable at record time
  
  -- If same IP, no travel
  if last_ip == current_ip then
    redis_adapter.hset(redis, key, "timestamp", timestamp)
    return false, nil
  end
  
  local current_country = _M.get_country_code(current_ip)
  local time_diff = timestamp - last_timestamp

  -- If different countries and < 1 hour, likely impossible
  -- Skip check when GeoIP is unavailable (nil) or when IPs are local/private
  if current_country and last_country and
     current_country ~= "LOCAL" and last_country ~= "LOCAL" and
     current_country ~= last_country and time_diff < 3600 then
    -- Update location anyway
    redis_adapter.hset(redis, key, "ip", current_ip)
    redis_adapter.hset(redis, key, "timestamp", timestamp)
    if current_country then
      redis_adapter.hset(redis, key, "country", current_country)
    end

    return true, string.format("%s -> %s in %d minutes",
                               last_country, current_country, math.floor(time_diff / 60))
  end

  -- Update location
  redis_adapter.hset(redis, key, "ip", current_ip)
  redis_adapter.hset(redis, key, "timestamp", timestamp)
  if current_country then
    redis_adapter.hset(redis, key, "country", current_country)
  end

  return false, nil
end

-- Maximum distinct country entries we will iterate over per user.
-- A legitimate user rarely transacts from more than a handful of countries;
-- capping this prevents a malicious actor from building a huge hash to cause
-- CPU/memory spikes in the Lua VM.
local MAX_LOCATION_ENTRIES = 50

-- Check if transaction is from expected location for user
function _M.check_location_consistency(redis, user_id, ip_address)
  local key = string.format("user:%s:usual_locations", user_id)

  -- Get user's usual countries.
  -- hgetall returns the full hash; we cap the iteration below.
  local location_counts, _ = redis_adapter.hgetall(redis, key)

  local current_country = _M.get_country_code(ip_address)

  -- Only track known countries; skip when GeoIP is unavailable (nil)
  if current_country then
    redis_adapter.hincrby(redis, key, current_country, 1)
    redis_adapter.expire(redis, key, 86400 * 30)  -- 30 days
  end

  if not location_counts or not next(location_counts) then
    return true, "first_location"  -- First transaction
  end

  -- If country is unknown, skip consistency check (fail-open)
  if not current_country then
    return true, "unknown_location"
  end

  -- Check if this is a new country, iterating at most MAX_LOCATION_ENTRIES
  local current_count = tonumber(location_counts[current_country]) or 0

  if current_count == 0 then
    -- New country for this user — count previous entries (capped)
    local total_txns = 0
    local iterated = 0
    for _, count in pairs(location_counts) do
      total_txns = total_txns + (tonumber(count) or 0)
      iterated = iterated + 1
      if iterated >= MAX_LOCATION_ENTRIES then break end
    end

    -- If user has >10 transactions and this is first from new country
    if total_txns > 10 then
      return false, "new_country"
    end
  end

  return true, "known_location"
end

-- Check for high-risk countries (configurable)
function _M.is_high_risk_country(country_code, high_risk_list)
  if not high_risk_list then
    -- Default high-risk countries (FATF non-compliant, etc.)
    high_risk_list = {"KP", "IR", "MM"}  -- North Korea, Iran, Myanmar as examples
  end
  
  for _, hr_country in ipairs(high_risk_list) do
    if country_code == hr_country then
      return true
    end
  end
  
  return false
end

-- Detect IP hopping (changing IPs frequently)
function _M.check_ip_hopping(redis, user_id, ip_address, timestamp)
  local key = string.format("user:%s:ip_changes", user_id)
  
  -- Get IP change events in last 24 hours
  local day_ago = timestamp - 86400
  redis_adapter.zremrangebyscore(redis, key, 0, day_ago)
  
  local changes, _ = redis_adapter.zrangebyscore(redis, key, day_ago, timestamp)
  changes = changes or {}

  -- Get last IP
  local last_ip = nil
  if #changes > 0 then
    last_ip = string.match(changes[#changes], "ip_([^_]+)_")
  end
  
  -- If IP changed, record it
  if last_ip ~= ip_address then
    redis_adapter.zadd(redis, key, timestamp, string.format("ip_%s_%d", ip_address, timestamp))
    redis_adapter.expire(redis, key, 86400)
  end
  
  -- Count unique IPs
  local unique_ips = {}
  for _, change in ipairs(changes) do
    local ip = string.match(change, "ip_([^_]+)_")
    if ip then
      unique_ips[ip] = true
    end
  end
  
  local unique_count = 0
  for _ in pairs(unique_ips) do
    unique_count = unique_count + 1
  end
  
  -- 5+ different IPs in 24 hours is suspicious
  if unique_count >= 5 then
    return true, unique_count + 1
  end
  
  return false, unique_count + 1
end

-- Comprehensive geo analysis
function _M.analyze_geo_risk(redis, transaction, conf)
  local geo_risks = {}
  
  if not transaction.ip_address then
    return geo_risks
  end
  
  local ip = transaction.ip_address
  
  -- Check blacklist
  if _M.is_blacklisted_ip(redis, ip) then
    table.insert(geo_risks, {
      type = "blacklisted_ip",
      ip = ip,
      severity = "critical"
    })
  end
  
  local is_range_blocked, subnet = _M.is_blacklisted_ip_range(redis, ip)
  if is_range_blocked then
    table.insert(geo_risks, {
      type = "blacklisted_subnet",
      subnet = subnet,
      severity = "critical"
    })
  end
  
  -- Check IP reputation
  local reputation = _M.get_ip_reputation(redis, ip)
  if reputation.score < 20 then
    table.insert(geo_risks, {
      type = "low_ip_reputation",
      score = reputation.score,
      severity = "high"
    })
  end
  
  -- Check impossible travel
  local impossible, travel_info = _M.check_impossible_travel(
    redis,
    transaction.user_id,
    ip,
    transaction.timestamp
  )
  
  if impossible then
    table.insert(geo_risks, {
      type = "impossible_travel",
      details = travel_info,
      severity = "critical"
    })
  end
  
  -- Check location consistency
  local is_consistent, location_status = _M.check_location_consistency(
    redis,
    transaction.user_id,
    ip
  )
  
  if not is_consistent and location_status == "new_country" then
    table.insert(geo_risks, {
      type = "new_country",
      severity = "medium"
    })
  end
  
  -- Check IP hopping
  local is_hopping, hop_count = _M.check_ip_hopping(
    redis,
    transaction.user_id,
    ip,
    transaction.timestamp
  )
  
  if is_hopping then
    table.insert(geo_risks, {
      type = "ip_hopping",
      unique_ips = hop_count,
      severity = "high"
    })
  end
  
  return geo_risks
end

return _M
