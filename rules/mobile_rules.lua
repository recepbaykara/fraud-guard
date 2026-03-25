-- Mobile Payment Services Rules (Section 3.1.4 - 2 rule groups)
-- Mobile Payment Risk Rules

local velocity = require "kong.plugins.fraud-guard.detectors.velocity"
local pattern = require "kong.plugins.fraud-guard.detectors.pattern"
local geo = require "kong.plugins.fraud-guard.detectors.geo"
local redis_adapter = require "kong.plugins.fraud-guard.storage.redis_adapter"

local _M = {}

-- Compare semantic version strings: "1.10.0" > "1.9.0" (not lexicographic)
-- Returns -1 (a < b), 0 (a == b), 1 (a > b)
local function compare_versions(a, b)
  local function parts(v)
    local t = {}
    for n in string.gmatch(tostring(v), "%d+") do
      t[#t + 1] = tonumber(n)
    end
    return t
  end
  local pa, pb = parts(a), parts(b)
  for i = 1, math.max(#pa, #pb) do
    local va, vb = pa[i] or 0, pb[i] or 0
    if va < vb then return -1 end
    if va > vb then return 1 end
  end
  return 0
end

-- Rule Group 3.1.4-1: Mobile device-specific risk indicators
local function rule_1_4_1_group(conf, transaction, redis)
  local violations = {}
  
  -- Only apply to mobile payment transactions
  if transaction.transaction_type ~= "mobile_payment" and 
     transaction.transaction_type ~= "mobile_transfer" then
    return violations
  end
  
  -- A. New device with high-value transaction
  if transaction.device_id then
    local device_key = string.format("user:%s:device:%s:first_seen", 
                                    transaction.user_id, transaction.device_id)
    
    local first_seen, _ = redis_adapter.get(redis, device_key)
    
    if not first_seen and transaction.amount > 5000 then
      table.insert(violations, {
        rule = "3.1.4-1a",
        score = 30,
        severity = "HIGH",
        description = string.format("New device with high-value transaction: %.2f TL", transaction.amount),
        blocked = false,
        metadata = {
          device_id = transaction.device_id,
          amount = transaction.amount,
          is_new_device = true
        }
      })
      
      redis_adapter.set(redis, device_key, transaction.timestamp, 86400 * 90)
    end
  end
  
  -- B. Jailbroken/Rooted device detection (if provided in transaction data)
  if transaction.device_security_status and 
     (transaction.device_security_status == "jailbroken" or 
      transaction.device_security_status == "rooted") then
    table.insert(violations, {
      rule = "3.1.4-1b",
      score = 35,
      severity = "HIGH",
      description = string.format("Transaction from %s device", transaction.device_security_status),
      blocked = false,
      metadata = {
        security_status = transaction.device_security_status,
        device_id = transaction.device_id
      }
    })
  end
  
  -- C. Device location mismatch with IP location
  if transaction.device_location and transaction.ip_address then
    local device_country = transaction.device_location.country
    local ip_country = geo.get_country_code(transaction.ip_address)
    
    if device_country ~= ip_country then
      table.insert(violations, {
        rule = "3.1.4-1c",
        score = 25,
        severity = "HIGH",
        description = string.format("Device location mismatch: device in %s, IP from %s", 
                                    device_country, ip_country),
        blocked = false,
        metadata = {
          device_country = device_country,
          ip_country = ip_country
        }
      })
    end
  end
  
  -- D. Multiple mobile transactions in very short time (potential app compromise)
  local burst_count = velocity.check_burst_activity(
    redis, 
    transaction.user_id, 
    30,  -- 30 seconds
    transaction.timestamp
  )
  
  if burst_count > 3 then
    table.insert(violations, {
      rule = "3.1.4-1d",
      score = 35,
      severity = "HIGH",
      description = string.format("Mobile payment burst: %d transactions in 30 seconds", burst_count),
      blocked = false,
      metadata = {
        burst_count = burst_count,
        window = "30s"
      }
    })
  end
  
  -- E. Mobile app version check (if old/vulnerable version)
  if transaction.app_version then
    local min_version_key = "config:mobile_app:min_version"
    local min_version, _ = redis_adapter.get(redis, min_version_key)
    
    if min_version and compare_versions(transaction.app_version, min_version) < 0 then
      table.insert(violations, {
        rule = "3.1.4-1e",
        score = 20,
        severity = "MEDIUM",
        description = string.format("Outdated mobile app version: %s (minimum: %s)", 
                                    transaction.app_version, min_version),
        blocked = false,
        metadata = {
          app_version = transaction.app_version,
          min_version = min_version
        }
      })
    end
  end
  
  -- F. Mobile payment at unusual hour for user
  local hour = transaction.transaction_hour
  if hour >= 2 and hour <= 5 then  -- 2AM - 5AM is very unusual for mobile payments
    local unusual, hour_count = pattern.check_unusual_hours(hour, transaction.user_id, redis)
    
    if unusual and transaction.amount > 1000 then
      table.insert(violations, {
        rule = "3.1.4-1f",
        score = 20,
        severity = "MEDIUM",
        description = string.format("Mobile payment at very unusual hour: %02d:00", hour),
        blocked = false,
        metadata = {
          hour = hour,
          amount = transaction.amount
        }
      })
    end
  end
  
  -- G. Excessive daily mobile payment count
  local daily_count = velocity.check_daily_transactions(
    redis,
    transaction.user_id,
    conf.thresholds.max_daily_transactions or 100,
    transaction.timestamp
  )
  
  if daily_count > 50 then  -- 50+ mobile payments in one day
    table.insert(violations, {
      rule = "3.1.4-1g",
      score = 25,
      severity = "HIGH",
      description = string.format("Excessive daily mobile payments: %d transactions", daily_count),
      blocked = false,
      metadata = {
        daily_count = daily_count
      }
    })
  end
  
  return violations
end

-- Rule Group 3.1.4-2: Mobile-specific behavioral anomalies
local function rule_1_4_2_group(conf, transaction, redis)
  local violations = {}
  
  -- Only apply to mobile payment transactions
  if transaction.transaction_type ~= "mobile_payment" and 
     transaction.transaction_type ~= "mobile_transfer" then
    return violations
  end
  
  -- A. Device fingerprint change (potential account takeover)
  if transaction.device_fingerprint then
    local fp_key = string.format("user:%s:device_fingerprints", transaction.user_id)
    
    local known_fps, _ = redis_adapter.smembers(redis, fp_key)
    
    local is_known = false
    for _, fp in ipairs(known_fps) do
      if fp == transaction.device_fingerprint then
        is_known = true
        break
      end
    end
    
    if not is_known and #known_fps > 0 and transaction.amount > 2000 then
      table.insert(violations, {
        rule = "3.1.4-2a",
        score = 30,
        severity = "HIGH",
        description = "New device fingerprint with significant transaction",
        blocked = false,
        metadata = {
          device_fingerprint = transaction.device_fingerprint,
          amount = transaction.amount
        }
      })
    end
    
    -- Add fingerprint
    redis_adapter.sadd(redis, fp_key, transaction.device_fingerprint)
    redis_adapter.expire(redis, fp_key, 86400 * 90)
  end
  
  -- B. Mobile payment after recent password change (potential account compromise)
  if transaction.password_changed_at then
    local hours_since_change = (transaction.timestamp - transaction.password_changed_at) / 3600
    
    if hours_since_change < 1 and transaction.amount > 3000 then
      table.insert(violations, {
        rule = "3.1.4-2b",
        score = 35,
        severity = "HIGH",
        description = string.format("Large mobile payment %.0f minutes after password change", 
                                    hours_since_change * 60),
        blocked = false,
        metadata = {
          minutes_since_change = math.floor(hours_since_change * 60),
          amount = transaction.amount
        }
      })
    end
  end
  
  -- C. Mobile payment from VPN/Proxy
  if transaction.ip_address then
    local is_proxy = geo.is_proxy_or_vpn(transaction.ip_address, transaction.user_agent)
    
    if is_proxy and transaction.amount > 5000 then
      table.insert(violations, {
        rule = "3.1.4-2c",
        score = 25,
        severity = "HIGH",
        description = "Large mobile payment from VPN/Proxy",
        blocked = false,
        metadata = {
          amount = transaction.amount,
          ip = transaction.ip_address
        }
      })
    end
  end
  
  -- D. Biometric authentication bypass (if biometric was enabled but not used)
  if transaction.biometric_enabled and not transaction.biometric_used then
    if transaction.amount > 2000 then
      table.insert(violations, {
        rule = "3.1.4-2d",
        score = 25,
        severity = "HIGH",
        description = "Biometric authentication bypassed for significant transaction",
        blocked = false,
        metadata = {
          amount = transaction.amount,
          auth_method = transaction.auth_method or "unknown"
        }
      })
    end
  end
  
  -- E. Mobile payment velocity spike compared to historical pattern
  local is_spike, spike_info = pattern.check_velocity_change(
    redis,
    transaction.user_id,
    transaction.timestamp
  )
  
  if is_spike then
    table.insert(violations, {
      rule = "3.1.4-2e",
      score = 20,
      severity = "MEDIUM",
      description = string.format("Mobile payment velocity spike: %s", spike_info),
      blocked = false,
      metadata = {
        spike_info = spike_info
      }
    })
  end
  
  -- F. Mobile QR code payment at suspicious merchant
  if transaction.payment_method == "qr_code" and transaction.merchant_id then
    local merchant_rep_key = string.format("merchant:%s:reputation", transaction.merchant_id)
    local merchant_rep, _ = redis_adapter.get(redis, merchant_rep_key)
    merchant_rep = tonumber(merchant_rep) or 50
    
    if merchant_rep < 30 then
      table.insert(violations, {
        rule = "3.1.4-2f",
        score = 20,
        severity = "MEDIUM",
        description = string.format("QR payment at low-reputation merchant (score: %d)", merchant_rep),
        blocked = false,
        metadata = {
          merchant_reputation = merchant_rep,
          merchant_id = transaction.merchant_id
        }
      })
    end
  end
  
  -- G. Rapid beneficiary change in mobile app
  if transaction.transaction_type == "mobile_transfer" and transaction.recipient_id then
    local recip_key = string.format("user:%s:mobile_recipients", transaction.user_id)
    local hour_ago = transaction.timestamp - 3600
    
    redis_adapter.zremrangebyscore(redis, recip_key, 0, hour_ago)
    
    -- Count unique recipients
    local recipients, _ = redis_adapter.zrangebyscore(redis, recip_key, hour_ago, transaction.timestamp)
    recipients = recipients or {}
    local unique_recipients = {}
    for _, entry in ipairs(recipients) do
      local recip = string.match(entry, "recip_([^_]+)_")
      if recip then
        unique_recipients[recip] = true
      end
    end
    
    redis_adapter.zadd(redis, recip_key, transaction.timestamp, 
                      string.format("recip_%s_%d", transaction.recipient_id, transaction.timestamp))
    redis_adapter.expire(redis, recip_key, 3600)
    
    local recip_count = 0
    for _ in pairs(unique_recipients) do
      recip_count = recip_count + 1
    end
    
    if recip_count >= 5 then
      table.insert(violations, {
        rule = "3.1.4-2g",
        score = 25,
        severity = "HIGH",
        description = string.format("Rapid beneficiary change: %d recipients in 1 hour", recip_count + 1),
        blocked = false,
        metadata = {
          recipient_count = recip_count + 1
        }
      })
    end
  end
  
  -- H. Mobile payment with SIM card change
  if transaction.sim_changed_recently then
    local hours_since_sim_change = transaction.hours_since_sim_change or 0
    
    if hours_since_sim_change < 24 and transaction.amount > 3000 then
      table.insert(violations, {
        rule = "3.1.4-2h",
        score = 35,
        severity = "HIGH",
        description = string.format("Large payment %.0f hours after SIM card change", hours_since_sim_change),
        blocked = false,
        metadata = {
          hours_since_sim_change = hours_since_sim_change,
          amount = transaction.amount
        }
      })
    end
  end
  
  return violations
end

-- Main check function for all mobile payment rules
function _M.check(conf, transaction, redis)
  local all_violations = {}
  
  -- Execute both rule groups
  local rule_groups = {
    rule_1_4_1_group,  -- Device-specific indicators (7 sub-rules)
    rule_1_4_2_group   -- Behavioral anomalies (8 sub-rules)
  }
  
  for _, rule_func in ipairs(rule_groups) do
    local violations = rule_func(conf, transaction, redis)
    for _, v in ipairs(violations) do
      table.insert(all_violations, v)
    end
  end
  
  return all_violations
end

return _M
