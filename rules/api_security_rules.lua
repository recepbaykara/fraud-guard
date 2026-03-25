-- API Security Rules (Section 3.2 - 5 rules)
-- API Access Security and Abuse Prevention
-- NOTE: Bot/attack tool detection (User-Agent) → Kong bot-detection plugin
-- NOTE: SQL injection / XSS pattern detection  → Kong request-validator plugin

local geo = require "kong.plugins.fraud-guard.detectors.geo"
local ip_validator = require "kong.plugins.fraud-guard.modules.ip_validator"
local redis_adapter = require "kong.plugins.fraud-guard.storage.redis_adapter"

local _M = {}

-- Rule 3.2-1: Missing authentication headers on non-public endpoints
local function rule_3_2_1(conf, transaction, redis)
  local violations = {}

  local headers = kong.request.get_headers()
  local path = transaction.request_path or ""

  -- Skip check for public/health endpoints
  local public_paths = { "/health", "/ping", "/status", "/ready", "/live" }
  for _, pub in ipairs(public_paths) do
    if path == pub or path:sub(1, #pub + 1) == pub .. "/" then
      return violations
    end
  end

  local has_auth = headers["authorization"] or
                   headers["x-api-key"] or
                   headers["x-auth-token"]

  if not has_auth then
    table.insert(violations, {
      rule = "3.2-1",
      score = 30,
      severity = "HIGH",
      description = "API request missing authentication headers",
      blocked = false,
      metadata = {
        path = path,
        method = transaction.request_method
      }
    })
  end

  return violations
end

-- Rule 3.2-2: Abnormal API request rate from same IP (>100 req/min)
local function rule_3_2_2(conf, transaction, redis)
  local violations = {}

  if not transaction.ip_address then
    return violations
  end

  local ip_key = "api:ip_rate:" .. transaction.ip_address
  local window_seconds = 60
  local max_requests = 100

  local count, err = redis_adapter.sliding_window_incr(
    redis, ip_key, window_seconds, transaction.timestamp
  )

  if err or not count then
    return violations
  end

  if count > max_requests then
    local is_critical = count > (max_requests * 3)
    table.insert(violations, {
      rule = "3.2-2",
      score = is_critical and 50 or 30,
      severity = is_critical and "CRITICAL" or "HIGH",
      description = string.format(
        "Abnormal API request rate from IP %s: %d req/min (limit: %d)",
        transaction.ip_address, count, max_requests
      ),
      blocked = is_critical,
      metadata = {
        ip = transaction.ip_address,
        request_count = count,
        threshold = max_requests,
        window_seconds = window_seconds
      }
    })
  end

  return violations
end

-- Rule 3.2-5: Non-whitelisted IP accessing sensitive/admin endpoints
local function rule_3_2_5(conf, transaction, redis)
  local violations = {}

  local path = transaction.request_path or ""
  local method = transaction.request_method or "GET"

  local sensitive_prefixes = {
    "/admin", "/internal", "/debug", "/actuator",
    "/metrics", "/env", "/config", "/management",
    "/swagger", "/api-docs", "/.env", "/console"
  }

  local is_sensitive = false
  for _, prefix in ipairs(sensitive_prefixes) do
    if path == prefix or path:sub(1, #prefix) == prefix then
      is_sensitive = true
      break
    end
  end

  if not is_sensitive then
    return violations
  end

  -- Allow if IP is explicitly whitelisted
  if conf.whitelists and conf.whitelists.ip_ranges and
     #conf.whitelists.ip_ranges > 0 and transaction.ip_address then
    local whitelisted, _ = ip_validator.is_ip_whitelisted(
      transaction.ip_address, conf.whitelists.ip_ranges
    )
    if whitelisted then
      return violations
    end
  end

  table.insert(violations, {
    rule = "3.2-5",
    score = 40,
    severity = "HIGH",
    description = string.format(
      "Non-whitelisted IP accessing sensitive endpoint: %s %s",
      method, path
    ),
    blocked = false,
    metadata = {
      ip = transaction.ip_address,
      path = path,
      method = method
    }
  })

  return violations
end

-- Rule 3.2-6: Blocklisted IP or very low reputation score
local function rule_3_2_6(conf, transaction, redis)
  local violations = {}

  if not transaction.ip_address then
    return violations
  end

  -- Hard block if IP is on explicit blocklist
  local is_blacklisted = geo.is_blacklisted_ip(redis, transaction.ip_address)
  if is_blacklisted then
    table.insert(violations, {
      rule = "3.2-6",
      score = 50,
      severity = "CRITICAL",
      description = string.format(
        "API access from blocklisted IP: %s", transaction.ip_address
      ),
      blocked = true,
      metadata = { ip = transaction.ip_address }
    })
    return violations
  end

  -- Soft flag if reputation score is low
  local reputation = geo.get_ip_reputation(redis, transaction.ip_address)
  if reputation and reputation.score < 30 then
    table.insert(violations, {
      rule = "3.2-6",
      score = 25,
      severity = "MEDIUM",
      description = string.format(
        "Low reputation IP accessing API: %s (score: %d)",
        transaction.ip_address, reputation.score
      ),
      blocked = false,
      metadata = {
        ip = transaction.ip_address,
        reputation_score = reputation.score,
        blocked_count = reputation.blocked_count
      }
    })
  end

  return violations
end

-- Rule 3.2-7: Credential stuffing / brute-force on authentication endpoints
local function rule_3_2_7(conf, transaction, redis)
  local violations = {}

  local path = transaction.request_path or ""
  local method = transaction.request_method or "GET"

  if method ~= "POST" then
    return violations
  end

  local auth_paths = { "/login", "/auth", "/token", "/signin", "/session", "/oauth" }
  local is_auth_endpoint = false
  for _, auth_path in ipairs(auth_paths) do
    if path == auth_path or path:sub(1, #auth_path) == auth_path then
      is_auth_endpoint = true
      break
    end
  end

  if not is_auth_endpoint then
    return violations
  end

  local ip_key = "api:auth_attempts:" .. (transaction.ip_address or "unknown")
  local window_seconds = 300  -- 5-minute window
  local max_attempts = 20

  local attempt_count, err = redis_adapter.sliding_window_incr(
    redis, ip_key, window_seconds, transaction.timestamp
  )

  if err or not attempt_count then
    return violations
  end

  if attempt_count > max_attempts then
    local is_critical = attempt_count > (max_attempts * 2)
    table.insert(violations, {
      rule = "3.2-7",
      score = is_critical and 50 or 30,
      severity = is_critical and "CRITICAL" or "HIGH",
      description = string.format(
        "Potential credential stuffing: %d auth attempts in 5 min from %s",
        attempt_count, transaction.ip_address or "unknown"
      ),
      blocked = is_critical,
      metadata = {
        ip = transaction.ip_address,
        attempt_count = attempt_count,
        threshold = max_attempts,
        path = path
      }
    })
  end

  return violations
end

-- Main check function called by rule engine
function _M.check(conf, transaction, redis)
  local violations = {}

  local rules = {
    rule_3_2_1,  -- Missing auth headers
    rule_3_2_2,  -- IP rate abuse
    rule_3_2_5,  -- Sensitive endpoint access
    rule_3_2_6,  -- IP blocklist / reputation
    rule_3_2_7,  -- Credential stuffing
  }

  for _, rule_fn in ipairs(rules) do
    local ok, result = pcall(rule_fn, conf, transaction, redis)
    if ok and result then
      for _, v in ipairs(result) do
        table.insert(violations, v)
      end
    elseif not ok then
      kong.log.warn("API security rule error: ", tostring(result))
    end
  end

  return violations
end

return _M
