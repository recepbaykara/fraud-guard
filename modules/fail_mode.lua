-- Fail Mode Module
-- Handles safe failure behavior for Redis, parsing errors, etc.
-- Implements configurable fail-open vs fail-closed logic

local cjson = require "cjson.safe"

local _M = {}

local FAIL_MODE_OPEN = "open"
local FAIL_MODE_CLOSED = "closed"

-- Validate fail mode configuration
function _M.validate_fail_mode(mode)
  if mode == FAIL_MODE_OPEN or mode == FAIL_MODE_CLOSED then
    return true
  end
  return false
end

-- Handle Redis connection failure
function _M.handle_redis_failure(conf, transaction, error_message)
  local fail_mode = conf.fail_mode or FAIL_MODE_OPEN
  
  -- Log the failure
  local log_entry = {
    event = "redis_failure",
    fail_mode = fail_mode,
    transaction_id = transaction and transaction.transaction_id or "unknown",
    user_id = transaction and transaction.user_id or "unknown",
    error = error_message,
    timestamp = os.time()
  }
  
  kong.log.err("Redis failure: ", cjson.encode(log_entry))
  
  -- Add diagnostic header
  kong.response.set_header("X-Fraud-Error", "redis_unavailable")
  kong.response.set_header("X-Fraud-Fail-Mode", fail_mode)
  
  if fail_mode == FAIL_MODE_CLOSED then
    -- Fail closed: block the request
    kong.log.warn("Failing closed due to Redis unavailability")
    return kong.response.exit(503, {
      error = "Fraud detection service temporarily unavailable",
      code = "SERVICE_UNAVAILABLE",
      message = "Unable to validate transaction safety at this time",
      fail_mode = fail_mode,
      transaction_id = transaction and transaction.transaction_id or "unknown"
    }, {
      ["Content-Type"] = "application/json",
      ["Retry-After"] = "60"
    })
  end
  
  -- Fail open: allow the request but log the incident
  kong.log.warn("Failing open due to Redis unavailability - transaction allowed")
  kong.response.set_header("X-Fraud-Score", "unknown")
  kong.response.set_header("X-Risk-Level", "unknown")
  return true
end

-- Handle transaction extraction failure
function _M.handle_extraction_failure(conf, error_message)
  local fail_mode = conf.fail_mode or FAIL_MODE_OPEN
  
  -- Log the failure
  local log_entry = {
    event = "extraction_failure",
    fail_mode = fail_mode,
    error = error_message,
    timestamp = os.time()
  }
  
  kong.log.err("Transaction extraction failed: ", cjson.encode(log_entry))
  
  kong.response.set_header("X-Fraud-Error", "invalid_request")
  kong.response.set_header("X-Fraud-Fail-Mode", fail_mode)
  
  if fail_mode == FAIL_MODE_CLOSED then
    -- Fail closed: reject malformed request
    return kong.response.exit(400, {
      error = "Invalid transaction data",
      code = "INVALID_REQUEST",
      message = error_message,
      fail_mode = fail_mode
    }, {
      ["Content-Type"] = "application/json"
    })
  end
  
  -- Fail open: allow the request
  kong.log.warn("Failing open due to extraction failure - transaction allowed")
  return true
end

-- Handle rule execution failure
function _M.handle_rule_failure(conf, transaction, rule_id, error_message)
  local fail_mode = conf.fail_mode or FAIL_MODE_OPEN
  
  -- Log the failure
  local log_entry = {
    event = "rule_execution_failure",
    fail_mode = fail_mode,
    transaction_id = transaction.transaction_id,
    user_id = transaction.user_id,
    rule_id = rule_id,
    error = error_message,
    timestamp = os.time()
  }
  
  kong.log.err("Rule execution failed: ", cjson.encode(log_entry))
  
  -- For rule failures, we typically continue with other rules
  -- unless it's a critical API security rule
  
  if rule_id and string.match(rule_id, "^3%.2%-") then
    -- API security rules are critical
    if fail_mode == FAIL_MODE_CLOSED then
      kong.log.warn("Failing closed due to API security rule failure")
      kong.response.set_header("X-Fraud-Error", "security_check_failed")
      kong.response.set_header("X-Fraud-Fail-Mode", fail_mode)
      
      return kong.response.exit(503, {
        error = "Security validation service temporarily unavailable",
        code = "SECURITY_UNAVAILABLE",
        fail_mode = fail_mode,
        transaction_id = transaction.transaction_id
      }, {
        ["Content-Type"] = "application/json"
      })
    end
  end
  
  -- For non-critical failures, continue processing
  return false
end

-- Get recommended fail mode for API security contexts
-- API security should default to closed for financial systems
function _M.get_api_security_fail_mode(conf)
  if conf.fail_mode then
    return conf.fail_mode
  end
  
  -- Default to closed for API security
  return FAIL_MODE_CLOSED
end

return _M
