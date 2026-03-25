-- Execution Mode Module
-- Handles shadow vs enforce mode logic
-- Ensures deterministic behavior across modes

local cjson = require "cjson.safe"

local _M = {}

local MODE_SHADOW = "shadow"
local MODE_ENFORCE = "enforce"

-- Validate mode configuration
function _M.validate_mode(mode)
  if mode == MODE_SHADOW or mode == MODE_ENFORCE then
    return true
  end
  return false
end

-- Check if plugin should block the request
-- In shadow mode, never blocks regardless of score
-- In enforce mode, blocks based on risk result
function _M.should_block(conf, risk_result)
  local mode = conf.mode or MODE_ENFORCE
  
  -- Shadow mode never blocks
  if mode == MODE_SHADOW then
    kong.log.info("Shadow mode: would have blocked with score ", risk_result.total_score)
    return false
  end
  
  -- Enforce mode blocks based on risk
  return risk_result.blocked
end

-- Add mode-specific headers to response
function _M.add_mode_headers(conf, risk_result)
  local mode = conf.mode or MODE_ENFORCE
  
  -- Always add mode header
  kong.response.set_header("X-Fraud-Mode", mode)
  
  -- In shadow mode, add hypothetical decision header
  if mode == MODE_SHADOW and risk_result.blocked then
    kong.response.set_header("X-Fraud-Would-Block", "true")
    kong.response.set_header("X-Fraud-Shadow-Decision", "blocked")
  end
end

-- Log decision in structured format
function _M.log_decision(conf, transaction, risk_result)
  local mode = conf.mode or MODE_ENFORCE
  
  local log_entry = {
    mode = mode,
    transaction_id = transaction.transaction_id,
    user_id = transaction.user_id,
    timestamp = os.time(),
    risk_score = risk_result.total_score,
    risk_level = risk_result.risk_level,
    would_block = risk_result.blocked,
    actually_blocked = mode == MODE_ENFORCE and risk_result.blocked,
    triggered_rules = risk_result.rules_triggered,
    execution_time_ms = risk_result.execution_time_ms
  }
  
  kong.log.info(cjson.encode(log_entry))
end

-- Handle blocking logic based on mode
function _M.handle_block(conf, transaction, risk_result)
  local should_block = _M.should_block(conf, risk_result)
  
  -- Add headers regardless of mode
  _M.add_mode_headers(conf, risk_result)
  
  -- Log decision
  _M.log_decision(conf, transaction, risk_result)
  
  if not should_block then
    return false
  end
  
  -- Build detailed cause message from triggered rules
  local causes = {}
  if risk_result.violation_summary and #risk_result.violation_summary > 0 then
    for _, violation in ipairs(risk_result.violation_summary) do
      if violation.description then
        table.insert(causes, violation.description)
      end
    end
  end
  
  local cause_message = #causes > 0 and table.concat(causes, "; ") or "Multiple fraud indicators detected"
  
  -- Block transaction
  return kong.response.exit(403, {
    error = "Transaction blocked due to fraud detection",
    code = "FRAUD_DETECTED",
    cause = cause_message,
    triggered_rules = risk_result.rules_triggered,
    fraud_score = risk_result.total_score,
    transaction_id = transaction.transaction_id,
    reference = risk_result.reference,
    mode = conf.mode or MODE_ENFORCE
  }, {
    ["Content-Type"] = "application/json",
    ["X-Fraud-Score"] = tostring(risk_result.total_score),
    ["X-Triggered-Rules"] = risk_result.rules_triggered,
    ["X-Risk-Level"] = risk_result.risk_level,
    ["X-Transaction-Id"] = transaction.transaction_id
  })
end

return _M
