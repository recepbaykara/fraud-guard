-- Risk Scoring Engine for Fraud Guard
-- Calculates weighted risk scores based on triggered rules

local cjson = require "cjson.safe"
local resty_random = require "resty.random"
local str = require "resty.string"

local _M = {}

-- Risk level thresholds
local RISK_LEVELS = {
  LOW = "low",
  MEDIUM = "medium",
  HIGH = "high"
}

-- Rule severity weights
local SEVERITY_WEIGHTS = {
  CRITICAL = {min = 40, max = 50},
  HIGH = {min = 25, max = 35},
  MEDIUM = {min = 15, max = 20},
  LOW = {min = 5, max = 10}
}

-- Generate unique reference ID for blocked transactions (cryptographically secure)
local function generate_reference()
  local date = os.date("%Y-%m-%d")
  
  -- Generate cryptographically secure random bytes
  local random_bytes = resty_random.bytes(3, true)
  if not random_bytes then
    -- Fallback to timestamp-based (deterministic but unique per request)
    local timestamp = ngx.now() * 1000000
    return string.format("FRD-%s-%012d", date, timestamp % 1000000000000)
  end
  
  -- Convert to hex and take first 6 digits
  local hex = str.to_hex(random_bytes)
  local numeric = tonumber(hex:sub(1, 6), 16) % 1000000
  
  return string.format("FRD-%s-%06d", date, numeric)
end

-- Determine risk level based on score
local function get_risk_level(score, conf)
  local block_threshold = conf.thresholds.block_score or 70
  local review_threshold = conf.thresholds.review_score or 30
  
  if score >= block_threshold then
    return RISK_LEVELS.HIGH
  elseif score >= review_threshold then
    return RISK_LEVELS.MEDIUM
  else
    return RISK_LEVELS.LOW
  end
end

-- Aggregate triggered rules into comma-separated string
local function aggregate_rules(violations)
  local rules = {}
  local seen = {}
  
  for _, violation in ipairs(violations) do
    if violation.rule and not seen[violation.rule] then
      table.insert(rules, violation.rule)
      seen[violation.rule] = true
    end
  end
  
  table.sort(rules)
  return table.concat(rules, ",")
end

-- Check if any violation explicitly blocks
local function should_block(violations)
  for _, violation in ipairs(violations) do
    if violation.blocked then
      return true
    end
  end
  return false
end

-- Calculate combo bonus when violations span multiple risk dimensions
-- Returns flat bonus points (not a multiplier, to keep math predictable)
local function calculate_combo_bonus(violations)
  local has_velocity   = false  -- frequency/count-based rules: 3.1.1-1, 3.1.1-5
  local has_diversity  = false  -- multi-recipient / multi-merchant: 3.1.1-2
  local has_amount     = false  -- amount anomaly rules: 3.1.1-7..10
  local has_geo        = false  -- geo / device rules: 3.1.1-11..14
  local has_behavioral = false  -- time / pattern rules: 3.1.1-3, 3.1.1-4, 3.1.1-6

  for _, v in ipairs(violations) do
    local r = v.rule or ""
    if r == "3.1.1-1" or r == "3.1.1-5" then
      has_velocity = true
    elseif r == "3.1.1-2" then
      has_diversity = true
    elseif r >= "3.1.1-7" and r <= "3.1.1-10" then
      has_amount = true
    elseif r >= "3.1.1-11" and r <= "3.1.1-14" then
      has_geo = true
    elseif r == "3.1.1-3" or r == "3.1.1-4" or r == "3.1.1-6" or r == "3.1.1-9" then
      has_behavioral = true
    end
  end

  -- Count how many distinct risk dimensions fired
  local active = 0
  if has_velocity   then active = active + 1 end
  if has_diversity  then active = active + 1 end
  if has_amount     then active = active + 1 end
  if has_geo        then active = active + 1 end
  if has_behavioral then active = active + 1 end

  -- Award bonus only when 2+ dimensions fire together
  -- 2 dimensions → +10 pts,  3 → +20,  4+ → +30
  if active >= 4 then
    return 30
  elseif active == 3 then
    return 20
  elseif active == 2 then
    return 10
  end
  return 0
end

-- Calculate total risk score from violations
local function calculate_total_score(violations)
  local total = 0
  local rule_scores = {}

  for _, violation in ipairs(violations) do
    if violation.score then
      total = total + violation.score

      if violation.rule then
        rule_scores[violation.rule] = violation.score
      end
    end
  end

  -- Add combo bonus for multi-dimension attacks
  local combo_bonus = calculate_combo_bonus(violations)
  if combo_bonus > 0 then
    total = total + combo_bonus
    -- Record it so it appears in the response
    rule_scores["combo_bonus"] = combo_bonus
  end

  -- Cap at 100
  if total > 100 then
    total = 100
  end

  return total, rule_scores
end

-- Build detailed violation summary
local function build_violation_summary(violations)
  local summary = {}
  
  for _, violation in ipairs(violations) do
    local entry = {
      rule = violation.rule,
      score = violation.score,
      description = violation.description,
      blocked = violation.blocked or false,
      severity = violation.severity or "unknown",
      timestamp = os.time()
    }
    
    -- Add rule-specific metadata
    if violation.metadata then
      entry.metadata = violation.metadata
    end
    
    table.insert(summary, entry)
  end
  
  return summary
end

-- Get rule category from rule ID (e.g., "3.1.1-2" -> "account_services")
local function get_rule_category(rule_id)
  if not rule_id then
    return "unknown"
  end
  
  if string.match(rule_id, "^3%.1%.1") then
    return "account_services"
  elseif string.match(rule_id, "^3%.1%.2") then
    return "pos_services"
  elseif string.match(rule_id, "^3%.1%.3") then
    return "transfer_services"
  elseif string.match(rule_id, "^3%.1%.4") then
    return "mobile_services"
  elseif string.match(rule_id, "^3%.2") then
    return "api_security"
  end
  
  return "unknown"
end

-- Categorize violations by type
local function categorize_violations(violations)
  local categories = {
    account_services = {},
    pos_services = {},
    transfer_services = {},
    mobile_services = {},
    api_security = {},
    unknown = {}
  }
  
  for _, violation in ipairs(violations) do
    local category = get_rule_category(violation.rule)
    table.insert(categories[category], violation)
  end
  
  -- Remove empty categories
  local result = {}
  for cat, vlist in pairs(categories) do
    if #vlist > 0 then
      result[cat] = vlist
    end
  end
  
  return result
end

-- Calculate risk score with all metadata
function _M.calculate_risk(conf, violations, transaction)
  -- Handle no violations case
  if not violations or #violations == 0 then
    return {
      total_score = 0,
      risk_level = RISK_LEVELS.LOW,
      blocked = false,
      rules_triggered = "",
      violation_count = 0,
      violation_summary = {},
      categories = {},
      reference = nil,
      timestamp = os.time(),
      transaction_id = transaction.transaction_id or "unknown"
    }
  end
  
  -- Calculate total score
  local total_score, rule_scores = calculate_total_score(violations)
  
  -- Determine if should block
  local blocked = should_block(violations) or 
                  total_score >= (conf.thresholds.block_score or 70)
  
  -- Get risk level
  local risk_level = get_risk_level(total_score, conf)
  
  -- If determined to be high risk, ensure blocked
  if risk_level == RISK_LEVELS.HIGH then
    blocked = true
  end
  
  -- Aggregate rule IDs
  local rules_triggered = aggregate_rules(violations)
  
  -- Build detailed summary
  local violation_summary = build_violation_summary(violations)
  
  -- Categorize violations
  local categories = categorize_violations(violations)
  
  -- Generate reference if blocked
  local reference = blocked and generate_reference() or nil
  
  -- Build result
  local result = {
    total_score = total_score,
    risk_level = risk_level,
    blocked = blocked,
    rules_triggered = rules_triggered,
    violation_count = #violations,
    violation_summary = violation_summary,
    rule_scores = rule_scores,
    categories = categories,
    reference = reference,
    timestamp = os.time(),
    transaction_id = transaction.transaction_id or "unknown",
    user_id = transaction.user_id,
    amount = transaction.amount,
    transaction_type = transaction.transaction_type
  }
  
  return result
end

-- Calculate severity weight for a rule type
function _M.get_severity_weight(severity, use_max)
  local weights = SEVERITY_WEIGHTS[string.upper(severity)]
  if not weights then
    return 10  -- Default to low
  end
  
  return use_max and weights.max or weights.min
end

-- Validate risk score calculation
function _M.validate_score(score)
  if type(score) ~= "number" then
    return false, "Score must be a number"
  end
  
  if score < 0 or score > 100 then
    return false, "Score must be between 0 and 100"
  end
  
  return true, nil
end

-- Get risk statistics for monitoring
function _M.get_risk_statistics(violations)
  local stats = {
    total_violations = #violations,
    critical_count = 0,
    high_count = 0,
    medium_count = 0,
    low_count = 0,
    blocked_count = 0,
    categories = {}
  }
  
  for _, violation in ipairs(violations) do
    -- Count by severity
    local severity = string.upper(violation.severity or "LOW")
    if severity == "CRITICAL" then
      stats.critical_count = stats.critical_count + 1
    elseif severity == "HIGH" then
      stats.high_count = stats.high_count + 1
    elseif severity == "MEDIUM" then
      stats.medium_count = stats.medium_count + 1
    else
      stats.low_count = stats.low_count + 1
    end
    
    -- Count blocked
    if violation.blocked then
      stats.blocked_count = stats.blocked_count + 1
    end
    
    -- Count by category
    local category = get_rule_category(violation.rule)
    stats.categories[category] = (stats.categories[category] or 0) + 1
  end
  
  return stats
end

-- Export risk result to JSON (for logging)
function _M.to_json(risk_result)
  return cjson.encode(risk_result)
end

-- Create a human-readable summary
function _M.create_summary(risk_result)
  local lines = {
    string.format("Risk Score: %d/100", risk_result.total_score),
    string.format("Risk Level: %s", string.upper(risk_result.risk_level)),
    string.format("Status: %s", risk_result.blocked and "BLOCKED" or "ALLOWED"),
    string.format("Violations: %d", risk_result.violation_count)
  }
  
  if risk_result.rules_triggered and risk_result.rules_triggered ~= "" then
    table.insert(lines, string.format("Triggered Rules: %s", risk_result.rules_triggered))
  end
  
  if risk_result.reference then
    table.insert(lines, string.format("Reference: %s", risk_result.reference))
  end
  
  return table.concat(lines, " | ")
end

-- Helper: Calculate score adjustment based on transaction context
function _M.apply_context_adjustments(base_score, transaction)
  local adjusted_score = base_score
  
  -- Weekend transactions might be less suspicious for some business types
  if transaction.is_weekend and transaction.transaction_type == "pos" then
    -- Slight reduction for weekend POS transactions (normal behavior)
    adjusted_score = adjusted_score * 0.95
  end
  
  -- Late night transactions (22:00 - 06:00)
  local hour = transaction.transaction_hour
  if hour >= 22 or hour <= 6 then
    -- Small increase for unusual hours
    adjusted_score = adjusted_score * 1.1
  end
  
  -- New account transactions are more suspicious
  if transaction.account_age_days and transaction.account_age_days < 30 then
    adjusted_score = adjusted_score * 1.15
  end
  
  -- Young users (under 20) require more scrutiny
  if transaction.user_age and transaction.user_age < 20 then
    adjusted_score = adjusted_score * 1.1
  end
  
  -- Cap at 100
  return math.min(adjusted_score, 100)
end

return _M
