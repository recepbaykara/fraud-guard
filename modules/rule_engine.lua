-- Rule Engine Module
-- Provides structured rule execution with deterministic results
-- Returns normalized rule violation objects

local cjson = require "cjson.safe"

local _M = {}

-- Rule violation structure
-- {
--   id = "POS-001",
--   category = "pos",
--   score = 30,
--   severity = "high",
--   description = "Multiple transactions to same merchant",
--   metadata = {...}
-- }

local SEVERITY_CRITICAL = "CRITICAL"
local SEVERITY_HIGH = "HIGH"
local SEVERITY_MEDIUM = "MEDIUM"
local SEVERITY_LOW = "LOW"

-- Map severity to score ranges
local SEVERITY_SCORES = {
  [SEVERITY_CRITICAL] = {min = 40, max = 50},
  [SEVERITY_HIGH] = {min = 25, max = 35},
  [SEVERITY_MEDIUM] = {min = 15, max = 20},
  [SEVERITY_LOW] = {min = 5, max = 10}
}

-- Create a normalized rule violation
function _M.create_violation(rule_id, category, score, severity, description, metadata)
  return {
    id = rule_id,
    category = category or "unknown",
    score = score or 0,
    severity = severity or SEVERITY_LOW,
    description = description or "",
    metadata = metadata or {},
    timestamp = os.time()
  }
end

-- Execute rule modules and aggregate results
function _M.execute_rules(conf, transaction, redis_client, rule_modules)
  local all_violations = {}
  local execution_times = {}
  local start_time = ngx.now()
  
  for module_name, rule_module in pairs(rule_modules) do
    local module_start = ngx.now()
    
    -- Protect against rule failures
    local ok, violations = pcall(rule_module.check, conf, transaction, redis_client)
    
    if not ok then
      kong.log.err("Rule module '", module_name, "' failed: ", violations)
      
      -- Handle rule failure based on fail mode
      local fail_mode = require "kong.plugins.fraud-guard.modules.fail_mode"
      local should_exit = fail_mode.handle_rule_failure(conf, transaction, module_name, violations)
      if should_exit then
        return nil, "Rule execution failed critically"
      end
      
      violations = {}
    end
    
    local module_time = (ngx.now() - module_start) * 1000
    execution_times[module_name] = module_time
    
    -- Add violations to aggregate list
    if violations and #violations > 0 then
      for _, v in ipairs(violations) do
        table.insert(all_violations, v)
      end
    end
    
    -- Log slow rule execution
    if module_time > 50 then
      kong.log.warn("Slow rule execution: ", module_name, " took ", 
                    string.format("%.2f", module_time), "ms")
    end
  end
  
  local total_time = (ngx.now() - start_time) * 1000
  
  return all_violations, total_time, execution_times
end

-- Sort violations by severity and score
function _M.sort_violations(violations)
  local severity_order = {
    CRITICAL = 1,
    HIGH = 2,
    MEDIUM = 3,
    LOW = 4
  }
  
  table.sort(violations, function(a, b)
    local a_order = severity_order[string.upper(a.severity or "")] or 999
    local b_order = severity_order[string.upper(b.severity or "")] or 999
    
    if a_order == b_order then
      return a.score > b.score
    end
    return a_order < b_order
  end)
  
  return violations
end

-- Aggregate violations into summary
function _M.aggregate_violations(violations)
  local by_category = {}
  local by_severity = {}
  local total_score = 0
  local rule_ids = {}
  
  for _, v in ipairs(violations) do
    -- Aggregate by category
    by_category[v.category] = (by_category[v.category] or 0) + 1
    
    -- Aggregate by severity
    by_severity[v.severity] = (by_severity[v.severity] or 0) + 1
    
    -- Sum scores
    total_score = total_score + v.score
    
    -- Collect rule IDs
    table.insert(rule_ids, v.id)
  end
  
  return {
    total_violations = #violations,
    total_score = total_score,
    by_category = by_category,
    by_severity = by_severity,
    rule_ids = rule_ids
  }
end

-- Check for critical violations that require immediate blocking
function _M.has_critical_violations(violations)
  for _, v in ipairs(violations) do
    if string.upper(v.severity or "") == SEVERITY_CRITICAL and v.score >= 40 then
      return true, v
    end
  end
  return false, nil
end

-- Filter violations by category
function _M.filter_by_category(violations, category)
  local filtered = {}
  for _, v in ipairs(violations) do
    if v.category == category then
      table.insert(filtered, v)
    end
  end
  return filtered
end

-- Get top N violations
function _M.get_top_violations(violations, n)
  local sorted = _M.sort_violations(violations)
  local top = {}
  
  for i = 1, math.min(n, #sorted) do
    table.insert(top, sorted[i])
  end
  
  return top
end

return _M
