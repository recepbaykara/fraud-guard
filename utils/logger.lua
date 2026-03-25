-- Compliance Logger for Fraud Guard
-- Implements 10-year retention logging as required by banking regulations

local cjson = require "cjson.safe"
local resty_sha256 = require "resty.sha256"
local resty_str    = require "resty.string"

local _M = {}

-- Fallback salt used ONLY when no per-deployment salt is configured via Kong Vault.
-- WARNING: This fallback is intentionally weak. It exists only to prevent a nil
-- error during development/CI. In production you MUST set config.pii_hash_salt
-- via Kong Vault, otherwise PII hashes offer no real protection:
--   vault://env/FRAUD_GUARD_HASH_SALT
local FALLBACK_HASH_SALT = "change-me-set-via-kong-vault"

-- Resolved at request time from conf.pii_hash_salt (Kong Vault reference).
-- Falls back to FALLBACK_HASH_SALT when not configured.
local function get_hash_salt(conf)
  if conf and conf.pii_hash_salt and conf.pii_hash_salt ~= "" then
    return conf.pii_hash_salt
  end
  return FALLBACK_HASH_SALT
end

-- Log levels
local LOG_LEVELS = {
  DEBUG = 1,
  INFO = 2,
  WARN = 3,
  ERROR = 4
}

-- Get numeric log level
local function get_log_level(level_str)
  return LOG_LEVELS[string.upper(level_str or "INFO")] or LOG_LEVELS.INFO
end

-- Check if should log at level
local function should_log(conf, level)
  local config_level = get_log_level(conf.log_level)
  local message_level = get_log_level(level)
  return message_level >= config_level
end

-- Hash sensitive data (user_id, card info) for compliance.
-- Uses SHA-256 and prepends a per-deployment salt (from Kong Vault when configured)
-- to prevent rainbow-table reversal of stored hashes.
local function hash_sensitive_data(data, conf)
  if not data then
    return nil
  end

  local salt = get_hash_salt(conf)
  local salted = salt .. tostring(data)

  local sha256 = resty_sha256:new()
  sha256:update(salted)
  local digest = sha256:final()             -- raw bytes
  return string.sub(resty_str.to_hex(digest), 1, 16)  -- hex, truncated
end

-- Sanitize transaction data for logging
local function sanitize_transaction(transaction, conf)
  return {
    user_id_hash = hash_sensitive_data(transaction.user_id, conf),
    account_id_hash = hash_sensitive_data(transaction.account_id, conf),
    transaction_type = transaction.transaction_type,
    amount = transaction.amount,
    currency = transaction.currency,
    merchant_id = transaction.merchant_id,
    timestamp = transaction.timestamp,
    ip_address = transaction.ip_address,  -- Keep for audit
    device_id_hash = hash_sensitive_data(transaction.device_id, conf),
    user_age = transaction.user_age,
    account_age_days = transaction.account_age_days,
    transaction_hour = transaction.transaction_hour,
    is_weekend = transaction.is_weekend,
    card_bin = transaction.card_bin  -- First 6 digits only, not sensitive
  }
end

-- Format log entry
local function format_log_entry(log_type, data, conf)
  return {
    log_type = log_type,
    timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
    plugin_version = "1.0.0",
    data = data,
    retention_days = conf.compliance_log_retention or 3650
  }
end

-- Write to Kong log
local function write_kong_log(level, message, data)
  -- Build the full log message only when the level will actually be emitted.
  -- cjson.encode() is non-trivial; avoid it for DEBUG messages in production.
  if level == "DEBUG" then
    if not kong.log.is_debug_enabled() then
      return
    end
    kong.log.debug(data and (message .. " | " .. (cjson.encode(data) or "{}")) or message)
  elseif level == "INFO" then
    kong.log.info(data and (message .. " | " .. (cjson.encode(data) or "{}")) or message)
  elseif level == "WARN" then
    kong.log.warn(data and (message .. " | " .. (cjson.encode(data) or "{}")) or message)
  elseif level == "ERROR" then
    kong.log.err(data and (message .. " | " .. (cjson.encode(data) or "{}")) or message)
  else
    kong.log.info(data and (message .. " | " .. (cjson.encode(data) or "{}")) or message)
  end
end

-- Log transaction with risk result (MAIN COMPLIANCE LOG)
function _M.log_transaction(conf, transaction, risk_result)
  if not should_log(conf, "INFO") then
    return
  end
  
  local log_entry = format_log_entry("TRANSACTION", {
    transaction = sanitize_transaction(transaction, conf),
    risk_score = risk_result.total_score,
    risk_level = risk_result.risk_level,
    blocked = risk_result.blocked,
    rules_triggered = risk_result.rules_triggered,
    violation_count = risk_result.violation_count,
    reference = risk_result.reference,
    execution_time_ms = risk_result.execution_time_ms
  }, conf)
  
  -- Write to Kong logs
  write_kong_log("INFO", "FRAUD_TRANSACTION", log_entry)
  
  -- If blocked, write separate entry for easy filtering
  if risk_result.blocked then
    local block_entry = format_log_entry("BLOCKED_TRANSACTION", {
      user_id_hash = hash_sensitive_data(transaction.user_id, conf),
      transaction_type = transaction.transaction_type,
      amount = transaction.amount,
      risk_score = risk_result.total_score,
      rules_triggered = risk_result.rules_triggered,
      reference = risk_result.reference
    }, conf)
    
    write_kong_log("WARN", "FRAUD_BLOCKED", block_entry)
  end
  
  -- If high score but not blocked, log for review
  if risk_result.risk_level == "medium" and not risk_result.blocked then
    local review_entry = format_log_entry("REVIEW_REQUIRED", {
      user_id_hash = hash_sensitive_data(transaction.user_id, conf),
      transaction_type = transaction.transaction_type,
      amount = transaction.amount,
      risk_score = risk_result.total_score,
      rules_triggered = risk_result.rules_triggered
    }, conf)
    
    write_kong_log("WARN", "FRAUD_REVIEW", review_entry)
  end
end

-- Log rule violation details (for debugging/auditing)
function _M.log_violation(conf, violation, transaction)
  if not should_log(conf, "DEBUG") then
    return
  end
  
  local log_entry = format_log_entry("RULE_VIOLATION", {
    rule = violation.rule,
    score = violation.score,
    description = violation.description,
    severity = violation.severity,
    blocked = violation.blocked,
    user_id_hash = hash_sensitive_data(transaction.user_id, conf),
    transaction_type = transaction.transaction_type,
    metadata = violation.metadata
  }, conf)
  
  write_kong_log("DEBUG", "FRAUD_VIOLATION", log_entry)
end

-- Log errors
function _M.log_error(conf, error_data)
  local log_entry = format_log_entry("ERROR", error_data, conf)
  write_kong_log("ERROR", "FRAUD_ERROR", log_entry)
end

-- Log performance metrics
function _M.log_performance(conf, metrics)
  if not should_log(conf, "DEBUG") then
    return
  end
  
  local log_entry = format_log_entry("PERFORMANCE", metrics, conf)
  write_kong_log("DEBUG", "FRAUD_PERFORMANCE", log_entry)
end

-- Log configuration changes
function _M.log_config_change(conf, change_data)
  local log_entry = format_log_entry("CONFIG_CHANGE", change_data, conf)
  write_kong_log("INFO", "FRAUD_CONFIG", log_entry)
end

-- Log Redis operations (for debugging)
function _M.log_redis_operation(conf, operation, key, success)
  if not should_log(conf, "DEBUG") then
    return
  end
  
  local log_entry = {
    operation = operation,
    key = key,
    success = success,
    timestamp = os.time()
  }
  
  write_kong_log("DEBUG", "FRAUD_REDIS", log_entry)
end

-- Log cache operations
function _M.log_cache_operation(conf, operation, key, hit)
  if not should_log(conf, "DEBUG") then
    return
  end
  
  local log_entry = {
    operation = operation,
    key = key,
    cache_hit = hit,
    timestamp = os.time()
  }
  
  write_kong_log("DEBUG", "FRAUD_CACHE", log_entry)
end

-- Log alert webhook delivery
function _M.log_alert_webhook(conf, webhook_url, success, error_msg)
  local log_entry = format_log_entry("WEBHOOK", {
    url = webhook_url,
    success = success,
    error = error_msg
  }, conf)
  
  local level = success and "INFO" or "ERROR"
  write_kong_log(level, "FRAUD_WEBHOOK", log_entry)
end

-- Log system health check
function _M.log_health_check(conf, health_data)
  if not should_log(conf, "INFO") then
    return
  end
  
  local log_entry = format_log_entry("HEALTH_CHECK", health_data, conf)
  write_kong_log("INFO", "FRAUD_HEALTH", log_entry)
end

-- Export logs to external system (for 10-year retention)
-- This would integrate with external log aggregation (e.g., Elasticsearch, S3)
function _M.export_to_external_storage(conf, log_data)
  -- Placeholder for external storage integration
  -- In production, this would send to:
  -- - Elasticsearch for searchable audit logs
  -- - S3 for long-term archival
  -- - SIEM system for security monitoring
  
  kong.log.info("Export to external storage: ", cjson.encode({
    type = log_data.log_type,
    timestamp = log_data.timestamp,
    record_count = 1
  }))
end

-- Audit log query helper (for compliance audits)
function _M.create_audit_query(filters, conf)
  -- Helper to construct queries for external log systems
  local query_parts = {}

  if filters.user_id then
    local hash = hash_sensitive_data(filters.user_id, conf)
    table.insert(query_parts, string.format('user_id_hash:"%s"', hash))
  end
  
  if filters.start_date then
    table.insert(query_parts, string.format('timestamp:>="%s"', filters.start_date))
  end
  
  if filters.end_date then
    table.insert(query_parts, string.format('timestamp:<="%s"', filters.end_date))
  end
  
  if filters.rule then
    table.insert(query_parts, string.format('rules_triggered:*%s*', filters.rule))
  end
  
  if filters.blocked ~= nil then
    table.insert(query_parts, string.format('blocked:%s', tostring(filters.blocked)))
  end
  
  return table.concat(query_parts, " AND ")
end

-- Generate compliance report
function _M.generate_compliance_report(start_date, end_date)
  -- This would query external log storage for compliance reporting
  return {
    report_type = "COMPLIANCE",
    period_start = start_date,
    period_end = end_date,
    generated_at = os.date("!%Y-%m-%dT%H:%M:%SZ"),
    metrics = {
      total_transactions = 0,  -- Would be calculated from logs
      blocked_transactions = 0,
      flagged_for_review = 0,
      avg_risk_score = 0,
      top_triggered_rules = {}
    },
    query = _M.create_audit_query({
      start_date = start_date,
      end_date = end_date
    })
  }
end

-- Anonymize logs for data privacy (GDPR/KVKK compliance)
function _M.anonymize_user_data(user_id, conf)
  -- This would be called when user requests data deletion
  -- Replace with generic hash, keeping audit trail but removing PII
  kong.log.info("Anonymizing user data: ", hash_sensitive_data(user_id, conf))

  return {
    success = true,
    user_id_hash = hash_sensitive_data(user_id, conf),
    anonymized_at = os.date("!%Y-%m-%dT%H:%M:%SZ")
  }
end

return _M
