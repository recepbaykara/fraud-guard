-- Fraud Guard Kong Plugin Handler
-- Production-hardened fraud detection with security best practices
-- Implements 62 risk detection rules
-- Sections: 3.1.1 (20), 3.1.2 (25), 3.1.3 (10), 3.1.4 (2), 3.2 (7)

local cjson = require "cjson.safe"
local http = require "resty.http"
local redis_adapter = require "kong.plugins.fraud-guard.storage.redis_adapter"
local scorer = require "kong.plugins.fraud-guard.utils.scorer"
local logger = require "kong.plugins.fraud-guard.utils.logger"

-- New security modules
local ip_validator = require "kong.plugins.fraud-guard.modules.ip_validator"
local transaction_extractor = require "kong.plugins.fraud-guard.modules.transaction_extractor"
local execution_mode = require "kong.plugins.fraud-guard.modules.execution_mode"
local fail_mode = require "kong.plugins.fraud-guard.modules.fail_mode"
local rule_engine = require "kong.plugins.fraud-guard.modules.rule_engine"
local cache = require "kong.plugins.fraud-guard.storage.cache"

-- Rule modules
local account_rules = require "kong.plugins.fraud-guard.rules.account_rules"
local pos_rules = require "kong.plugins.fraud-guard.rules.pos_rules"
local transfer_rules = require "kong.plugins.fraud-guard.rules.transfer_rules"
local mobile_rules = require "kong.plugins.fraud-guard.rules.mobile_rules"
local api_security_rules = require "kong.plugins.fraud-guard.rules.api_security_rules"

local FraudGuardHandler = {}

FraudGuardHandler.PRIORITY = 1000
-- Version loaded from VERSION file at runtime
FraudGuardHandler.VERSION = "1.0.10"

-- Extract transaction data from request
local function extract_transaction_data(conf)
  local body_data, err = kong.request.get_body()
  if err then
    kong.log.err("Failed to parse request body: ", err)
    return nil, "Invalid request body"
  end

  local headers = kong.request.get_headers()
  local client_ip = kong.client.get_forwarded_ip()
  
  -- Extract required fields
  local transaction = {
    user_id = body_data and body_data.user_id or headers["x-user-id"],
    account_id = body_data and body_data.account_id,
    transaction_type = body_data and body_data.transaction_type,
    amount = math.max(0, tonumber(body_data and body_data.amount or 0) or 0),
    currency = body_data and body_data.currency or "TRY",
    merchant_id = body_data and body_data.merchant_id,
    recipient_id = body_data and body_data.recipient_id,
    timestamp = os.time(),
    ip_address = client_ip,
    device_id = headers["x-device-id"],
    user_age = tonumber(body_data and body_data.user_age or 0),
    account_age_days = tonumber(body_data and body_data.account_age_days or 0),
    description = body_data and body_data.description or "",
    card_bin = body_data and body_data.card_bin,
    transaction_hour = tonumber(os.date("%H")),
    is_weekend = (tonumber(os.date("%w")) == 0 or tonumber(os.date("%w")) == 6),
    request_path = kong.request.get_path(),
    request_method = kong.request.get_method()
  }

  -- Validate required fields
  if not transaction.user_id then
    return nil, "Missing user_id"
  end

  return transaction, nil
end

-- Check if entity is whitelisted
local function is_whitelisted(conf, transaction)
  -- Check user whitelist
  if conf.whitelists and conf.whitelists.user_ids then
    for _, whitelisted_id in ipairs(conf.whitelists.user_ids) do
      if transaction.user_id == whitelisted_id then
        return true, "user"
      end
    end
  end

  -- Check merchant whitelist
  if conf.whitelists and conf.whitelists.merchant_ids and transaction.merchant_id then
    for _, whitelisted_id in ipairs(conf.whitelists.merchant_ids) do
      if transaction.merchant_id == whitelisted_id then
        return true, "merchant"
      end
    end
  end
  
  -- Check IP whitelist using secure CIDR validation
  if conf.whitelists and conf.whitelists.ip_ranges and #conf.whitelists.ip_ranges > 0 then
    local is_whitelisted, err = ip_validator.is_ip_whitelisted(
      transaction.ip_address, 
      conf.whitelists.ip_ranges
    )
    
    if err then
      kong.log.warn("IP whitelist validation error: ", err)
    elseif is_whitelisted then
      return true, "ip"
    end
  end
  
  return false
end

-- Execute all rule checks
local function execute_rule_checks(conf, transaction, redis_client)
  local rule_modules_map = {}
  
  -- API Security checks (always run first - can hard block)
  if conf.enable_api_security then
    rule_modules_map["api_security"] = api_security_rules
  end
  
  -- Section 3.1.1: Payment Account Services (20 rules)
  if conf.enable_account_transfers then
    rule_modules_map["account_rules"] = account_rules
  end
  
  -- Section 3.1.2: POS/Virtual POS Services (25 rules)
  if conf.enable_pos_transactions then
    rule_modules_map["pos_rules"] = pos_rules
  end
  
  -- Section 3.1.3: Bill Payment and Money Transfer (10 rules)
  if conf.enable_bill_payments then
    rule_modules_map["transfer_rules"] = transfer_rules
  end
  
  -- Section 3.1.4: Mobile Payment Services (2 rule groups)
  if conf.enable_mobile_payments then
    rule_modules_map["mobile_rules"] = mobile_rules
  end
  
  -- Execute all enabled rule modules
  local violations, execution_time, module_times = rule_engine.execute_rules(
    conf, 
    transaction, 
    redis_client, 
    rule_modules_map
  )
  
  if not violations then
    return nil, execution_time
  end
  
  -- Check for critical violations (immediate block)
  local has_critical, critical_violation = rule_engine.has_critical_violations(violations)
  if has_critical then
    kong.log.warn("Critical violation detected: ", critical_violation.description)
  end
  
  return violations, execution_time
end

-- Validate webhook URL against SSRF risks.
-- Returns true only for https:// URLs pointing at public, non-internal hosts.
-- Blocks: RFC-1918 IPv4, loopback IPv4, IPv6 loopback/link-local,
--         octal/hex encoded IPs, and well-known internal hostnames.
local function is_safe_webhook_url(url)
  if not url then
    return false, "no url"
  end

  -- Require HTTPS scheme
  if not string.match(url, "^https://") then
    return false, "only https:// scheme is allowed"
  end

  -- Extract host portion (strip scheme, path, port, brackets for IPv6)
  local host = string.match(url, "^https://(%[?[^/%]?#]+%]?)")
  if not host then
    host = string.match(url, "^https://([^/:?#]+)")
  end
  if not host then
    return false, "could not parse host"
  end

  -- Normalise: strip surrounding brackets from IPv6 literals like [::1]
  local ipv6_literal = string.match(host, "^%[(.+)%]$")
  if ipv6_literal then
    -- Block any IPv6 loopback or link-local address
    -- ::1  (loopback)
    if ipv6_literal == "::1" then
      return false, "IPv6 loopback address (::1)"
    end
    -- fe80::/10  (link-local)
    local first16 = string.match(ipv6_literal, "^[Ff][Ee]([89aAbB%x])")
    if first16 then
      return false, "IPv6 link-local address (fe80::/10)"
    end
    -- fc00::/7  (unique-local / RFC-4193)
    local fc_fd = string.match(string.lower(ipv6_literal), "^f[cd]")
    if fc_fd then
      return false, "IPv6 unique-local address (fc00::/7)"
    end
    -- All other IPv6 literals are allowed
    return true, nil
  end

  -- Block well-known internal hostnames (case-insensitive)
  local host_lower = string.lower(host)
  local blocked_hostnames = {
    "localhost", "ip6-localhost", "ip6-loopback",
    "metadata.google.internal",   -- GCP metadata
    "169.254.169.254",            -- AWS/Azure/GCP metadata (hostname form)
    "100.100.100.200",            -- Alibaba Cloud metadata
  }
  for _, blocked in ipairs(blocked_hostnames) do
    if host_lower == blocked then
      return false, "blocked internal hostname (" .. blocked .. ")"
    end
  end

  -- Block hostnames ending in .local, .internal, .localhost, .localdomain
  local internal_suffixes = { "%.local$", "%.internal$", "%.localhost$", "%.localdomain$" }
  for _, suffix in ipairs(internal_suffixes) do
    if string.match(host_lower, suffix) then
      return false, "internal hostname suffix: " .. host
    end
  end

  -- Parse dotted-decimal IPv4 (including octal/hex detection)
  local oct1, oct2, oct3, oct4 = string.match(host, "^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if oct1 then
    -- Reject octal notation (leading zero) e.g. 0177.0.0.1
    if string.match(host, "^0") or
       string.match(host, "%.0%d") then
      return false, "octal IP notation is not allowed"
    end

    local a, b = tonumber(oct1), tonumber(oct2)

    -- 10.0.0.0/8
    if a == 10 then
      return false, "private IP range (10.x.x.x)"
    end
    -- 127.0.0.0/8  (loopback)
    if a == 127 then
      return false, "loopback address (127.x.x.x)"
    end
    -- 169.254.0.0/16  (link-local / cloud metadata)
    if a == 169 and b == 254 then
      return false, "link-local address (169.254.x.x)"
    end
    -- 172.16.0.0/12  (172.16 – 172.31)
    if a == 172 and b >= 16 and b <= 31 then
      return false, "private IP range (172.16-31.x.x)"
    end
    -- 192.168.0.0/16
    if a == 192 and b == 168 then
      return false, "private IP range (192.168.x.x)"
    end
    -- 0.0.0.0/8  (unspecified)
    if a == 0 then
      return false, "unspecified address (0.x.x.x)"
    end
    -- 100.64.0.0/10  (CGNAT / shared address space)
    if a == 100 and b >= 64 and b <= 127 then
      return false, "CGNAT shared address (100.64-127.x.x)"
    end
  end

  -- Block pure-hex IP notation e.g. 0x7f000001
  if string.match(host, "^0[xX]%x+$") then
    return false, "hexadecimal IP notation is not allowed"
  end

  return true, nil
end

-- Send alert webhook
local function send_alert(conf, transaction, risk_result)
  -- Preserve existing early-return behaviour when no URL is configured
  if not conf.webhook_url then
    return
  end

  -- SSRF guard: validate URL before use
  local safe, reason = is_safe_webhook_url(conf.webhook_url)
  if not safe then
    kong.log.warn("Webhook skipped — unsafe URL (", reason, "): ", conf.webhook_url)
    return
  end

  if (risk_result.blocked and conf.alert_on_block) or
     (risk_result.risk_level == "medium" and conf.alert_on_review) then

    local alert_data = {
      event = risk_result.blocked and "transaction_blocked" or "transaction_flagged",
      timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
      transaction_id = transaction.transaction_id or "unknown",
      user_id = transaction.user_id,
      risk_score = risk_result.total_score,
      risk_level = risk_result.risk_level,
      triggered_rules = risk_result.rules_triggered,
      reference = risk_result.reference,
      mode = conf.mode or "enforce"
    }

    -- Capture validated URL and auth header in upvalues so the timer closure
    -- does not hold a reference to the entire conf table.
    local webhook_url = conf.webhook_url
    local webhook_auth = conf.webhook_auth_header  -- nil when not configured

    -- Non-blocking webhook call
    ngx.timer.at(0, function()
      local httpc = http.new()
      httpc:set_timeout(5000)

      local req_headers = { ["Content-Type"] = "application/json" }
      if webhook_auth and webhook_auth ~= "" then
        req_headers["Authorization"] = webhook_auth
      end

      local res, err = httpc:request_uri(webhook_url, {
        method = "POST",
        body = cjson.encode(alert_data),
        headers = req_headers,
        ssl_verify = true,  -- Verify TLS certificate (prevents MITM)
      })

      if err then
        kong.log.warn("Failed to send alert webhook: ", err)
      elseif res and res.status >= 400 then
        kong.log.warn("Alert webhook returned HTTP ", res.status)
      end
    end)
  end
end

-- Worker initialization — seed UUID generator per-worker to avoid duplicate transaction IDs
-- and initialise the cache shared-dict (emits a startup warning if the dict is missing).
function FraudGuardHandler:init_worker()
  transaction_extractor.init_worker()
  -- conf is not available at init_worker time; use the module default (300 s).
  -- Individual plugin instances will call cache.init(conf.cache_ttl) on first access.
  cache.init()
end

-- Main access handler
function FraudGuardHandler:access(conf)
  local start_time = ngx.now()
  
  -- Extract real client IP with proper X-Forwarded-For handling
  local client_ip, ip_err = ip_validator.get_real_client_ip(conf.trusted_proxies or {})
  if ip_err then
    kong.log.warn("IP extraction warning: ", ip_err)
    client_ip = kong.client.get_forwarded_ip()
  end
  
  -- Extract transaction data with transaction ID generation
  local transaction, err = transaction_extractor.extract_transaction_data(conf, client_ip)
  if err then
    kong.log.err("Transaction extraction failed: ", err)
    return fail_mode.handle_extraction_failure(conf, err)
  end
  
  -- Log transaction start
  kong.log.info(cjson.encode({
    event = "transaction_start",
    transaction_id = transaction.transaction_id,
    user_id = transaction.user_id,
    amount = transaction.amount,
    ip = client_ip,
    timestamp = os.time()
  }))
  
  -- Check whitelist
  local whitelisted, whitelist_type = is_whitelisted(conf, transaction)
  if whitelisted then
    kong.log.info(cjson.encode({
      event = "transaction_whitelisted",
      transaction_id = transaction.transaction_id,
      whitelist_type = whitelist_type,
      user_id = transaction.user_id
    }))
    
    kong.response.set_header("X-Fraud-Score", "0")
    kong.response.set_header("X-Risk-Level", "whitelisted")
    kong.response.set_header("X-Transaction-Id", transaction.transaction_id)
    kong.response.set_header("X-Fraud-Mode", conf.mode or "enforce")
    return
  end
  
  -- Initialize Redis connection
  local redis_client, redis_err = redis_adapter.connect(conf.redis)
  if redis_err then
    kong.log.err("Redis connection failed: ", redis_err)
    return fail_mode.handle_redis_failure(conf, transaction, redis_err)
  end
  
  -- Execute rule checks
  local violations, execution_time = execute_rule_checks(conf, transaction, redis_client)
  
  -- Close Redis connection
  redis_adapter.close(redis_client, conf.redis)
  
  -- Handle rule execution failure
  if not violations then
    kong.log.err("Rule execution failed")
    return fail_mode.handle_rule_failure(conf, transaction, "rule_engine", "Rule execution returned nil")
  end
  
  -- Calculate risk score
  local risk_result = scorer.calculate_risk(conf, violations, transaction)
  
  -- Add execution time to result
  risk_result.execution_time_ms = execution_time
  
  -- Check performance threshold
  local total_time = (ngx.now() - start_time) * 1000
  local max_exec_time = conf.max_execution_ms or conf.max_execution_time or 100
  if total_time > max_exec_time then
    kong.log.warn(cjson.encode({
      event = "slow_execution",
      transaction_id = transaction.transaction_id,
      execution_time_ms = total_time,
      threshold_ms = max_exec_time,
      rule_execution_ms = execution_time
    }))
  end
  
  -- Log transaction result (structured JSON)
  logger.log_transaction(conf, transaction, risk_result)
  
  -- Set response headers
  kong.response.set_header("X-Fraud-Score", tostring(risk_result.total_score))
  kong.response.set_header("X-Triggered-Rules", risk_result.rules_triggered)
  kong.response.set_header("X-Risk-Level", risk_result.risk_level)
  kong.response.set_header("X-Transaction-Id", transaction.transaction_id)
  kong.response.set_header("X-Execution-Time-Ms", string.format("%.2f", total_time))
  
  if risk_result.risk_level == "medium" then
    kong.response.set_header("X-Review-Required", "true")
  end
  
  -- Send alert if needed
  send_alert(conf, transaction, risk_result)
  
  -- Handle blocking with execution mode awareness
  if risk_result.blocked then
    return execution_mode.handle_block(conf, transaction, risk_result)
  end
  
  -- Add mode-specific headers even when not blocking
  execution_mode.add_mode_headers(conf, risk_result)
  
  kong.log.info(cjson.encode({
    event = "transaction_processed",
    transaction_id = transaction.transaction_id,
    user_id = transaction.user_id,
    risk_score = risk_result.total_score,
    risk_level = risk_result.risk_level,
    mode = conf.mode or "enforce",
    execution_time_ms = string.format("%.2f", total_time)
  }))
end

return FraudGuardHandler
