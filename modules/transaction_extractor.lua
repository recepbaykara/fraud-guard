-- Transaction Extractor Module
-- Extracts and enriches transaction data from requests
-- Generates deterministic transaction IDs

local cjson = require "cjson.safe"
local uuid = require "resty.jit-uuid"

local _M = {}

-- init_worker must be called from the plugin's init_worker phase so each
-- worker process gets a unique seed (avoids duplicate UUIDs when workers fork).
function _M.init_worker()
  math.randomseed(ngx.now() * 1000 + (ngx.worker.id() + 1) * 997)
  uuid.seed()
end

-- UUID v4 pattern: xxxxxxxx-xxxx-4xxx-[89ab]xxx-xxxxxxxxxxxx
local UUID_PATTERN = "^%x%x%x%x%x%x%x%x%-%x%x%x%x%-4%x%x%x%-[89abAB]%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$"

-- Validate that a string looks like a safe UUID v4 (rejects path-traversal,
-- injection characters, and non-UUID correlation IDs supplied by clients).
local function is_valid_uuid(s)
  if not s or type(s) ~= "string" then return false end
  -- Length guard first (cheap)
  if #s ~= 36 then return false end
  return string.match(s, UUID_PATTERN) ~= nil
end

-- Generate a unique transaction ID.
-- Accepts client-supplied correlation headers ONLY when they are valid UUID v4
-- values; otherwise a fresh UUID is generated to prevent injection / spoofing.
function _M.generate_transaction_id()
  local headers = kong.request.get_headers()

  -- Check for existing correlation/request ID headers (in priority order)
  local candidate = headers["x-request-id"]
                 or headers["x-correlation-id"]
                 or headers["x-transaction-id"]

  if candidate and is_valid_uuid(candidate) then
    return candidate
  end

  if candidate and candidate ~= "" then
    -- Log that we rejected the client-supplied value so operators are aware
    kong.log.debug("Ignoring non-UUID correlation header value; generating new ID")
  end

  -- Generate new UUID v4 (thread-safe, seeded per-worker)
  return uuid()
end

-- Extract transaction data from request
function _M.extract_transaction_data(conf, client_ip)
  local body_data, err = kong.request.get_body()
  if err then
    kong.log.err("Failed to parse request body: ", err)
    return nil, "Invalid request body"
  end

  local headers = kong.request.get_headers()
  
  -- Generate or extract transaction ID
  local transaction_id = _M.generate_transaction_id()
  
  -- Extract required fields
  local transaction = {
    -- Core identifiers
    transaction_id = transaction_id,
    user_id = body_data and body_data.user_id or headers["x-user-id"],
    account_id = body_data and body_data.account_id,

    -- Transaction details
    transaction_type = body_data and body_data.transaction_type,
    amount = math.max(0, tonumber(body_data and body_data.amount or 0) or 0),
    currency = body_data and body_data.currency or "TRY",
    description = body_data and body_data.description or "",
    status = body_data and body_data.status,  -- "success", "failed", etc.

    -- Parties involved
    merchant_id = body_data and body_data.merchant_id,
    merchant_category = body_data and body_data.merchant_category,
    merchant_country = body_data and body_data.merchant_country,
    recipient_id = body_data and body_data.recipient_id,
    recipient_country = body_data and body_data.recipient_country,
    biller_id = body_data and body_data.biller_id,

    -- Network context
    ip_address = client_ip,
    device_id = body_data and body_data.device_id or headers["x-device-id"],
    device_fingerprint = body_data and body_data.device_fingerprint or headers["x-device-fingerprint"],
    device_location = body_data and body_data.device_location or headers["x-device-location"],
    user_agent = headers["user-agent"],

    -- User context
    user_age = tonumber(body_data and body_data.user_age or 0),
    account_age_days = tonumber(body_data and body_data.account_age_days or 0),

    -- Payment context
    card_bin = body_data and body_data.card_bin,
    payment_method = body_data and body_data.payment_method,
    auth_method = body_data and body_data.auth_method or headers["x-auth-method"],

    -- Mobile / device security context
    device_security_status = body_data and body_data.device_security_status,
    app_version = body_data and body_data.app_version or headers["x-app-version"],
    biometric_enabled = body_data and body_data.biometric_enabled,
    biometric_used = body_data and body_data.biometric_used,
    sim_changed_recently = body_data and body_data.sim_changed_recently,
    hours_since_sim_change = tonumber(body_data and body_data.hours_since_sim_change or 0),
    password_changed_at = tonumber(body_data and body_data.password_changed_at or 0),

    -- Temporal context
    timestamp = os.time(),
    transaction_hour = tonumber(os.date("%H")),
    is_weekend = (tonumber(os.date("%w")) == 0 or tonumber(os.date("%w")) == 6),

    -- Request context
    request_path = kong.request.get_path(),
    request_method = kong.request.get_method(),

    -- Metadata
    extracted_at = ngx.now(),
  }

  -- Validate required fields
  if not transaction.user_id then
    return nil, "Missing required field: user_id"
  end

  return transaction, nil
end

-- Enrich transaction with Redis state (velocity, history, etc.)
function _M.enrich_from_redis(transaction, redis_client, conf)
  if not redis_client then
    return transaction
  end
  
  -- This can be extended to pre-fetch common Redis data
  -- For now, we'll keep it simple and let individual rules fetch what they need
  
  return transaction
end

-- Sanitize transaction data for logging (remove sensitive fields)
function _M.sanitize_for_logging(transaction)
  local sanitized = {}
  
  for k, v in pairs(transaction) do
    -- Mask sensitive fields
    if k == "card_bin" then
      sanitized[k] = v and string.sub(v, 1, 2) .. "****" or nil
    elseif k == "account_id" then
      sanitized[k] = v and "***" .. string.sub(v, -4) or nil
    else
      sanitized[k] = v
    end
  end
  
  return sanitized
end

return _M
