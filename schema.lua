-- Fraud Guard Configuration Schema

local typedefs = require "kong.db.schema.typedefs"

return {
  name = "fraud-guard",
  entity_checks = {
    -- review_score must be strictly below block_score so the two levels are distinct.
    { custom_entity_check = {
        field_sources = { "config" },
        fn = function(entity)
          local thresholds = entity.config and entity.config.thresholds
          if thresholds then
            local rs = thresholds.review_score
            local bs = thresholds.block_score
            if rs ~= nil and bs ~= nil and rs >= bs then
              return nil, "thresholds.review_score (" .. tostring(rs) ..
                          ") must be less than thresholds.block_score (" .. tostring(bs) .. ")"
            end
          end
          return true
        end
    }},
    -- Positive-only numeric thresholds
    { custom_entity_check = {
        field_sources = { "config" },
        fn = function(entity)
          local t = entity.config and entity.config.thresholds
          if not t then return true end
          local positive_fields = {
            "max_daily_recipients", "max_hourly_same_merchant",
            "max_transactions_2hours_same_merchant", "new_account_txn_limit",
            "new_account_amount_limit", "new_account_days_threshold",
            "young_user_age_threshold", "max_accounts_per_ip",
            "merchant_revenue_multiplier", "epin_card_txn_hour_limit",
            "epin_card_amount_hour_limit", "max_daily_transactions",
            "max_hourly_transactions", "max_daily_amount",
          }
          for _, field in ipairs(positive_fields) do
            if t[field] ~= nil and t[field] <= 0 then
              return nil, "thresholds." .. field .. " must be greater than 0"
            end
          end
          return true
        end
    }},
  },
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          -- Execution mode: shadow mode logs but doesn't block, enforce mode blocks
          { mode = { 
              type = "string", 
              default = "enforce",
              one_of = {"shadow", "enforce"}
          }},
          
          -- Fail mode: open allows on errors, closed blocks on errors
          { fail_mode = { 
              type = "string", 
              default = "open",
              one_of = {"open", "closed"}
          }},
          
          -- Rule category toggles (Section 3.1.1 - 3.1.4, 3.2)
          { enable_account_transfers = { type = "boolean", default = true }},    -- Section 3.1.1 (20 rules)
          { enable_pos_transactions = { type = "boolean", default = true }},      -- Section 3.1.2 (25 rules)
          { enable_bill_payments = { type = "boolean", default = true }},         -- Section 3.1.3 (10 rules)
          { enable_mobile_payments = { type = "boolean", default = true }},       -- Section 3.1.4 (2 groups)
          { enable_api_security = { type = "boolean", default = true }},          -- Section 3.2 (7 requirements)
          
          -- Risk score thresholds
          { thresholds = {
              type = "record",
              required = true,
              default = {},
              fields = {
                { block_score = { type = "number", default = 70, between = {0, 100} }},
                { review_score = { type = "number", default = 30, between = {0, 100} }},
                
                -- Section 3.1.1 thresholds
                { max_daily_recipients = { type = "number", default = 5 }},
                { max_hourly_same_merchant = { type = "number", default = 5 }},
                { max_transactions_2hours_same_merchant = { type = "number", default = 5 }},
                { new_account_txn_limit = { type = "number", default = 50 }},
                { new_account_amount_limit = { type = "number", default = 27500 }},
                { new_account_days_threshold = { type = "number", default = 30 }},
                { young_user_age_threshold = { type = "number", default = 20 }},
                { max_accounts_per_ip = { type = "number", default = 5 }},
                
                -- Section 3.1.2 thresholds
                { merchant_revenue_multiplier = { type = "number", default = 4 }},
                { epin_card_txn_hour_limit = { type = "number", default = 3 }},
                { epin_card_amount_hour_limit = { type = "number", default = 15000 }},
                
                -- Velocity thresholds
                { max_daily_transactions = { type = "number", default = 100 }},
                { max_hourly_transactions = { type = "number", default = 20 }},
                { max_daily_amount = { type = "number", default = 100000 }},
              }
          }},
          
          -- Redis configuration
          { redis = {
              type = "record",
              required = true,
              fields = {
                { host = { type = "string", required = true, default = "localhost" }},
                { port = { type = "number", required = true, default = 6379, between = {1, 65535} }},
                -- `referenceable = true` allows the password to be stored in Kong Vault
                -- (e.g. env:// or AWS Secrets Manager) instead of plain-text in the DB.
                -- Kong Enterprise users can additionally set `encrypted = true`.
                { password = { type = "string", required = false, referenceable = true }},
                { db = { type = "number", default = 0, between = {0, 15} }},
                { timeout = { type = "number", default = 1000 }},
                { connect_timeout = { type = "number", default = 500 }},
                { send_timeout = { type = "number", default = 1000 }},
                { read_timeout = { type = "number", default = 1000 }},
                { keepalive_pool_size = { type = "number", default = 30 }},
                { keepalive_idle_timeout = { type = "number", default = 60000 }},
              }
          }},
          
          -- Whitelists (bypass all rules)
          { whitelists = {
              type = "record",
              required = false,
              default = {},
              fields = {
                { user_ids = { type = "array", elements = { type = "string" }, default = {} }},
                { merchant_ids = { type = "array", elements = { type = "string" }, default = {} }},
                { ip_ranges = { type = "array", elements = { type = "string" }, default = {} }},
              }
          }},
          
          -- Trusted proxies for X-Forwarded-For validation
          { trusted_proxies = {
              type = "array",
              elements = { type = "string" },
              default = {},
              description = "CIDR ranges of trusted proxies for IP extraction"
          }},
          
          -- Performance settings
          { cache_ttl = { type = "number", default = 300, between = {1, 3600} }},
          { max_execution_time = { type = "number", default = 100, between = {10, 5000} }},
          
          -- Alert configuration
          { webhook_url = { type = "string", required = false }},
          -- Optional Bearer / API-key token sent as `Authorization: <value>`.
          -- Use Kong Vault (referenceable = true) to avoid storing secrets in plain text.
          { webhook_auth_header = { type = "string", required = false, referenceable = true }},
          { alert_on_block = { type = "boolean", default = true }},
          { alert_on_review = { type = "boolean", default = false }},
          
          -- Logging configuration
          { log_level = {
              type = "string",
              default = "info",
              one_of = {"debug", "info", "warn", "error"}
          }},
          { compliance_log_retention = { type = "number", default = 3650 }},  -- 10 years in days
          -- Per-deployment salt used for PII hashing (user_id, account_id, etc.).
          -- Store via Kong Vault (referenceable = true) so the value is never saved
          -- in plain text in the Kong database.  When omitted the logger falls back
          -- to a built-in default salt, which is acceptable for development but
          -- MUST be overridden in production.
          { pii_hash_salt = { type = "string", required = false, referenceable = true }},
          
          -- Sector average data (for merchant revenue anomaly detection)
          { sector_averages = {
              type = "record",
              required = false,
              default = {},
              fields = {
                { retail = { type = "number", default = 50000 }},
                { epin = { type = "number", default = 100000 }},
                { food = { type = "number", default = 30000 }},
                { services = { type = "number", default = 40000 }},
                { default = { type = "number", default = 50000 }},
              }
          }},
          
          -- Rule-specific configurations
          { suspicious_keywords = {
              type = "array",
              default = {
                "kumar", "kmr", "bahis", "bhs", "bet",
                "betting", "gambling", "kacak", "sanal bahis", "snl"
              },
              elements = { type = "string" }
          }},
          
          -- Feature toggles for specific rules
          { rule_toggles = {
              type = "record",
              default = {},
              fields = {
                { enable_keyword_detection = { type = "boolean", default = true }},
                { enable_velocity_checks = { type = "boolean", default = true }},
                { enable_merchant_anomaly = { type = "boolean", default = true }},
                { enable_geo_checks = { type = "boolean", default = true }},
                { enable_amount_analysis = { type = "boolean", default = true }},
              }
          }},
        }
    }}
  }
}
