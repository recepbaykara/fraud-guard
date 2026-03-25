-- Fraud Guard Test Suite
-- Run with: busted test_suite.lua

local handler = require("kong.plugins.fraud-guard.handler")
local cjson = require("cjson")

describe("Fraud Guard Plugin", function()
  local old_ngx, mock_conf

  before_each(function()
    -- Mock Kong context
    _G.kong = {
      request = {
        get_body = function() return {} end,
        get_headers = function() return {} end
      },
      response = {
        set_header = function() end,
        exit = function() end
      },
      log = {
        err = function() end,
        warn = function() end,
        info = function() end
      },
      service = {
        request = {
          set_header = function() end
        }
      }
    }

    -- Mock configuration
    mock_conf = {
      redis = {
        host = "localhost",
        port = 6379,
        password = "",
        database = 0,
        timeout = 2000,
        pool_size = 30,
        keepalive_ms = 60000
      },
      thresholds = {
        block_score = 70,
        review_score = 30,
        daily_transfer_limit = 50000,
        monthly_transfer_limit = 250000,
        daily_pos_limit = 20000,
        new_account_daily_limit = 27500,
        new_account_monthly_txn_limit = 50,
        hourly_epin_card_limit = 15000,
        hourly_epin_txn_limit = 3
      },
      enabled_categories = {
        "account_services",
        "pos_services",
        "transfer_services",
        "mobile_services",
        "api_security"
      },
      whitelists = {
        user_ids = {},
        merchant_ids = {},
        ip_ranges = {"127.0.0.0/8"}
      },
      weights = {
        critical = 45,
        high = 30,
        medium = 18,
        low = 7
      },
      sector_averages = {
        retail = 500,
        grocery = 300,
        restaurant = 200,
        ecommerce = 800,
        default = 400
      }
    }
  end)

  describe("Configuration Schema", function()
    local schema = require("kong.plugins.fraud-guard.schema")

    it("validates correct configuration", function()
      local ok, err = schema.check_schema(mock_conf)
      assert.is_true(ok)
      assert.is_nil(err)
    end)

    it("rejects invalid redis host", function()
      mock_conf.redis.host = 12345
      local ok, err = schema.check_schema(mock_conf)
      assert.is_false(ok)
      assert.is_not_nil(err)
    end)

    it("rejects invalid threshold range", function()
      mock_conf.thresholds.block_score = 150
      local ok, err = schema.check_schema(mock_conf)
      assert.is_false(ok)
      assert.is_not_nil(err)
    end)
  end)

  describe("Risk Scorer", function()
    local scorer = require("kong.plugins.fraud-guard.utils.scorer")

    it("calculates risk score correctly", function()
      local violations = {
        {rule_id = "3.1.1-1", score = 30, severity = "high"},
        {rule_id = "3.1.1-2", score = 45, severity = "critical"}
      }
      local context = {account_age_days = 100}
      
      local score, level = scorer.calculate_risk(violations, context)
      assert.is_true(score >= 75)  -- 30 + 45 = 75
      assert.equals("high", level)
    end)

    it("applies new account multiplier", function()
      local violations = {
        {rule_id = "3.1.1-15", score = 25, severity = "high"}
      }
      local context = {account_age_days = 5}  -- New account
      
      local score, level = scorer.calculate_risk(violations, context)
      assert.is_true(score > 25)  -- Should be multiplied
    end)

    it("caps risk score at 100", function()
      local violations = {
        {rule_id = "3.1.1-1", score = 50, severity = "critical"},
        {rule_id = "3.1.1-2", score = 50, severity = "critical"},
        {rule_id = "3.1.1-3", score = 50, severity = "critical"}
      }
      local context = {}
      
      local score, level = scorer.calculate_risk(violations, context)
      assert.equals(100, score)
      assert.equals("high", level)
    end)

    it("categorizes risk levels correctly", function()
      assert.equals("low", scorer.categorize_score(15))
      assert.equals("medium", scorer.categorize_score(45))
      assert.equals("high", scorer.categorize_score(85))
    end)
  end)

  describe("Velocity Detector", function()
    local velocity = require("kong.plugins.fraud-guard.detectors.velocity")
    local redis_adapter = require("kong.plugins.fraud-guard.storage.redis_adapter")

    before_each(function()
      -- Mock Redis operations
      redis_adapter.connect = function() return {}, nil end
      redis_adapter.sadd = function() return true, nil end
      redis_adapter.scard = function() return 2, nil end  -- Mock 2 recipients
      redis_adapter.incr = function() return 1, nil end
      redis_adapter.set = function() return true, nil end
      redis_adapter.expire = function() return true, nil end
      redis_adapter.get = function() return "5", nil end  -- Mock 5 transactions
    end)

    it("detects excessive daily recipients", function()
      redis_adapter.scard = function() return 6, nil end  -- 6 recipients > 5 limit
      
      local txn = {
        user_id = "user_123",
        transaction_type = "transfer",
        recipient_id = "recip_6"
      }
      
      local violations = velocity.check_daily_recipients(txn, mock_conf)
      assert.is_not_nil(violations)
      assert.equals(1, #violations)
      assert.equals("3.1.1-2", violations[1].rule_id)
    end)

    it("allows transactions under recipient limit", function()
      redis_adapter.scard = function() return 3, nil end  -- 3 recipients < 5 limit
      
      local txn = {
        user_id = "user_123",
        transaction_type = "transfer",
        recipient_id = "recip_3"
      }
      
      local violations = velocity.check_daily_recipients(txn, mock_conf)
      assert.equals(0, #violations)
    end)
  end)

  describe("Pattern Detector", function()
    local pattern = require("kong.plugins.fraud-guard.detectors.pattern")

    it("detects suspicious keywords", function()
      local txn = {
        user_id = "user_123",
        description = "kumar bahis payment"
      }
      
      local violations = pattern.check_suspicious_keywords(txn, mock_conf)
      assert.is_not_nil(violations)
      assert.equals(1, #violations)
      assert.equals("3.1.1-15", violations[1].rule_id)
    end)

    it("detects multiple accounts per IP", function()
      local redis_adapter = require("kong.plugins.fraud-guard.storage.redis_adapter")
      redis_adapter.scard = function() return 6, nil end  -- 6 accounts > 5 limit
      
      local txn = {
        user_id = "user_123",
        client_ip = "1.2.3.4"
      }
      
      local violations = pattern.check_accounts_per_ip(txn, mock_conf)
      assert.is_not_nil(violations)
      assert.equals(1, #violations)
      assert.equals("3.1.1-7", violations[1].rule_id)
    end)

    it("allows clean descriptions", function()
      local txn = {
        user_id = "user_123",
        description = "grocery shopping payment"
      }
      
      local violations = pattern.check_suspicious_keywords(txn, mock_conf)
      assert.equals(0, #violations)
    end)
  end)

  describe("Amount Detector", function()
    local amount_detector = require("kong.plugins.fraud-guard.detectors.amount")
    local redis_adapter = require("kong.plugins.fraud-guard.storage.redis_adapter")

    it("detects amount anomaly", function()
      redis_adapter.get = function(key)
        if key:match("user_avg_amount") then
          return "1000", nil  -- User avg: 1000 TL
        end
        return nil, nil
      end
      
      local txn = {
        user_id = "user_123",
        amount = 10000  -- 10x average
      }
      
      local violations = amount_detector.check_amount_anomaly(txn, mock_conf)
      assert.is_not_nil(violations)
      assert.equals(1, #violations)
    end)

    it("detects threshold avoidance", function()
      local txn = {
        user_id = "user_123",
        transaction_type = "transfer",
        amount = 49500  -- 99% of 50,000 limit
      }
      
      local violations = amount_detector.check_threshold_avoidance(txn, mock_conf)
      assert.is_not_nil(violations)
      assert.equals(1, #violations)
      assert.equals("3.1.3-4", violations[1].rule_id)
    end)
  end)

  describe("Account Rules", function()
    local account_rules = require("kong.plugins.fraud-guard.rules.account_rules")
    local redis_adapter = require("kong.plugins.fraud-guard.storage.redis_adapter")

    before_each(function()
      redis_adapter.get = function() return "0", nil end
      redis_adapter.incr = function() return 1, nil end
      redis_adapter.zadd = function() return true, nil end
    end)

    it("rule 3.1.1-1: checks daily transfer limit", function()
      redis_adapter.get = function(key)
        if key:match("daily_total") then
          return "60000", nil  -- 60K TL > 50K limit
        end
        return "0", nil
      end
      
      local txn = {
        user_id = "user_123",
        transaction_type = "transfer",
        amount = 10000
      }
      
      local violations = account_rules.rule_1_1_1(txn, mock_conf)
      assert.is_not_nil(violations)
      assert.equals("3.1.1-1", violations.rule_id)
    end)

    it("rule 3.1.1-6: checks new account limits", function()
      local txn = {
        user_id = "user_new",
        account_age_days = 15,  -- New account
        amount = 30000  -- Exceeds 27,500 limit
      }
      
      redis_adapter.get = function(key)
        if key:match("monthly_total") then
          return "20000", nil
        end
        if key:match("monthly_txn_count") then
          return "60", nil  -- 60 > 50 limit
        end
        return "0", nil
      end
      
      local violations = account_rules.rule_1_1_6(txn, mock_conf)
      assert.is_not_nil(violations)
      assert.equals("3.1.1-6", violations.rule_id)
    end)
  end)

  describe("POS Rules", function()
    local pos_rules = require("kong.plugins.fraud-guard.rules.pos_rules")
    local redis_adapter = require("kong.plugins.fraud-guard.storage.redis_adapter")

    it("rule 3.1.2-15: blocks excessive E-PIN purchases", function()
      redis_adapter.get = function(key)
        if key:match("epin_card_hourly_count") then
          return "4", nil  -- 4 transactions > 3 limit
        end
        if key:match("epin_card_hourly_amount") then
          return "10000", nil
        end
        return "0", nil
      end
      
      local txn = {
        user_id = "user_123",
        transaction_type = "pos",
        merchant_category = "epin",
        card_bin = "123456",
        amount = 5000
      }
      
      local violations = pos_rules.rule_1_2_15(txn, mock_conf)
      assert.is_not_nil(violations)
      assert.equals("3.1.2-15", violations.rule_id)
      assert.equals("CRITICAL", violations.severity)
    end)

    it("rule 3.1.2-1: detects merchant revenue anomaly", function()
      redis_adapter.get = function(key)
        if key:match("merchant_hourly") then
          return "100000", nil  -- High hourly amount
        end
        if key:match("merchant_daily") then
          return "200000", nil
        end
        if key:match("merchant_baseline") then
          return "20000", nil  -- Baseline: 20K
        end
        return "0", nil
      end
      
      local txn = {
        merchant_id = "merch_123",
        transaction_type = "pos",
        amount = 5000
      }
      
      local violations = pos_rules.rule_1_2_1(txn, mock_conf)
      assert.is_not_nil(violations)
      assert.equals("3.1.2-1", violations.rule_id)
    end)
  end)

  describe("Transfer Rules", function()
    local transfer_rules = require("kong.plugins.fraud-guard.rules.transfer_rules")
    local redis_adapter = require("kong.plugins.fraud-guard.storage.redis_adapter")

    it("rule 3.1.3-5: detects roundtrip transfers", function()
      redis_adapter.zscore = function() return "1", nil end  -- Transfer exists
      
      local txn = {
        user_id = "user_a",
        transaction_type = "transfer",
        recipient_id = "user_b",
        amount = 5000
      }
      
      local violations = transfer_rules.rule_1_3_5(txn, mock_conf)
      assert.is_not_nil(violations)
      assert.equals("3.1.3-5", violations.rule_id)
    end)

    it("rule 3.1.3-8: detects high-risk country transfers", function()
      local txn = {
        user_id = "user_123",
        transaction_type = "transfer",
        recipient_country = "KP",  -- North Korea - high risk
        amount = 10000
      }
      
      local violations = transfer_rules.rule_1_3_8(txn, mock_conf)
      assert.is_not_nil(violations)
      assert.equals("3.1.3-8", violations.rule_id)
    end)
  end)

  describe("Mobile Rules", function()
    local mobile_rules = require("kong.plugins.fraud-guard.rules.mobile_rules")
    local redis_adapter = require("kong.plugins.fraud-guard.storage.redis_adapter")

    it("rule 3.1.4-1: detects rooted/jailbroken device", function()
      local txn = {
        user_id = "user_123",
        transaction_type = "mobile_payment",
        device_security_status = "rooted"
      }
      
      local violations = mobile_rules.rule_1_4_1_group(txn, mock_conf)
      assert.is_not_nil(violations)
      assert.is_true(#violations > 0)
      assert.equals("3.1.4-1-2", violations[1].rule_id)
    end)

    it("rule 3.1.4-2: detects recent SIM swap", function()
      local txn = {
        user_id = "user_123",
        transaction_type = "mobile_payment",
        sim_changed_recently = true,
        hours_since_sim_change = 2,  -- < 48 hours
        amount = 5000
      }
      
      local violations = mobile_rules.rule_1_4_2_group(txn, mock_conf)
      assert.is_not_nil(violations)
      local sim_violation = nil
      for _, v in ipairs(violations) do
        if v.rule_id == "3.1.4-2-6" then
          sim_violation = v
          break
        end
      end
      assert.is_not_nil(sim_violation)
    end)
  end)

  describe("Integration Tests", function()
    it("processes normal transaction successfully", function()
      local txn_data = {
        user_id = "user_normal",
        account_id = "acc_001",
        transaction_type = "transfer",
        amount = 1000,
        recipient_id = "recip_001"
      }
      
      kong.request.get_body = function() return txn_data end
      
      -- Should not throw errors
      assert.has_no.errors(function()
        handler:access(mock_conf)
      end)
    end)

    it("blocks transaction with critical violations", function()
      local blocked = false
      kong.response.exit = function(status)
        if status == 403 then
          blocked = true
        end
      end
      
      -- Mock 6 recipients (exceeds limit)
      local redis_adapter = require("kong.plugins.fraud-guard.storage.redis_adapter")
      redis_adapter.scard = function() return 6, nil end
      
      local txn_data = {
        user_id = "user_blocked",
        account_id = "acc_002",
        transaction_type = "transfer",
        amount = 5000,
        recipient_id = "recip_999"
      }
      
      kong.request.get_body = function() return txn_data end
      
      handler:access(mock_conf)
      assert.is_true(blocked)
    end)
  end)

  describe("Performance Tests", function()
    it("completes in under 100ms", function()
      local start_time = os.clock()
      
      local txn_data = {
        user_id = "user_perf",
        account_id = "acc_perf",
        transaction_type = "pos",
        merchant_id = "merch_001",
        amount = 500
      }
      
      kong.request.get_body = function() return txn_data end
      
      handler:access(mock_conf)
      
      local elapsed = (os.clock() - start_time) * 1000  -- Convert to ms
      assert.is_true(elapsed < 100, "Execution took " .. elapsed .. "ms (target: <100ms)")
    end)
  end)
end)

-- Run with: busted test_suite.lua
-- Requires: luarocks install busted
