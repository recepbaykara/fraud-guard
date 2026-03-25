-- IP Validator Module
-- Provides secure IP validation with proper CIDR support
-- Handles X-Forwarded-For chains and trusted proxy configuration

-- Explicit require keeps the module compatible with plain Lua 5.1 CI tooling
-- (busted, luacheck) where `bit` is not a pre-loaded global.
local bit = require "bit"

local _M = {}

-- Simple IP to number conversion
local function ip_to_number(ip)
  local parts = {}
  for part in string.gmatch(ip, "%d+") do
    table.insert(parts, tonumber(part))
  end
  
  if #parts ~= 4 then
    return nil
  end
  
  return (parts[1] * 16777216) + (parts[2] * 65536) + (parts[3] * 256) + parts[4]
end

-- Check if IP is in CIDR range
local function is_ip_in_cidr(ip, cidr)
  local ip_parts = {}
  for part in string.gmatch(ip, "%d+") do
    table.insert(ip_parts, tonumber(part))
  end
  
  if #ip_parts ~= 4 then
    return false
  end
  
  local cidr_ip, cidr_mask = string.match(cidr, "([^/]+)/(%d+)")
  if not cidr_ip or not cidr_mask then
    -- No mask, exact match
    return ip == cidr
  end
  
  cidr_mask = tonumber(cidr_mask)
  if not cidr_mask or cidr_mask < 0 or cidr_mask > 32 then
    return false
  end

  local ip_num = ip_to_number(ip)
  local cidr_num = ip_to_number(cidr_ip)

  if not ip_num or not cidr_num then
    return false
  end

  -- cidr_mask=0 means match all IPs; bit.lshift wraps at 32 so handle explicitly
  if cidr_mask == 0 then
    return true
  end

  -- bit.lshift(0xFFFFFFFF, n) correctly produces subnet masks in LuaJIT's 32-bit signed arithmetic
  local mask = bit.lshift(0xFFFFFFFF, (32 - cidr_mask))
  return bit.band(ip_num, mask) == bit.band(cidr_num, mask)
end

-- Extract real client IP from X-Forwarded-For chain
function _M.get_real_client_ip(trusted_proxies)
  -- Get the client IP as determined by Kong
  local client_ip = kong.client.get_forwarded_ip()
  
  -- If no trusted proxies configured, use Kong's determination
  if not trusted_proxies or #trusted_proxies == 0 then
    return client_ip, nil
  end
  
  -- Parse X-Forwarded-For header
  local xff_header = kong.request.get_header("X-Forwarded-For")
  if not xff_header then
    return client_ip, nil
  end
  
  -- Split X-Forwarded-For chain
  local ip_list = {}
  for ip in string.gmatch(xff_header, "([^,%s]+)") do
    table.insert(ip_list, ip)
  end
  
  -- Walk backwards through chain to find first untrusted IP
  for i = #ip_list, 1, -1 do
    local ip = ip_list[i]
    local is_trusted = false
    
    for _, trusted_cidr in ipairs(trusted_proxies) do
      if is_ip_in_cidr(ip, trusted_cidr) then
        is_trusted = true
        break
      end
    end
    
    if not is_trusted then
      return ip, nil
    end
  end
  
  -- All IPs are trusted, use the first one
  return ip_list[1] or client_ip, nil
end

-- Check if IP is in whitelist (CIDR-aware)
function _M.is_ip_whitelisted(client_ip, whitelist)
  if not whitelist or #whitelist == 0 then
    return false, nil
  end
  
  for _, cidr in ipairs(whitelist) do
    if is_ip_in_cidr(client_ip, cidr) then
      return true, nil
    end
  end
  
  return false, nil
end

-- Check if IP is in a specific range (single CIDR)
function _M.ip_in_range(ip, cidr)
  return is_ip_in_cidr(ip, cidr), nil
end

-- Validate IP format (IPv4)
function _M.is_valid_ip(ip)
  if not ip or ip == "" then
    return false
  end
  
  local parts = {}
  for part in string.gmatch(ip, "%d+") do
    local num = tonumber(part)
    if not num or num < 0 or num > 255 then
      return false
    end
    table.insert(parts, num)
  end
  
  return #parts == 4
end

-- No-op cache clear called by unit tests after each test case.
-- The module does not maintain an in-process cache at this time;
-- this stub satisfies the test harness without altering behaviour.
function _M.clear_cache()
end

-- Check if IP is a private/internal address
function _M.is_private_ip(ip)
  local private_ranges = {
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16"
  }
  
  for _, cidr in ipairs(private_ranges) do
    if is_ip_in_cidr(ip, cidr) then
      return true
    end
  end
  
  return false
end

return _M
