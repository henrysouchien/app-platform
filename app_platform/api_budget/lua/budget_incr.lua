-- Atomic multi-key increment for API budget counters.
--
-- KEYS (always present):
--   [1] global_op_daily       [2] global_op_monthly
--   [3] global_agg_daily      [4] global_agg_monthly
-- KEYS (optional, present iff user_id supplied):
--   [5] user_op_daily         [6] user_op_monthly
--   [7] user_agg_daily        [8] user_agg_monthly
--
-- ARGV: inc_amount, (limit, warn, ttl_seconds) tuples aligned with KEYS.
-- "-1" means "no cap" for warn or limit.

local scope_by_index = {
  "global", "global", "global", "global",
  "user", "user", "user", "user"
}

local key_kind_by_index = {
  "op", "op", "agg", "agg",
  "op", "op", "agg", "agg"
}

local window_by_index = {
  "daily", "monthly", "daily", "monthly",
  "daily", "monthly", "daily", "monthly"
}

local inc_amount = tonumber(ARGV[1])
local counts = {}
local crossings = {}
local severity = 0
local blocked_global = false
local blocked_user = false
local first_blocked = nil

for i = 1, #KEYS do
  local argv_offset = 2 + ((i - 1) * 3)
  local limit = tonumber(ARGV[argv_offset])
  local warn = tonumber(ARGV[argv_offset + 1])
  local ttl_seconds = tonumber(ARGV[argv_offset + 2])

  local current_value = redis.call("GET", KEYS[i])
  local before = tonumber(current_value or "0")
  local after = tonumber(redis.call("INCRBY", KEYS[i], inc_amount))

  local ttl = tonumber(redis.call("TTL", KEYS[i]))
  if ttl < 0 then
    redis.call("EXPIRE", KEYS[i], ttl_seconds)
  end

  counts[i] = {
    key_index = i,
    scope = scope_by_index[i],
    key_kind = key_kind_by_index[i],
    window_kind = window_by_index[i],
    before = before,
    after = after
  }

  local crossing_kind = nil
  local crossing_threshold = nil

  if limit ~= nil and limit >= 0 and after > limit then
    severity = 2
    if scope_by_index[i] == "global" then
      blocked_global = true
    else
      blocked_user = true
    end
    if first_blocked == nil then
      first_blocked = {
        key_index = i,
        key_kind = key_kind_by_index[i],
        window_kind = window_by_index[i],
        threshold = limit,
        count = after
      }
    end
    if before <= limit then
      crossing_kind = "limit"
      crossing_threshold = limit
    end
  end

  if crossing_kind == nil and warn ~= nil and warn >= 0 and after >= warn then
    if severity < 1 then
      severity = 1
    end
    if before < warn then
      crossing_kind = "warn"
      crossing_threshold = warn
    end
  end

  if crossing_kind ~= nil then
    crossings[#crossings + 1] = {
      key_index = i,
      scope = scope_by_index[i],
      key_kind = key_kind_by_index[i],
      window_kind = window_by_index[i],
      threshold_kind = crossing_kind,
      threshold = crossing_threshold,
      count = after
    }
  end
end

local blocked_scope = cjson.null
local blocked_key_kind = cjson.null
local blocked_window_kind = cjson.null
local blocked_threshold = cjson.null
local blocked_count = cjson.null

if first_blocked ~= nil then
  if blocked_global and blocked_user then
    blocked_scope = "both"
  elseif blocked_global then
    blocked_scope = "global"
  else
    blocked_scope = "user"
  end
  blocked_key_kind = first_blocked["key_kind"]
  blocked_window_kind = first_blocked["window_kind"]
  blocked_threshold = first_blocked["threshold"]
  blocked_count = first_blocked["count"]
end

local decision = "ok"
if severity == 2 then
  decision = "blocked"
elseif severity == 1 then
  decision = "warned"
end

return cjson.encode({
  decision = decision,
  blocked_scope = blocked_scope,
  blocked_key_kind = blocked_key_kind,
  blocked_window_kind = blocked_window_kind,
  blocked_threshold = blocked_threshold,
  blocked_count = blocked_count,
  crossings = crossings,
  counts = counts
})
