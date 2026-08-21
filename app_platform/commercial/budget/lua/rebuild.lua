-- Atomically stage or validate one complete commercial budget generation.
-- KEYS: generation metadata, active counter, policy, bucket counters, reservations...
-- ARGV: canonical JSON rebuild command. All integer fields are decimal strings.

local max_safe_integer = 4503599627370495
local max_safe_raw = "4503599627370495"
local max_ttl_seconds = 31536000

local function exact_nonnegative_string(raw)
  if type(raw) ~= "string" or not string.match(raw, "^%d+$") then return nil end
  if raw ~= "0" and string.sub(raw, 1, 1) == "0" then return nil end
  if string.len(raw) > string.len(max_safe_raw)
     or (string.len(raw) == string.len(max_safe_raw) and raw > max_safe_raw) then
    return nil
  end
  local value = tonumber(raw)
  if not value or value < 0 or value > max_safe_integer
     or value ~= math.floor(value) then return nil end
  return value
end

local function exact_positive_string(raw)
  local value = exact_nonnegative_string(raw)
  if not value or value <= 0 then return nil end
  return value
end

local function canonical_nonnegative(raw)
  return exact_nonnegative_string(raw) ~= nil
end

local ok, command = pcall(cjson.decode, ARGV[1] or "")
local expected_generation = ok and type(command) == "table"
  and exact_positive_string(command.expected_generation) or nil
local target_generation = ok and type(command) == "table"
  and exact_positive_string(command.target_generation) or nil

local function response(decision, reason, replayed)
  return cjson.encode({
    decision = decision,
    reason_code = reason,
    generation = target_generation or 1,
    snapshot_sha256 = ok and type(command) == "table"
      and command.snapshot_sha256 or ("sha256:" .. string.rep("0", 64)),
    replayed = replayed
  })
end

if #ARGV ~= 1 or not ok or type(command) ~= "table"
   or not expected_generation or not target_generation
   or target_generation <= expected_generation
   or type(command.snapshot_sha256) ~= "string"
   or string.len(command.snapshot_sha256) ~= 71
   or not string.match(command.snapshot_sha256, "^sha256:[0-9a-f]+$")
   or type(command.buckets) ~= "table" or #command.buckets ~= 2
   or type(command.reservations) ~= "table"
   or #KEYS ~= 6 + #command.reservations then
  return response("block", "budget.rebuild_invalid", false)
end

local agreement_terms_id = exact_positive_string(command.agreement_terms_id)
local budget_period_id = exact_positive_string(command.budget_period_id)
local budget_policy_id = exact_positive_string(command.budget_policy_id)
local max_concurrency = exact_positive_string(
  command.max_concurrent_reservations)
local max_unreserved_delta = exact_nonnegative_string(
  command.max_unreserved_delta_microusd)
local late_allowance = exact_nonnegative_string(
  command.late_child_allowance_microusd)
local late_consumed = exact_nonnegative_string(
  command.late_child_consumed_microusd)
local max_overdraft = exact_nonnegative_string(
  command.max_period_overdraft_microusd)
local active_reservations = exact_nonnegative_string(command.active_reservations)
if not agreement_terms_id or not budget_period_id or not budget_policy_id
   or not max_concurrency or max_unreserved_delta == nil
   or late_allowance == nil or late_consumed == nil or max_overdraft == nil
   or late_consumed > late_allowance or late_consumed > max_overdraft
   or active_reservations == nil or active_reservations > max_concurrency
   or command.buckets[1].budget_bucket ~= "model"
   or command.buckets[2].budget_bucket ~= "technical"
   or exact_nonnegative_string(command.buckets[1].amount_microusd) == nil
   or exact_nonnegative_string(command.buckets[2].amount_microusd) == nil
   or exact_nonnegative_string(command.buckets[1].limit_microusd) == nil
   or exact_nonnegative_string(command.buckets[2].limit_microusd) == nil then
  return response("block", "budget.rebuild_invalid", false)
end

local tag = "commercial:enforce:" .. command.agreement_terms_id
  .. ":" .. command.budget_period_id
local base = "budget:spend:v2:{" .. tag .. "}:g" .. command.target_generation
if KEYS[1] ~= base .. ":generation"
   or KEYS[2] ~= base .. ":active"
   or KEYS[3] ~= base .. ":late-child-used"
   or KEYS[4] ~= base .. ":policy"
   or KEYS[5] ~= base .. ":bucket:model"
   or KEYS[6] ~= base .. ":bucket:technical" then
  return response("block", "budget.rebuild_invalid", false)
end

local seen_reservations = {}
local counted_active = 0
for i = 1, #command.reservations do
  local reservation = command.reservations[i]
  local lease_version = type(reservation) == "table"
    and exact_positive_string(reservation.lease_version) or nil
  local ttl_seconds = type(reservation) == "table"
    and exact_positive_string(reservation.ttl_seconds) or nil
  local active_state = type(reservation) == "table" and (
    reservation.state == "reserved"
    or reservation.state == "partially_settled"
    or reservation.state == "overdrawn")
  local terminal_state = type(reservation) == "table" and (
    reservation.state == "settled"
    or reservation.state == "released"
    or reservation.state == "expired"
    or reservation.state == "overdrawn")
  if type(reservation) ~= "table"
     or type(reservation.reservation_id) ~= "string"
     or reservation.reservation_id == ""
     or seen_reservations[reservation.reservation_id]
     or KEYS[6 + i] ~= base .. ":reservation:" .. reservation.reservation_id
     or type(reservation.payload_sha256) ~= "string"
     or string.len(reservation.payload_sha256) ~= 71
     or not string.match(reservation.payload_sha256, "^sha256:[0-9a-f]+$")
     or type(reservation.lease_token) ~= "string"
     or reservation.lease_token == ""
     or not lease_version or not ttl_seconds or ttl_seconds > max_ttl_seconds
     or type(reservation.active) ~= "boolean"
     or (reservation.active and not active_state)
     or (not reservation.active and not terminal_state)
     or type(reservation.holds_by_bucket_microusd) ~= "table"
     or #reservation.holds_by_bucket_microusd ~= 2 then
    return response("block", "budget.rebuild_invalid", false)
  end
  seen_reservations[reservation.reservation_id] = true
  if reservation.active then counted_active = counted_active + 1 end
  for bucket_index = 1, 2 do
    local hold = reservation.holds_by_bucket_microusd[bucket_index]
    local hold_amount = type(hold) == "table"
      and exact_nonnegative_string(hold.amount_microusd) or nil
    if type(hold) ~= "table"
       or hold.budget_bucket ~= command.buckets[bucket_index].budget_bucket
       or hold_amount == nil
       or (not reservation.active and hold_amount ~= 0) then
      return response("block", "budget.rebuild_invalid", false)
    end
  end
end
if counted_active ~= active_reservations then
  return response("block", "budget.rebuild_invalid", false)
end

local function structure_matches()
  if redis.call("HGET", KEYS[1], "snapshot_sha256") ~= command.snapshot_sha256
     or redis.call("HGET", KEYS[1], "generation") ~= command.target_generation
     or redis.call("HGET", KEYS[1], "state") ~= "ready"
     or redis.call("GET", KEYS[2]) ~= command.active_reservations
     or redis.call("GET", KEYS[3]) ~= command.late_child_consumed_microusd
     or redis.call("HGET", KEYS[4], "generation") ~= command.target_generation
     or redis.call("HGET", KEYS[4], "budget_policy_id")
        ~= command.budget_policy_id
     or redis.call("HGET", KEYS[4], "max_concurrency")
        ~= command.max_concurrent_reservations
     or redis.call("HGET", KEYS[4], "max_unreserved_delta")
        ~= command.max_unreserved_delta_microusd
     or redis.call("HGET", KEYS[4], "late_allowance")
        ~= command.late_child_allowance_microusd
     or redis.call("HGET", KEYS[4], "max_overdraft")
        ~= command.max_period_overdraft_microusd
     or redis.call("HGET", KEYS[4], "bucket_count") ~= "2" then
    return false
  end
  for i = 1, 2 do
    local bucket = command.buckets[i]
    if redis.call("HGET", KEYS[4], "bucket:" .. i) ~= bucket.budget_bucket
       or redis.call("HGET", KEYS[4], "limit:" .. bucket.budget_bucket)
          ~= bucket.limit_microusd
       or redis.call("GET", KEYS[4 + i]) ~= bucket.amount_microusd
       or not canonical_nonnegative(redis.call("GET", KEYS[4 + i])) then
      return false
    end
  end
  for i = 1, #command.reservations do
    local reservation = command.reservations[i]
    local key = KEYS[6 + i]
    if redis.call("HGET", key, "reservation_id") ~= reservation.reservation_id
       or redis.call("HGET", key, "payload_digest") ~= reservation.payload_sha256
       or redis.call("HGET", key, "lease_token") ~= reservation.lease_token
       or redis.call("HGET", key, "lease_version") ~= reservation.lease_version
       or redis.call("HGET", key, "generation") ~= command.target_generation
       or redis.call("HGET", key, "state") ~= reservation.state
       or redis.call("HGET", key, "active")
          ~= (reservation.active and "1" or "0")
       or redis.call("HGET", key, "bucket_count") ~= "2" then
      return false
    end
    for bucket_index = 1, 2 do
      local hold = reservation.holds_by_bucket_microusd[bucket_index]
      if redis.call("HGET", key, "bucket:" .. bucket_index)
            ~= hold.budget_bucket
         or redis.call("HGET", key, "hold:" .. hold.budget_bucket)
            ~= hold.amount_microusd then
        return false
      end
    end
  end
  return true
end

if redis.call("EXISTS", KEYS[1]) == 1 then
  if structure_matches() then
    return response("allow", "budget.rebuild_replay", true)
  end
  return response("block", "budget.rebuild_conflict", false)
end

for i = 1, #KEYS do
  if redis.call("EXISTS", KEYS[i]) == 1 then
    return response("block", "budget.rebuild_orphan_keys", false)
  end
end

redis.call("HSET", KEYS[1],
  "generation", command.target_generation,
  "expected_generation", command.expected_generation,
  "snapshot_sha256", command.snapshot_sha256,
  "state", "ready",
  "reservation_count", tostring(#command.reservations))
redis.call("SET", KEYS[2], command.active_reservations)
redis.call("SET", KEYS[3], command.late_child_consumed_microusd)
redis.call("HSET", KEYS[4],
  "budget_policy_id", command.budget_policy_id,
  "generation", command.target_generation,
  "max_concurrency", command.max_concurrent_reservations,
  "max_unreserved_delta", command.max_unreserved_delta_microusd,
  "late_allowance", command.late_child_allowance_microusd,
  "max_overdraft", command.max_period_overdraft_microusd,
  "bucket_count", 2)
for i = 1, 2 do
  local bucket = command.buckets[i]
  redis.call("HSET", KEYS[4],
    "bucket:" .. i, bucket.budget_bucket,
    "limit:" .. bucket.budget_bucket, bucket.limit_microusd)
  redis.call("SET", KEYS[4 + i], bucket.amount_microusd)
end
for i = 1, #command.reservations do
  local reservation = command.reservations[i]
  local key = KEYS[6 + i]
  redis.call("HSET", key,
    "reservation_id", reservation.reservation_id,
    "payload_digest", reservation.payload_sha256,
    "lease_token", reservation.lease_token,
    "lease_version", reservation.lease_version,
    "generation", command.target_generation,
    "state", reservation.state,
    "active", reservation.active and 1 or 0,
    "bucket_count", 2)
  for bucket_index = 1, 2 do
    local hold = reservation.holds_by_bucket_microusd[bucket_index]
    redis.call("HSET", key,
      "bucket:" .. bucket_index, hold.budget_bucket,
      "hold:" .. hold.budget_bucket, hold.amount_microusd)
  end
  redis.call("EXPIRE", key, tonumber(reservation.ttl_seconds))
end
return response("allow", "budget.rebuilt", false)
