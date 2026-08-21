-- Atomic commercial settlement and bounded late-child accounting.
-- KEYS: reservation, idempotency, active, policy, late-child-used, bucket counters,
--       generation metadata, stable generation pointer
-- All keys share the period-scoped Redis Cluster hash tag.

local reservation_id = ARGV[1]
local payload_digest = ARGV[2]
local lease_token = ARGV[3]
local lease_version = tonumber(ARGV[4])
local generation = tonumber(ARGV[5])
local budget_policy_id = ARGV[6]
local ttl_seconds = tonumber(ARGV[7])
local source_product = ARGV[8]
local source_event_id = ARGV[9]
local cost_revision = tonumber(ARGV[10])
local actor_type = ARGV[11]
local actor_id = ARGV[12]
local cost_adjustment_id = ARGV[13]
local is_late_child = ARGV[14] == "1"
local finalize_reservation = ARGV[15] == "1"
local late_child_allowance = tonumber(ARGV[16])
local bucket_count = tonumber(ARGV[17])
local reason_code = ARGV[18 + (bucket_count * 3)]
local max_safe_integer = 4503599627370495

local function expire_at_least(key, seconds)
  local current_ttl = tonumber(redis.call("TTL", key))
  if current_ttl < seconds then redis.call("EXPIRE", key, seconds) end
end

local function read_nonnegative(key)
  local raw = redis.call("GET", key)
  if not raw then return nil end
  local value = tonumber(raw)
  if not string.match(raw, "^%d+$") or not value
     or value < 0 or value > max_safe_integer or value ~= math.floor(value) then
    return nil
  end
  return value
end

local function read_nonnegative_hash(field, missing_is_zero)
  local raw = redis.call("HGET", KEYS[1], field)
  if not raw and missing_is_zero then return 0 end
  if not raw or not string.match(raw, "^%d+$") then return nil end
  local value = tonumber(raw)
  if not value or value < 0 or value > max_safe_integer
     or value ~= math.floor(value) then return nil end
  return value
end

local function refresh_state_retention()
  expire_at_least(KEYS[1], ttl_seconds)
  expire_at_least(KEYS[2], ttl_seconds)
  for i = 3, #KEYS do redis.call("PERSIST", KEYS[i]) end
end

local function response(decision, reason, replayed, overdrawn)
  local holds = {}
  local settled = {}
  for i = 1, bucket_count do
    local offset = 18 + ((i - 1) * 3)
    local bucket = ARGV[offset]
    local held = redis.call("HGET", KEYS[1], "hold:" .. bucket) or "0"
    local settled_amount = redis.call("HGET", KEYS[1], "settled:" .. bucket) or "0"
    local parsed_held = tonumber(held)
    local parsed_settled = tonumber(settled_amount)
    if not string.match(held, "^%d+$") or not parsed_held
       or parsed_held < 0 or parsed_held > max_safe_integer
       or parsed_held ~= math.floor(parsed_held) then held = "0" end
    if not string.match(settled_amount, "^%d+$") or not parsed_settled
       or parsed_settled < 0
       or parsed_settled > max_safe_integer
       or parsed_settled ~= math.floor(parsed_settled) then settled_amount = "0" end
    holds[bucket] = held
    settled[bucket] = settled_amount
  end
  local late_consumed = redis.call("GET", KEYS[5]) or "0"
  if not string.match(late_consumed, "^%d+$")
     or (redis.call("EXISTS", KEYS[5]) == 1
         and read_nonnegative(KEYS[5]) == nil) then
    late_consumed = "0"
  end
  local response_lease_version = redis.call("HGET", KEYS[1], "lease_version")
    or tostring(lease_version)
  local response_generation = redis.call("HGET", KEYS[1], "generation")
    or tostring(generation)
  local parsed_response_lease = tonumber(response_lease_version)
  local parsed_response_generation = tonumber(response_generation)
  if not string.match(response_lease_version, "^%d+$")
     or not parsed_response_lease or parsed_response_lease <= 0
     or parsed_response_lease > max_safe_integer
     or parsed_response_lease ~= math.floor(parsed_response_lease) then
    response_lease_version = tostring(lease_version)
  end
  if not string.match(response_generation, "^%d+$")
     or not parsed_response_generation or parsed_response_generation <= 0
     or parsed_response_generation > max_safe_integer
     or parsed_response_generation ~= math.floor(parsed_response_generation) then
    response_generation = tostring(generation)
  end
  local response_state = redis.call("HGET", KEYS[1], "state") or "missing"
  if response_state ~= "reserved" and response_state ~= "partially_settled"
     and response_state ~= "settled" and response_state ~= "overdrawn"
     and response_state ~= "released" and response_state ~= "expired" then
    response_state = "missing"
  end
  return cjson.encode({
    decision = decision,
    reason_code = reason,
    reservation_id = reservation_id,
    lease_version = response_lease_version,
    generation = response_generation,
    state = response_state,
    replayed = replayed,
    overdrawn = overdrawn,
    holds_by_bucket_microusd = holds,
    settled_by_bucket_microusd = settled,
    late_child_consumed_microusd = late_consumed
  })
end

if #KEYS ~= 7 + bucket_count then
  return response("block", "budget.settlement_invalid", false, false)
end
local metadata_key = KEYS[6 + bucket_count]
local pointer_key = KEYS[7 + bucket_count]
local metadata_digest = redis.call("HGET", metadata_key, "snapshot_sha256")
if redis.call("HGET", metadata_key, "generation") ~= ARGV[5]
   or redis.call("HGET", metadata_key, "state") ~= "ready"
   or not metadata_digest
   or redis.call("HGET", pointer_key, "generation") ~= ARGV[5]
   or redis.call("HGET", pointer_key, "snapshot_sha256") ~= metadata_digest then
  return response("block", "budget.generation_not_ready", false, false)
end

if redis.call("EXISTS", KEYS[1]) == 0 then
  return response("block", "budget.reservation_missing", false, false)
end
if redis.call("EXISTS", KEYS[3]) == 0 or redis.call("EXISTS", KEYS[4]) == 0 then
  return response("block", "budget.counter_corrupt", false, false)
end
local existing = redis.call("HGET", KEYS[2], "reservation_id")
if existing then
  if existing ~= reservation_id
     or redis.call("HGET", KEYS[2], "payload_digest") ~= payload_digest
     or redis.call("HGET", KEYS[2], "operation") ~= "settle"
     or redis.call("HGET", KEYS[2], "lease_token") ~= lease_token
     or redis.call("HGET", KEYS[2], "lease_version") ~= ARGV[4]
     or redis.call("HGET", KEYS[2], "generation") ~= ARGV[5]
     or redis.call("HGET", KEYS[2], "source_product") ~= source_product
     or redis.call("HGET", KEYS[2], "source_event_id") ~= source_event_id
     or redis.call("HGET", KEYS[2], "cost_revision") ~= ARGV[10]
     or redis.call("HGET", KEYS[2], "actor_type") ~= actor_type
     or redis.call("HGET", KEYS[2], "actor_id") ~= actor_id
     or redis.call("HGET", KEYS[2], "cost_adjustment_id") ~= cost_adjustment_id
     or redis.call("HGET", KEYS[2], "reason_code") ~= reason_code
     or redis.call("HGET", KEYS[2], "is_late_child") ~= ARGV[14]
     or redis.call("HGET", KEYS[2], "finalize_reservation") ~= ARGV[15] then
    return response("block", "budget.idempotency_conflict", false, false)
  end
end
local expected_current_lease = ARGV[4]
if existing then
  local committed_raw = redis.call(
    "HGET", KEYS[2], "committed_lease_version")
  local advanced_raw = redis.call("HGET", KEYS[2], "fence_advanced")
  local committed = tonumber(committed_raw)
  local current_raw = redis.call("HGET", KEYS[1], "lease_version")
  local current = tonumber(current_raw)
  if not committed_raw or not string.match(committed_raw, "^%d+$")
     or not committed or committed <= 0 or committed > max_safe_integer
     or committed ~= math.floor(committed)
     or (advanced_raw ~= "0" and advanced_raw ~= "1")
     or committed ~= lease_version + tonumber(advanced_raw)
     or not current_raw or not string.match(current_raw, "^%d+$")
     or not current or current <= 0 or current > max_safe_integer
     or current ~= math.floor(current) or current < committed then
    return response("block", "budget.counter_corrupt", false, false)
  end
  expected_current_lease = current_raw
end
if redis.call("HGET", KEYS[1], "lease_token") ~= lease_token
   or redis.call("HGET", KEYS[1], "lease_version") ~= expected_current_lease
   or redis.call("HGET", KEYS[1], "generation") ~= ARGV[5] then
  return response("block", "budget.stale_fence", false, false)
end
if redis.call("HGET", KEYS[4], "budget_policy_id") ~= budget_policy_id
   or redis.call("HGET", KEYS[4], "generation") ~= ARGV[5]
   or redis.call("HGET", KEYS[4], "bucket_count") ~= ARGV[17] then
  return response("block", "budget.policy_mismatch", false, false)
end
local stored_late_allowance = redis.call("HGET", KEYS[4], "late_allowance")
if not stored_late_allowance or stored_late_allowance ~= ARGV[16] then
  return response("block", "budget.policy_mismatch", false, false)
end

for i = 1, bucket_count do
  local offset = 18 + ((i - 1) * 3)
  local bucket = ARGV[offset]
  local limit = ARGV[offset + 2]
  if redis.call("EXISTS", KEYS[5 + i]) == 0
     or redis.call("HGET", KEYS[4], "bucket:" .. i) ~= bucket
     or redis.call("HGET", KEYS[4], "limit:" .. bucket) ~= limit
     or read_nonnegative(KEYS[5 + i]) == nil then
    return response("block", "budget.counter_corrupt", false, false)
  end
end

local state = redis.call("HGET", KEYS[1], "state")
local reservation_active_raw = redis.call("HGET", KEYS[1], "active")
if reservation_active_raw ~= "0" and reservation_active_raw ~= "1" then
  return response("block", "budget.counter_corrupt", false, false)
end
local reservation_active = tonumber(reservation_active_raw)
local active_normal = not is_late_child and cost_revision == 0
  and reservation_active == 1
  and (state == "reserved" or state == "partially_settled" or state == "overdrawn")
local active_late = is_late_child and cost_revision == 0
  and reservation_active == 1
  and (state == "reserved" or state == "partially_settled" or state == "overdrawn")
local active_initial = active_normal or active_late
local post_final_revision = not is_late_child and reservation_active == 0
  and cost_revision > 0 and (state == "settled" or state == "overdrawn")
local bounded_late = is_late_child and reservation_active == 0
  and (state == "settled" or state == "overdrawn")
local canonical_terminal = reservation_active == 0
  and (state == "settled" or state == "overdrawn"
       or state == "released" or state == "expired")
if existing and not active_initial and not canonical_terminal then
  return response("block", "budget.invalid_state", false, false)
end
if not existing and not active_initial
   and not post_final_revision and not bounded_late then
  return response("block", "budget.invalid_state", false, false)
end
if existing then
  for i = 1, bucket_count do
    local offset = 18 + ((i - 1) * 3)
    local bucket = ARGV[offset]
    if redis.call("HGET", KEYS[1], "bucket:" .. i) ~= bucket
       or read_nonnegative_hash("hold:" .. bucket, false) == nil
       or read_nonnegative_hash("settled:" .. bucket, true) == nil then
      return response("block", "budget.counter_corrupt", false, false)
    end
  end
  refresh_state_retention()
  return response("allow", "budget.settlement_replay", true,
    redis.call("HGET", KEYS[1], "state") == "overdrawn")
end
if active_initial and lease_version >= max_safe_integer then
  return response("block", "budget.counter_overflow", false, false)
end
local committed_lease_version = active_initial and lease_version + 1 or lease_version

local technical_actual = nil
local overdrawn = state == "overdrawn"
local actual_by_index = {}
local held_by_index = {}
local current_by_index = {}
local settled_by_index = {}
for i = 1, bucket_count do
  local offset = 18 + ((i - 1) * 3)
  local bucket = ARGV[offset]
  local actual = tonumber(ARGV[offset + 1])
  local held = read_nonnegative_hash("hold:" .. bucket, false)
  local current = read_nonnegative(KEYS[5 + i])
  local settled = read_nonnegative_hash("settled:" .. bucket, true)
  if not actual or actual < -max_safe_integer or actual > max_safe_integer
     or actual ~= math.floor(actual) or held == nil or current == nil
     or settled == nil then
    return response("block", "budget.counter_corrupt", false, false)
  end
  if is_late_child and not active_initial and held ~= 0 then
    return response("block", "budget.late_child_open_hold", false, false)
  end
  if actual < 0 and not (cost_revision > 0
      and (actor_type == "admin" or actor_type == "reconciler")
      and actor_id ~= "" and cost_adjustment_id ~= "") then
    return response("block", "budget.adjustment_authority_required", false, false)
  end
  if actual > held then overdrawn = true end
  if bucket == "technical" then technical_actual = actual end
  local resulting_counter
  if active_initial and actual >= 0 then
    local consumed_hold = math.min(actual, held)
    local remaining_hold = held - consumed_hold
    resulting_counter = current + (actual - consumed_hold)
    if finalize_reservation then resulting_counter = resulting_counter - remaining_hold end
  else
    resulting_counter = current + actual
  end
  if resulting_counter < 0 or settled + actual < 0 then
    return response("block", "budget.counter_underflow", false, false)
  end
  if resulting_counter > max_safe_integer or settled + actual > max_safe_integer then
    return response("block", "budget.counter_overflow", false, false)
  end
  actual_by_index[i] = actual
  held_by_index[i] = held
  current_by_index[i] = current
  settled_by_index[i] = settled
end
if technical_actual == nil then
  return response("block", "budget.technical_total_required", false, false)
end

local active = read_nonnegative(KEYS[3])
local late_used
if redis.call("EXISTS", KEYS[5]) == 0 then
  late_used = 0
else
  late_used = read_nonnegative(KEYS[5])
end
if active == nil or late_used == nil then
  return response("block", "budget.counter_corrupt", false, false)
end
if active_initial and active <= 0 then
  return response("block", "budget.counter_corrupt", false, false)
end
if is_late_child and late_used + technical_actual > max_safe_integer then
  return response("block", "budget.counter_overflow", false, false)
end
if is_late_child and late_used + technical_actual < 0 then
  return response("block", "budget.counter_underflow", false, false)
end
if is_late_child and late_used + technical_actual > late_child_allowance then
  return response("block", "budget.late_child_allowance_exhausted", false, false)
end

if redis.call("EXISTS", KEYS[5]) == 0 then redis.call("SET", KEYS[5], 0) end

for i = 1, bucket_count do
  local offset = 18 + ((i - 1) * 3)
  local bucket = ARGV[offset]
  local actual = tonumber(ARGV[offset + 1])
  local held = held_by_index[i]
  if active_initial and actual >= 0 then
    local consumed_hold = math.min(actual, held)
    local remaining_hold = held - consumed_hold
    local uncovered = actual - consumed_hold
    if uncovered > 0 then redis.call("INCRBY", KEYS[5 + i], uncovered) end
    redis.call("HSET", KEYS[1], "hold:" .. bucket, remaining_hold)
  elseif actual ~= 0 then
    redis.call("INCRBY", KEYS[5 + i], actual)
  end
  redis.call("HINCRBY", KEYS[1], "settled:" .. bucket, actual)
end
if is_late_child then
  if technical_actual ~= 0 then redis.call("INCRBY", KEYS[5], technical_actual) end
  overdrawn = true
end
if post_final_revision then
  redis.call("HSET", KEYS[1], "state", overdrawn and "overdrawn" or "settled")
elseif active_initial and finalize_reservation then
  for i = 1, bucket_count do
    local offset = 18 + ((i - 1) * 3)
    local bucket = ARGV[offset]
    local remaining = read_nonnegative_hash("hold:" .. bucket, false)
    if remaining > 0 then redis.call("DECRBY", KEYS[5 + i], remaining) end
    redis.call("HSET", KEYS[1], "hold:" .. bucket, 0)
  end
  redis.call("DECR", KEYS[3])
  redis.call("HSET", KEYS[1], "active", 0)
  redis.call("HSET", KEYS[1], "state", overdrawn and "overdrawn" or "settled")
elseif active_initial then
  redis.call("HSET", KEYS[1], "state", overdrawn and "overdrawn" or "partially_settled")
else
  redis.call("HSET", KEYS[1], "state", "overdrawn")
end
redis.call("HSET", KEYS[1], "lease_version", committed_lease_version)
redis.call("HSET", KEYS[2],
  "reservation_id", reservation_id, "payload_digest", payload_digest,
  "operation", "settle", "lease_token", lease_token,
  "lease_version", lease_version,
  "committed_lease_version", committed_lease_version,
  "fence_advanced", active_initial and "1" or "0",
  "generation", generation,
  "source_product", source_product, "source_event_id", source_event_id,
  "cost_revision", cost_revision, "actor_type", actor_type,
  "actor_id", actor_id, "cost_adjustment_id", cost_adjustment_id,
  "reason_code", reason_code,
  "is_late_child", ARGV[14], "finalize_reservation", ARGV[15])
refresh_state_retention()
return response("allow", overdrawn and "budget.overdrawn" or "budget.settled",
  false, overdrawn)
