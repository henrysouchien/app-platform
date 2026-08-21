-- Atomic commercial multi-bucket reservation operations.
-- All KEYS must share one Redis Cluster hash tag.
-- KEYS: reservation, idempotency, active-count, period-policy, bucket counters,
--       generation metadata, stable generation pointer
-- ARGV common: operation, reservation_id, payload_digest, lease_token,
--              lease_version, generation, ttl_seconds, max_concurrency, bucket_count,
--              budget_policy_id, max_unreserved_delta, late_allowance, max_overdraft
-- ARGV bucket tuples: bucket_name, delta_microusd, limit_microusd
-- ARGV final: allow generation-one bootstrap (0/1)

local operation = ARGV[1]
local reservation_id = ARGV[2]
local payload_digest = ARGV[3]
local lease_token = ARGV[4]
local lease_version = tonumber(ARGV[5])
local generation = tonumber(ARGV[6])
local ttl_seconds = tonumber(ARGV[7])
local max_concurrency = tonumber(ARGV[8])
local bucket_count = tonumber(ARGV[9])
local budget_policy_id = ARGV[10]
local max_unreserved_delta = tonumber(ARGV[11])
local late_allowance = tonumber(ARGV[12])
local max_overdraft = tonumber(ARGV[13])
local max_safe_integer = 4503599627370495
local bootstrap_raw = ARGV[14 + (bucket_count * 3)]

local function expire_at_least(key, seconds)
  local current_ttl = tonumber(redis.call("TTL", key))
  if current_ttl == -1 or (current_ttl >= 0 and current_ttl < seconds) then
    redis.call("EXPIRE", key, seconds)
  end
end

local function read_nonnegative_counter(key)
  local raw = redis.call("GET", key)
  if not raw then return 0 end
  local value = tonumber(raw)
  if not string.match(raw, "^%d+$") or not value
     or value < 0 or value > max_safe_integer or value ~= math.floor(value) then
    return nil
  end
  return value
end

local function exact_nonnegative(value)
  return value and value >= 0 and value <= max_safe_integer
     and value == math.floor(value)
end

local function exact_positive(value)
  return exact_nonnegative(value) and value > 0
end

local function command_policy_is_safe()
  if not exact_positive(lease_version) or not exact_positive(generation)
     or not exact_positive(ttl_seconds) or not exact_positive(max_concurrency)
     or not exact_positive(bucket_count) or not exact_nonnegative(max_unreserved_delta)
     or not exact_nonnegative(late_allowance) or not exact_nonnegative(max_overdraft)
     or late_allowance > max_overdraft
     or #KEYS ~= 6 + bucket_count
     or #ARGV ~= 14 + (bucket_count * 3)
     or (bootstrap_raw ~= "0" and bootstrap_raw ~= "1") then
    return false
  end
  if max_unreserved_delta > 0
     and max_concurrency > math.floor(
       (max_overdraft - late_allowance) / max_unreserved_delta) then
    return false
  end
  local technical_delta = nil
  local technical_limit = nil
  local nontechnical_delta = 0
  local nontechnical_limit = 0
  for i = 1, bucket_count do
    local offset = 14 + ((i - 1) * 3)
    local bucket = ARGV[offset]
    local delta = tonumber(ARGV[offset + 1])
    local limit = tonumber(ARGV[offset + 2])
    if not bucket or bucket == "" or not exact_nonnegative(delta)
       or not exact_positive(limit) or delta > limit then
      return false
    end
    if bucket == "technical" then
      technical_delta = delta
      technical_limit = limit
    else
      nontechnical_delta = nontechnical_delta + delta
      nontechnical_limit = nontechnical_limit + limit
      if nontechnical_delta > max_safe_integer
         or nontechnical_limit > max_safe_integer then return false end
    end
  end
  return technical_delta ~= nil and technical_limit ~= nil
     and technical_delta >= nontechnical_delta
     and technical_limit >= nontechnical_limit
end

local function generation_is_ready()
  local metadata_key = KEYS[5 + bucket_count]
  local pointer_key = KEYS[6 + bucket_count]
  local metadata_exists = redis.call("EXISTS", metadata_key) == 1
  local pointer_exists = redis.call("EXISTS", pointer_key) == 1
  if not metadata_exists and not pointer_exists then
    for i = 1, 4 + bucket_count do
      if redis.call("EXISTS", KEYS[i]) == 1 then return false, false, false end
    end
    if operation == "release" and generation == 1 and bootstrap_raw == "1" then
      return false, true, false
    end
    if operation ~= "reserve" or generation ~= 1 or bootstrap_raw ~= "1" then
      return false, false, false
    end
    local bootstrap_digest = "sha256:" .. string.rep("0", 64)
    redis.call("HSET", metadata_key,
      "generation", 1, "expected_generation", 1,
      "snapshot_sha256", bootstrap_digest, "state", "ready")
    redis.call("HSET", pointer_key,
      "generation", 1, "snapshot_sha256", bootstrap_digest)
    redis.call("PERSIST", metadata_key)
    redis.call("PERSIST", pointer_key)
    return true, false, true
  end
  if not metadata_exists or not pointer_exists then return false, false, false end
  local metadata_digest = redis.call("HGET", metadata_key, "snapshot_sha256")
  return redis.call("HGET", metadata_key, "generation") == ARGV[6]
     and redis.call("HGET", metadata_key, "state") == "ready"
     and metadata_digest ~= false
     and redis.call("HGET", pointer_key, "generation") == ARGV[6]
     and redis.call("HGET", pointer_key, "snapshot_sha256") == metadata_digest,
     false, false
end

local function refresh_state_retention()
  expire_at_least(KEYS[1], ttl_seconds)
  expire_at_least(KEYS[2], ttl_seconds)
  redis.call("PERSIST", KEYS[3])
  redis.call("PERSIST", KEYS[4])
  for i = 1, bucket_count do redis.call("PERSIST", KEYS[4 + i]) end
  redis.call("PERSIST", KEYS[5 + bucket_count])
  redis.call("PERSIST", KEYS[6 + bucket_count])
end

local function response(decision, reason, replayed)
  local holds = {}
  for i = 1, bucket_count do
    local offset = 14 + ((i - 1) * 3)
    local bucket = ARGV[offset]
    local held = redis.call("HGET", KEYS[1], "hold:" .. bucket) or "0"
    local parsed = tonumber(held)
    if not string.match(held, "^%d+$") or not parsed
       or parsed < 0 or parsed > max_safe_integer
       or parsed ~= math.floor(parsed) then held = "0" end
    holds[bucket] = held
  end
  local authoritative_lease_version =
    redis.call("HGET", KEYS[1], "lease_version") or tostring(lease_version)
  local authoritative_generation =
    redis.call("HGET", KEYS[1], "generation") or tostring(generation)
  local parsed_lease_version = tonumber(authoritative_lease_version)
  local parsed_generation = tonumber(authoritative_generation)
  if not string.match(authoritative_lease_version, "^%d+$")
     or not exact_positive(parsed_lease_version) then
    authoritative_lease_version = tostring(lease_version)
  end
  if not string.match(authoritative_generation, "^%d+$")
     or not exact_positive(parsed_generation) then
    authoritative_generation = tostring(generation)
  end
  local active = redis.call("GET", KEYS[3]) or "0"
  if not string.match(active, "^%d+$")
     or read_nonnegative_counter(KEYS[3]) == nil then active = "0" end
  return cjson.encode({
    decision = decision,
    reason_code = reason,
    reservation_id = reservation_id,
    lease_version = authoritative_lease_version,
    generation = authoritative_generation,
    replayed = replayed,
    holds_by_bucket_microusd = holds,
    active_reservations = active
  })
end

local function policy_matches()
  if redis.call("EXISTS", KEYS[4]) == 0 then return false end
  if redis.call("HGET", KEYS[4], "budget_policy_id") ~= budget_policy_id
     or redis.call("HGET", KEYS[4], "generation") ~= ARGV[6]
     or redis.call("HGET", KEYS[4], "max_concurrency") ~= ARGV[8]
     or redis.call("HGET", KEYS[4], "max_unreserved_delta") ~= ARGV[11]
     or redis.call("HGET", KEYS[4], "late_allowance") ~= ARGV[12]
     or redis.call("HGET", KEYS[4], "max_overdraft") ~= ARGV[13]
     or redis.call("HGET", KEYS[4], "bucket_count") ~= ARGV[9] then
    return false
  end
  for i = 1, bucket_count do
    local offset = 14 + ((i - 1) * 3)
    local bucket = ARGV[offset]
    local limit = ARGV[offset + 2]
    if redis.call("HGET", KEYS[4], "bucket:" .. i) ~= bucket
       or redis.call("HGET", KEYS[4], "limit:" .. bucket) ~= limit then
      return false
    end
  end
  return true
end

local function counters_exist()
  if redis.call("EXISTS", KEYS[3]) == 0 then return false end
  for i = 1, bucket_count do
    if redis.call("EXISTS", KEYS[4 + i]) == 0 then return false end
  end
  return true
end

local function any_counter_exists()
  if redis.call("EXISTS", KEYS[3]) == 1 then return true end
  for i = 1, bucket_count do
    if redis.call("EXISTS", KEYS[4 + i]) == 1 then return true end
  end
  return false
end

local function idempotency_matches(expected_operation)
  return redis.call("HGET", KEYS[2], "reservation_id") == reservation_id
     and redis.call("HGET", KEYS[2], "payload_digest") == payload_digest
     and redis.call("HGET", KEYS[2], "operation") == expected_operation
     and redis.call("HGET", KEYS[2], "lease_token") == lease_token
     and redis.call("HGET", KEYS[2], "lease_version") == ARGV[5]
     and redis.call("HGET", KEYS[2], "generation") == ARGV[6]
end

local function write_idempotency(expected_operation, decision, reason)
  redis.call("HSET", KEYS[2], "reservation_id", reservation_id,
    "payload_digest", payload_digest, "operation", expected_operation,
    "lease_token", lease_token, "lease_version", lease_version,
    "generation", generation, "decision", decision or "allow",
    "reason_code", reason or "budget.identical_replay")
end

local function reservation_fence_matches()
  return redis.call("HGET", KEYS[1], "lease_token") == lease_token
     and redis.call("HGET", KEYS[1], "lease_version") == ARGV[5]
     and redis.call("HGET", KEYS[1], "generation") == ARGV[6]
end

local function read_reservation_hold(bucket)
  local raw = redis.call("HGET", KEYS[1], "hold:" .. bucket)
  if not raw then return nil end
  local value = tonumber(raw)
  if not string.match(raw, "^%d+$") or not exact_nonnegative(value) then
    return nil
  end
  return value
end

local function reservation_holds_are_valid()
  if redis.call("HGET", KEYS[1], "bucket_count") ~= ARGV[9] then
    return false
  end
  for i = 1, bucket_count do
    local offset = 14 + ((i - 1) * 3)
    local bucket = ARGV[offset]
    if redis.call("HGET", KEYS[1], "bucket:" .. i) ~= bucket
       or read_reservation_hold(bucket) == nil then
      return false
    end
  end
  return true
end

local function record_reserve_block(reason)
  if redis.call("HGET", KEYS[2], "operation") == "reserve" then
    local stored_decision = redis.call("HGET", KEYS[2], "decision")
    if not stored_decision or stored_decision == "allow" then
      return response("block", reason, false)
    end
  end
  write_idempotency("reserve", "block", reason)
  expire_at_least(KEYS[2], ttl_seconds)
  return response("block", reason, false)
end

if not command_policy_is_safe() then
  return response("block", "budget.policy_invalid", false)
end
local generation_ready, pristine_release_missing, bootstrap_created =
  generation_is_ready()
if pristine_release_missing then
  return response("block", "budget.reservation_missing", false)
end
if not generation_ready then
  return response("block", "budget.generation_not_ready", false)
end

if operation == "reserve" then
  local existing_reservation = redis.call("HGET", KEYS[2], "reservation_id")
  if existing_reservation then
    if not idempotency_matches("reserve") then
      return response("block", "budget.idempotency_conflict", false)
    end
    local prior_decision = redis.call("HGET", KEYS[2], "decision") or "allow"
    local prior_reason = redis.call("HGET", KEYS[2], "reason_code")
      or "budget.identical_replay"
    if prior_decision == "block" then
      expire_at_least(KEYS[2], ttl_seconds)
      return response("block", prior_reason, true)
    end
  end
  if redis.call("EXISTS", KEYS[4]) == 1 then
    if not policy_matches() then
      return record_reserve_block("budget.policy_mismatch")
    end
    if not counters_exist() then
      return record_reserve_block("budget.counter_corrupt")
    end
  elseif any_counter_exists() then
    return record_reserve_block("budget.counter_corrupt")
  elseif not bootstrap_created then
    return response("block", "budget.generation_not_ready", false)
  end
  if existing_reservation then
    if redis.call("EXISTS", KEYS[1]) == 0 then
      return response("block", "budget.idempotency_orphan", false)
    end
    if not reservation_fence_matches() then
      return response("block", "budget.stale_fence", false)
    end
    if not reservation_holds_are_valid() then
      return record_reserve_block("budget.counter_corrupt")
    end
    if redis.call("HGET", KEYS[1], "state") ~= "reserved" then
      return response("block", "budget.reservation_terminal_replay", true)
    end
    refresh_state_retention()
    return response("allow", "budget.identical_replay", true)
  end
  if redis.call("EXISTS", KEYS[1]) == 1 then
    return response("block", "budget.reservation_conflict", false)
  end
  local active = read_nonnegative_counter(KEYS[3])
  if active == nil then return record_reserve_block("budget.counter_corrupt") end
  if active >= max_concurrency then
    return record_reserve_block("budget.concurrency_limit")
  end
  for i = 1, bucket_count do
    local offset = 14 + ((i - 1) * 3)
    local delta = tonumber(ARGV[offset + 1])
    local limit = tonumber(ARGV[offset + 2])
    local current = read_nonnegative_counter(KEYS[4 + i])
    if current == nil then return record_reserve_block("budget.counter_corrupt") end
    if current > limit - delta then
      return record_reserve_block("budget.bucket_limit")
    end
  end
  redis.call("HSET", KEYS[1],
    "reservation_id", reservation_id, "payload_digest", payload_digest,
    "lease_token", lease_token, "lease_version", lease_version,
    "generation", generation, "state", "reserved", "active", 1,
    "bucket_count", bucket_count)
  write_idempotency("reserve", "allow", "budget.reserved")
  if redis.call("EXISTS", KEYS[4]) == 0 then
    redis.call("HSET", KEYS[4], "budget_policy_id", budget_policy_id,
      "generation", generation,
      "max_concurrency", max_concurrency,
      "max_unreserved_delta", max_unreserved_delta,
      "late_allowance", late_allowance,
      "max_overdraft", max_overdraft,
      "bucket_count", bucket_count)
    for i = 1, bucket_count do
      local offset = 14 + ((i - 1) * 3)
      local bucket = ARGV[offset]
      redis.call("HSET", KEYS[4], "bucket:" .. i, bucket,
        "limit:" .. bucket, ARGV[offset + 2])
    end
  end
  redis.call("INCR", KEYS[3])
  for i = 1, bucket_count do
    local offset = 14 + ((i - 1) * 3)
    local bucket = ARGV[offset]
    local delta = tonumber(ARGV[offset + 1])
    redis.call("INCRBY", KEYS[4 + i], delta)
    redis.call("HSET", KEYS[1], "hold:" .. bucket, delta)
    redis.call("HSET", KEYS[1], "bucket:" .. i, bucket)
  end
  refresh_state_retention()
  return response("allow", "budget.reserved", false)
end

if redis.call("EXISTS", KEYS[1]) == 0 then
  return response("block", "budget.reservation_missing", false)
end
if redis.call("EXISTS", KEYS[4]) == 0 or not counters_exist() then
  return response("block", "budget.counter_corrupt", false)
end
if not policy_matches() then
  return response("block", "budget.policy_mismatch", false)
end
local existing_mutation_reservation = redis.call("HGET", KEYS[2], "reservation_id")
if existing_mutation_reservation then
  if not idempotency_matches(operation) then
    return response("block", "budget.idempotency_conflict", false)
  end
end
if existing_mutation_reservation then
  local current_lease_raw = redis.call("HGET", KEYS[1], "lease_version")
  local current_lease = tonumber(current_lease_raw)
  if redis.call("HGET", KEYS[1], "lease_token") ~= lease_token
     or redis.call("HGET", KEYS[1], "generation") ~= ARGV[6]
     or not current_lease_raw or not string.match(current_lease_raw, "^%d+$")
     or not exact_positive(current_lease) or current_lease < lease_version then
    return response("block", "budget.stale_fence", false)
  end
elseif not reservation_fence_matches() then
  return response("block", "budget.stale_fence", false)
end
if redis.call("HGET", KEYS[1], "bucket_count") ~= ARGV[9] then
  return response("block", "budget.bucket_set_mismatch", false)
end
for i = 1, bucket_count do
  local offset = 14 + ((i - 1) * 3)
  if redis.call("HGET", KEYS[1], "bucket:" .. i) ~= ARGV[offset] then
    return response("block", "budget.bucket_set_mismatch", false)
  end
  if read_reservation_hold(ARGV[offset]) == nil then
    return response("block", "budget.counter_corrupt", false)
  end
end
local reservation_state = redis.call("HGET", KEYS[1], "state")
local reservation_active = redis.call("HGET", KEYS[1], "active")
if reservation_active ~= "0" and reservation_active ~= "1" then
  return response("block", "budget.counter_corrupt", false)
end
local reservation_is_live = reservation_active == "1"
  and (reservation_state == "reserved" or reservation_state == "partially_settled"
       or reservation_state == "overdrawn")
local reservation_is_released = reservation_active == "0"
  and reservation_state == "released"
local reservation_is_terminal = reservation_active == "0"
  and (reservation_state == "released" or reservation_state == "settled"
       or reservation_state == "overdrawn" or reservation_state == "expired")
if existing_mutation_reservation then
  if not reservation_is_live and not reservation_is_terminal then
    return response("block", "budget.invalid_state", false)
  end
  refresh_state_retention()
  return response(
    redis.call("HGET", KEYS[2], "decision") or "allow",
    redis.call("HGET", KEYS[2], "reason_code") or "budget.identical_replay",
    true)
end
if not reservation_is_live then
  if operation == "release" and reservation_state == "released"
     and reservation_is_released then
    write_idempotency("release", "allow", "budget.release_replay")
    refresh_state_retention()
    return response("allow", "budget.release_replay", true)
  end
  return response("block", "budget.invalid_state", false)
end

if operation == "top_up" then
  for i = 1, bucket_count do
    local offset = 14 + ((i - 1) * 3)
    local delta = tonumber(ARGV[offset + 1])
    local limit = tonumber(ARGV[offset + 2])
    local current = read_nonnegative_counter(KEYS[4 + i])
    local held = read_reservation_hold(ARGV[offset])
    if current == nil then return response("block", "budget.counter_corrupt", false) end
    if held == nil or held > max_safe_integer - delta then
      return response("block", "budget.counter_corrupt", false)
    end
    if current > limit - delta then
      write_idempotency("top_up", "block", "budget.bucket_limit")
      refresh_state_retention()
      return response("block", "budget.bucket_limit", false)
    end
  end
  for i = 1, bucket_count do
    local offset = 14 + ((i - 1) * 3)
    local bucket = ARGV[offset]
    local delta = tonumber(ARGV[offset + 1])
    redis.call("INCRBY", KEYS[4 + i], delta)
    redis.call("HINCRBY", KEYS[1], "hold:" .. bucket, delta)
  end
  write_idempotency("top_up", "allow", "budget.topped_up")
  refresh_state_retention()
  return response("allow", "budget.topped_up", false)
end

if operation == "release" then
  local active = read_nonnegative_counter(KEYS[3])
  if active == nil or active <= 0 then
    return response("block", "budget.counter_corrupt", false)
  end
  for i = 1, bucket_count do
    local offset = 14 + ((i - 1) * 3)
    local bucket = ARGV[offset]
    local held = read_reservation_hold(bucket)
    local current = read_nonnegative_counter(KEYS[4 + i])
    if held == nil or current == nil or held > current then
      return response("block", "budget.counter_corrupt", false)
    end
  end
  for i = 1, bucket_count do
    local offset = 14 + ((i - 1) * 3)
    local bucket = ARGV[offset]
    local held = read_reservation_hold(bucket)
    if held > 0 then redis.call("DECRBY", KEYS[4 + i], held) end
    redis.call("HSET", KEYS[1], "hold:" .. bucket, 0)
  end
  redis.call("HSET", KEYS[1], "state", "released")
  redis.call("HSET", KEYS[1], "active", 0)
  redis.call("DECR", KEYS[3])
  write_idempotency("release", "allow", "budget.released")
  refresh_state_retention()
  return response("allow", "budget.released", false)
end

return response("block", "budget.operation_invalid", false)
