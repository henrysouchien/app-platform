-- Atomic fenced commercial reservation heartbeat.
-- KEYS: reservation, idempotency marker, active counter, policy, bucket counters,
--       generation metadata, stable generation pointer
-- ARGV: reservation_id, payload_digest, lease_token, lease_version, generation,
--       ttl_seconds, bucket_count, heartbeat_at, recovery_only, bucket names...

local reservation_id = ARGV[1]
local payload_digest = ARGV[2]
local lease_token = ARGV[3]
local lease_version_raw = ARGV[4]
local generation_raw = ARGV[5]
local ttl_seconds_raw = ARGV[6]
local bucket_count_raw = ARGV[7]
local heartbeat_at = ARGV[8]
local recovery_only = ARGV[9]
local lease_version = tonumber(lease_version_raw)
local generation = tonumber(generation_raw)
local ttl_seconds = tonumber(ttl_seconds_raw)
local bucket_count = tonumber(bucket_count_raw)
local max_safe_integer = 4503599627370495

local function exact_positive(value)
  return value and value > 0 and value <= max_safe_integer
     and value == math.floor(value)
end

local function canonical_positive(raw, value)
  return raw and string.match(raw, "^[1-9]%d*$")
     and exact_positive(value) and raw == tostring(value)
end

local function expire_at_least(key, seconds)
  local current = tonumber(redis.call("TTL", key))
  if current == -1 or (current >= 0 and current < seconds) then
    redis.call("EXPIRE", key, seconds)
  end
end

local function response(decision, reason, replayed, committed, committed_heartbeat_at)
  return cjson.encode({decision = decision, reason_code = reason,
    reservation_id = reservation_id, lease_version = committed,
    generation = generation, replayed = replayed,
    heartbeat_at = committed_heartbeat_at or heartbeat_at})
end

if not canonical_positive(lease_version_raw, lease_version)
   or not canonical_positive(generation_raw, generation)
   or not canonical_positive(ttl_seconds_raw, ttl_seconds)
   or not canonical_positive(bucket_count_raw, bucket_count)
   or #KEYS ~= 6 + bucket_count
   or #ARGV ~= 9 + bucket_count
   or not heartbeat_at or heartbeat_at == ""
   or (recovery_only ~= "0" and recovery_only ~= "1") then
  return response("block", "budget.heartbeat_invalid", false, lease_version or 1)
end

local metadata_key = KEYS[5 + bucket_count]
local pointer_key = KEYS[6 + bucket_count]
local metadata_digest = redis.call("HGET", metadata_key, "snapshot_sha256")
if redis.call("HGET", metadata_key, "generation") ~= generation_raw
   or redis.call("HGET", metadata_key, "state") ~= "ready"
   or not metadata_digest
   or redis.call("HGET", pointer_key, "generation") ~= generation_raw
   or redis.call("HGET", pointer_key, "snapshot_sha256") ~= metadata_digest then
  return response("block", "budget.generation_not_ready", false, lease_version)
end

local seen = {}
for i = 1, bucket_count do
  local bucket = ARGV[9 + i]
  if not bucket or bucket == "" or seen[bucket] then
    return response("block", "budget.heartbeat_invalid", false, lease_version)
  end
  seen[bucket] = true
end

local existing = redis.call("HGET", KEYS[2], "reservation_id")
if existing then
  local committed_raw = redis.call("HGET", KEYS[2], "committed_lease_version")
  local committed = tonumber(committed_raw)
  local current_raw = redis.call("HGET", KEYS[1], "lease_version")
  local current = tonumber(current_raw)
  local committed_heartbeat_at = redis.call("HGET", KEYS[2], "heartbeat_at")
  local state = redis.call("HGET", KEYS[1], "state")
  if existing ~= reservation_id
     or redis.call("HGET", KEYS[2], "payload_digest") ~= payload_digest
     or redis.call("HGET", KEYS[2], "lease_token") ~= lease_token
     or redis.call("HGET", KEYS[2], "lease_version") ~= ARGV[4]
     or redis.call("HGET", KEYS[2], "generation") ~= ARGV[5] then
    return response("block", "budget.idempotency_conflict", false, lease_version)
  end
  if not canonical_positive(committed_raw, committed)
     or committed ~= lease_version + 1
     or not canonical_positive(current_raw, current)
     or current ~= committed
     or redis.call("HGET", KEYS[1], "lease_token") ~= lease_token
     or redis.call("HGET", KEYS[1], "generation") ~= ARGV[5]
     or redis.call("HGET", KEYS[1], "active") ~= "1"
     or (state ~= "reserved" and state ~= "partially_settled"
         and state ~= "overdrawn")
     or redis.call("HGET", KEYS[1], "bucket_count") ~= ARGV[7]
     or redis.call("EXISTS", KEYS[3]) == 0
     or redis.call("EXISTS", KEYS[4]) == 0
     or redis.call("HGET", KEYS[4], "generation") ~= ARGV[5]
     or redis.call("HGET", KEYS[4], "bucket_count") ~= ARGV[7]
     or not committed_heartbeat_at then
    return response("block", "budget.counter_corrupt", false, lease_version)
  end
  for i = 1, bucket_count do
    local bucket = ARGV[9 + i]
    if redis.call("HGET", KEYS[1], "bucket:" .. i) ~= bucket
       or redis.call("HGET", KEYS[4], "bucket:" .. i) ~= bucket
       or redis.call("EXISTS", KEYS[4 + i]) == 0 then
      return response("block", "budget.counter_corrupt", false, lease_version)
    end
  end
  expire_at_least(KEYS[1], ttl_seconds)
  expire_at_least(KEYS[2], ttl_seconds)
  return response("allow", "budget.heartbeat_replay", true, committed,
    committed_heartbeat_at)
end

if recovery_only == "1" then
  return response("block", "budget.heartbeat_recovery_missing", false, lease_version)
end

if redis.call("EXISTS", KEYS[1]) == 0
   or redis.call("EXISTS", KEYS[3]) == 0
   or redis.call("EXISTS", KEYS[4]) == 0 then
  return response("block", "budget.counter_corrupt", false, lease_version)
end
local state = redis.call("HGET", KEYS[1], "state")
if redis.call("HGET", KEYS[1], "active") ~= "1"
   or (state ~= "reserved" and state ~= "partially_settled" and state ~= "overdrawn") then
  return response("block", "budget.invalid_state", false, lease_version)
end
if redis.call("HGET", KEYS[1], "lease_token") ~= lease_token
   or redis.call("HGET", KEYS[1], "lease_version") ~= ARGV[4]
   or redis.call("HGET", KEYS[1], "generation") ~= ARGV[5]
   or redis.call("HGET", KEYS[1], "bucket_count") ~= ARGV[7]
   or redis.call("HGET", KEYS[4], "generation") ~= ARGV[5]
   or redis.call("HGET", KEYS[4], "bucket_count") ~= ARGV[7] then
  return response("block", "budget.stale_fence", false, lease_version)
end
if lease_version >= max_safe_integer then
  return response("block", "budget.counter_overflow", false, lease_version)
end
for i = 1, bucket_count do
  local bucket = ARGV[9 + i]
  if not bucket or bucket == ""
     or redis.call("HGET", KEYS[1], "bucket:" .. i) ~= bucket
     or redis.call("HGET", KEYS[4], "bucket:" .. i) ~= bucket
     or redis.call("EXISTS", KEYS[4 + i]) == 0 then
    return response("block", "budget.counter_corrupt", false, lease_version)
  end
end

local committed = lease_version + 1
redis.call("HSET", KEYS[1], "lease_version", committed)
redis.call("HSET", KEYS[2], "reservation_id", reservation_id,
  "payload_digest", payload_digest, "lease_token", lease_token,
  "lease_version", lease_version, "committed_lease_version", committed,
  "generation", generation, "heartbeat_at", heartbeat_at)
expire_at_least(KEYS[1], ttl_seconds)
expire_at_least(KEYS[2], ttl_seconds)
redis.call("PERSIST", KEYS[3])
redis.call("PERSIST", KEYS[4])
for i = 1, bucket_count do redis.call("PERSIST", KEYS[4 + i]) end
return response("allow", "budget.heartbeat", false, committed)
