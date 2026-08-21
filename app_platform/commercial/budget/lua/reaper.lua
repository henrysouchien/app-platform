-- Atomically expire one abandoned, fenced commercial reservation.
-- KEYS: reservation, idempotency marker, active counter, policy, bucket counters,
--       generation metadata, stable generation pointer
-- ARGV: reservation_id, payload_digest, lease_token, lease_version, generation,
--       ttl_seconds, bucket_count, reason_code, bucket/expected-hold pairs...

local reservation_id = ARGV[1]
local payload_digest = ARGV[2]
local lease_token = ARGV[3]
local lease_version_raw = ARGV[4]
local generation_raw = ARGV[5]
local ttl_raw = ARGV[6]
local bucket_count_raw = ARGV[7]
local reason_code = ARGV[8]
local max_safe_integer = 4503599627370495

local function exact_positive_string(raw)
  if not raw or not string.match(raw, "^%d+$") then return nil end
  if raw ~= "0" and string.sub(raw, 1, 1) == "0" then return nil end
  local value = tonumber(raw)
  if not value or value <= 0 or value > max_safe_integer
     or value ~= math.floor(value) then return nil end
  return value
end

local function exact_nonnegative_string(raw)
  if not raw or not string.match(raw, "^%d+$") then return nil end
  if raw ~= "0" and string.sub(raw, 1, 1) == "0" then return nil end
  local value = tonumber(raw)
  if not value or value < 0 or value > max_safe_integer
     or value ~= math.floor(value) then return nil end
  return value
end

local function read_nonnegative(key)
  local raw = redis.call("GET", key)
  if not raw or not string.match(raw, "^%d+$") then return nil end
  if raw ~= "0" and string.sub(raw, 1, 1) == "0" then return nil end
  local value = tonumber(raw)
  if not value or value < 0 or value > max_safe_integer
     or value ~= math.floor(value) then return nil end
  return value
end

local function read_hold(bucket)
  local raw = redis.call("HGET", KEYS[1], "hold:" .. bucket)
  if not raw or not string.match(raw, "^%d+$") then return nil end
  if raw ~= "0" and string.sub(raw, 1, 1) == "0" then return nil end
  local value = tonumber(raw)
  if not value or value < 0 or value > max_safe_integer
     or value ~= math.floor(value) then return nil end
  return value
end

local function expire_at_least(key, seconds)
  local current = tonumber(redis.call("TTL", key))
  if current == -1 or (current >= 0 and current < seconds) then
    redis.call("EXPIRE", key, seconds)
  end
end

local lease_version = exact_positive_string(lease_version_raw)
local generation = exact_positive_string(generation_raw)
local ttl_seconds = exact_positive_string(ttl_raw)
local bucket_count = exact_positive_string(bucket_count_raw)

local function response(decision, reason, replayed, committed)
  local holds = {}
  if bucket_count then
    for i = 1, bucket_count do
      local offset = 9 + ((i - 1) * 2)
      local bucket = ARGV[offset]
      holds[bucket or ("invalid" .. i)] = ARGV[offset + 1] or "0"
    end
  end
  return cjson.encode({
    decision = decision,
    reason_code = reason,
    reservation_id = reservation_id,
    lease_version = tostring(committed or lease_version or 1),
    generation = tostring(generation or 1),
    replayed = replayed,
    holds_by_bucket_microusd = holds
  })
end

if not lease_version or not generation or not ttl_seconds or not bucket_count
   or #KEYS ~= 6 + bucket_count or #ARGV ~= 8 + (bucket_count * 2)
   or not reason_code or reason_code == ""
   or lease_version >= max_safe_integer then
  return response("block", "budget.reaper_invalid", false, lease_version)
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
  local offset = 9 + ((i - 1) * 2)
  local bucket = ARGV[offset]
  local expected = exact_nonnegative_string(ARGV[offset + 1])
  if not bucket or bucket == "" or seen[bucket] or expected == nil then
    return response("block", "budget.reaper_invalid", false, lease_version)
  end
  seen[bucket] = true
end

local existing = redis.call("HGET", KEYS[2], "reservation_id")
if existing then
  local committed_raw = redis.call("HGET", KEYS[2], "committed_lease_version")
  local committed = exact_positive_string(committed_raw)
  local current = exact_positive_string(
    redis.call("HGET", KEYS[1], "lease_version"))
  if existing ~= reservation_id
     or redis.call("HGET", KEYS[2], "payload_digest") ~= payload_digest
     or redis.call("HGET", KEYS[2], "lease_token") ~= lease_token
     or redis.call("HGET", KEYS[2], "lease_version") ~= lease_version_raw
     or redis.call("HGET", KEYS[2], "generation") ~= generation_raw
     or redis.call("HGET", KEYS[2], "reason_code") ~= reason_code then
    return response("block", "budget.idempotency_conflict", false, lease_version)
  end
  for i = 1, bucket_count do
    local offset = 9 + ((i - 1) * 2)
    local bucket = ARGV[offset]
    if redis.call("HGET", KEYS[2], "hold:" .. bucket) ~= ARGV[offset + 1] then
      return response("block", "budget.idempotency_conflict", false, lease_version)
    end
  end
  if not committed or committed ~= lease_version + 1 or not current
     or current ~= committed
     or redis.call("HGET", KEYS[1], "lease_token") ~= lease_token
     or redis.call("HGET", KEYS[1], "generation") ~= generation_raw
     or redis.call("HGET", KEYS[1], "state") ~= "expired"
     or redis.call("HGET", KEYS[1], "active") ~= "0"
     or redis.call("HGET", KEYS[1], "bucket_count") ~= bucket_count_raw
     or redis.call("EXISTS", KEYS[3]) == 0
     or redis.call("EXISTS", KEYS[4]) == 0
     or redis.call("HGET", KEYS[4], "generation") ~= generation_raw
     or redis.call("HGET", KEYS[4], "bucket_count") ~= bucket_count_raw
     or read_nonnegative(KEYS[3]) == nil then
    return response("block", "budget.counter_corrupt", false, lease_version)
  end
  for i = 1, bucket_count do
    local offset = 9 + ((i - 1) * 2)
    local bucket = ARGV[offset]
    if redis.call("HGET", KEYS[1], "bucket:" .. i) ~= bucket
       or redis.call("HGET", KEYS[4], "bucket:" .. i) ~= bucket
       or redis.call("EXISTS", KEYS[4 + i]) == 0
       or read_nonnegative(KEYS[4 + i]) == nil
       or redis.call("HGET", KEYS[1], "hold:" .. bucket) ~= "0" then
      return response("block", "budget.counter_corrupt", false, lease_version)
    end
  end
  expire_at_least(KEYS[1], ttl_seconds)
  expire_at_least(KEYS[2], ttl_seconds)
  return response("allow", "budget.expire_replay", true, committed)
end

if redis.call("EXISTS", KEYS[1]) == 0
   or redis.call("EXISTS", KEYS[3]) == 0
   or redis.call("EXISTS", KEYS[4]) == 0 then
  return response("block", "budget.counter_corrupt", false, lease_version)
end
if redis.call("HGET", KEYS[1], "lease_token") ~= lease_token
   or redis.call("HGET", KEYS[1], "lease_version") ~= lease_version_raw
   or redis.call("HGET", KEYS[1], "generation") ~= generation_raw
   or redis.call("HGET", KEYS[1], "bucket_count") ~= bucket_count_raw
   or redis.call("HGET", KEYS[4], "generation") ~= generation_raw
   or redis.call("HGET", KEYS[4], "bucket_count") ~= bucket_count_raw then
  return response("block", "budget.stale_fence", false, lease_version)
end
local state = redis.call("HGET", KEYS[1], "state")
if redis.call("HGET", KEYS[1], "active") ~= "1"
   or (state ~= "reserved" and state ~= "partially_settled"
       and state ~= "overdrawn") then
  return response("block", "budget.invalid_state", false, lease_version)
end

local active = read_nonnegative(KEYS[3])
if not active or active <= 0 then
  return response("block", "budget.counter_corrupt", false, lease_version)
end
local holds = {}
for i = 1, bucket_count do
  local offset = 9 + ((i - 1) * 2)
  local bucket = ARGV[offset]
  local expected = exact_nonnegative_string(ARGV[offset + 1])
  if redis.call("HGET", KEYS[1], "bucket:" .. i) ~= bucket
     or redis.call("HGET", KEYS[4], "bucket:" .. i) ~= bucket
     or redis.call("EXISTS", KEYS[4 + i]) == 0 then
    return response("block", "budget.counter_corrupt", false, lease_version)
  end
  local held = read_hold(bucket)
  local current = read_nonnegative(KEYS[4 + i])
  if held == nil or current == nil or expected == nil
     or held ~= expected or held > current then
    return response("block", "budget.counter_corrupt", false, lease_version)
  end
  holds[i] = held
end

for i = 1, bucket_count do
  local bucket = ARGV[9 + ((i - 1) * 2)]
  if holds[i] > 0 then redis.call("DECRBY", KEYS[4 + i], holds[i]) end
  redis.call("HSET", KEYS[1], "hold:" .. bucket, 0)
end
local committed = lease_version + 1
redis.call("DECR", KEYS[3])
redis.call("HSET", KEYS[1], "state", "expired", "active", 0,
  "lease_version", committed)
redis.call("HSET", KEYS[2], "reservation_id", reservation_id,
  "payload_digest", payload_digest, "lease_token", lease_token,
  "lease_version", lease_version, "committed_lease_version", committed,
  "generation", generation, "reason_code", reason_code)
for i = 1, bucket_count do
  local offset = 9 + ((i - 1) * 2)
  redis.call("HSET", KEYS[2], "hold:" .. ARGV[offset], ARGV[offset + 1])
end
expire_at_least(KEYS[1], ttl_seconds)
expire_at_least(KEYS[2], ttl_seconds)
redis.call("PERSIST", KEYS[3])
redis.call("PERSIST", KEYS[4])
for i = 1, bucket_count do redis.call("PERSIST", KEYS[4 + i]) end
return response("allow", reason_code, false, committed)
