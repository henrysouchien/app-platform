-- Compare-and-set the stable period generation pointer.
-- KEYS: stable pointer, target metadata, active, late-used, policy, two buckets,
--       reservations...
-- ARGV: expected generation, target generation, snapshot digest, reservation count.

local max_safe_raw = "4503599627370495"

local function canonical_nonnegative(raw)
  if not raw or not string.match(raw, "^%d+$") then return false end
  if raw ~= "0" and string.sub(raw, 1, 1) == "0" then return false end
  if string.len(raw) > string.len(max_safe_raw)
     or (string.len(raw) == string.len(max_safe_raw) and raw > max_safe_raw) then
    return false
  end
  local value = tonumber(raw)
  return value and value >= 0 and value == math.floor(value)
end

local function canonical_positive(raw)
  return canonical_nonnegative(raw) and raw ~= "0"
end

local expected = ARGV[1]
local target = ARGV[2]
local digest = ARGV[3]
local reservation_count_raw = ARGV[4]
local reservation_count = tonumber(reservation_count_raw)

local function response(decision, reason, replayed)
  return cjson.encode({
    decision = decision,
    reason_code = reason,
    generation = tonumber(target) or 1,
    snapshot_sha256 = digest or ("sha256:" .. string.rep("0", 64)),
    replayed = replayed
  })
end

if #ARGV ~= 4 or not canonical_positive(expected)
   or not canonical_positive(target)
   or tonumber(target) <= tonumber(expected)
   or not canonical_nonnegative(reservation_count_raw)
   or #KEYS ~= 7 + reservation_count
   or not digest or string.len(digest) ~= 71
   or not string.match(digest, "^sha256:[0-9a-f]+$") then
  return response("block", "budget.generation_cas_invalid", false)
end

if redis.call("HGET", KEYS[2], "generation") ~= target
   or redis.call("HGET", KEYS[2], "snapshot_sha256") ~= digest
   or redis.call("HGET", KEYS[2], "state") ~= "ready"
   or redis.call("HGET", KEYS[2], "reservation_count") ~= reservation_count_raw
   or redis.call("EXISTS", KEYS[3]) == 0
   or not canonical_nonnegative(redis.call("GET", KEYS[3]))
   or redis.call("EXISTS", KEYS[4]) == 0
   or not canonical_nonnegative(redis.call("GET", KEYS[4]))
   or redis.call("HGET", KEYS[5], "generation") ~= target
   or redis.call("HGET", KEYS[5], "bucket_count") ~= "2"
   or redis.call("HGET", KEYS[5], "bucket:1") ~= "model"
   or redis.call("HGET", KEYS[5], "bucket:2") ~= "technical"
   or redis.call("EXISTS", KEYS[6]) == 0
   or not canonical_nonnegative(redis.call("GET", KEYS[6]))
   or redis.call("EXISTS", KEYS[7]) == 0
   or not canonical_nonnegative(redis.call("GET", KEYS[7])) then
  return response("block", "budget.generation_target_not_ready", false)
end
for i = 1, reservation_count do
  if redis.call("HGET", KEYS[7 + i], "generation") ~= target then
    return response("block", "budget.generation_target_not_ready", false)
  end
end

local current = redis.call("HGET", KEYS[1], "generation")
if current == target then
  if redis.call("HGET", KEYS[1], "snapshot_sha256") == digest then
    return response("allow", "budget.generation_cas_replay", true)
  end
  return response("block", "budget.generation_cas_conflict", false)
end
if current and current ~= expected then
  return response("block", "budget.generation_cas_stale", false)
end
redis.call("HSET", KEYS[1], "generation", target, "snapshot_sha256", digest)
redis.call("PERSIST", KEYS[1])
return response("allow", "budget.generation_swapped", false)
