-- Read-only readiness check before creating a durable settlement attempt.
-- KEYS: generation metadata, stable pointer, policy, active, reservation, buckets...
-- ARGV: generation, bucket count, ordered bucket names...

local generation = ARGV[1]
local bucket_count = tonumber(ARGV[2])
if not bucket_count or bucket_count <= 0
   or bucket_count ~= math.floor(bucket_count)
   or #ARGV ~= 2 + bucket_count
   or #KEYS ~= 5 + bucket_count then
  return 0
end

local digest = redis.call("HGET", KEYS[1], "snapshot_sha256")
if redis.call("HGET", KEYS[1], "generation") ~= generation
   or redis.call("HGET", KEYS[1], "state") ~= "ready"
   or not digest
   or redis.call("HGET", KEYS[2], "generation") ~= generation
   or redis.call("HGET", KEYS[2], "snapshot_sha256") ~= digest
   or redis.call("HGET", KEYS[3], "generation") ~= generation
   or redis.call("HGET", KEYS[3], "bucket_count") ~= ARGV[2]
   or redis.call("EXISTS", KEYS[4]) == 0
   or redis.call("HGET", KEYS[5], "generation") ~= generation then
  return 0
end
for i = 1, bucket_count do
  local bucket = ARGV[2 + i]
  if not bucket or bucket == ""
     or redis.call("HGET", KEYS[3], "bucket:" .. i) ~= bucket
     or redis.call("HGET", KEYS[5], "bucket:" .. i) ~= bucket
     or redis.call("EXISTS", KEYS[5 + i]) == 0 then
    return 0
  end
end
return 1
