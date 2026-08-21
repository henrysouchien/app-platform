local pointer = KEYS[1]
local generation = redis.call('HGET', pointer, 'generation')
local digest = redis.call('HGET', pointer, 'snapshot_sha256')
if not generation then return cjson.encode({present=false}) end
local base = string.gsub(pointer, ':generation$', '')
local prefix = base .. ':g' .. generation
local counters, leases = prefix .. ':counters', prefix .. ':leases'
local ids = redis.call('ZRANGE', leases, 0, -1)
local items = {}
for _,id in ipairs(ids) do
  local key = prefix .. ':lease:' .. id
  if redis.call('EXISTS', key) ~= 1 then return redis.error_reply('token generation lease missing') end
  table.insert(items, {lease_id=id, lease_token=redis.call('HGET', key, 'lease_token'),
    lease_version=tonumber(redis.call('HGET', key, 'lease_version')),
    expires_at_epoch=tonumber(redis.call('HGET', key, 'expires_at'))})
end
return cjson.encode({present=true, generation=tonumber(generation), snapshot_sha256=digest,
  entitlement_revision=tonumber(redis.call('HGET', counters, 'entitlement_revision')),
  policy_sha256=redis.call('HGET', counters, 'policy_digest'),
  minute_start_epoch=tonumber(redis.call('HGET', counters, 'minute_start') or '0'),
  minute_count=tonumber(redis.call('HGET', counters, 'minute_count') or '0'),
  day_start_epoch=tonumber(redis.call('HGET', counters, 'day_start') or '0'),
  day_count=tonumber(redis.call('HGET', counters, 'day_count') or '0'), leases=items})
