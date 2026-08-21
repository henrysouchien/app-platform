local leases = KEYS[2]
local lease_key = KEYS[3]
local idem_key = KEYS[4]
local lease_id = ARGV[1]
local lease_token = ARGV[2]
local lease_version = ARGV[3]
local digest = ARGV[4]
local generation = ARGV[5]

if redis.call('HGET', KEYS[5], 'generation') ~= generation then
  return redis.error_reply('token-limit generation is not current')
end

local prior_digest = redis.call('HGET', idem_key, 'digest')
local prior_response = redis.call('HGET', idem_key, 'response')
if prior_digest ~= digest or not prior_response then
  return redis.error_reply('token-limit compensation identity mismatch')
end
local decoded = cjson.decode(prior_response)
if decoded.reason_code == 'limit.compensated' then
  decoded.replayed = true
  return cjson.encode(decoded)
end
if decoded.decision ~= 'allow' then
  return redis.error_reply('only allowed admission can be compensated')
end
if redis.call('HGET', lease_key, 'lease_id') ~= lease_id
  or redis.call('HGET', lease_key, 'lease_token') ~= lease_token
  or redis.call('HGET', lease_key, 'lease_version') ~= lease_version
  or redis.call('HGET', lease_key, 'digest') ~= digest then
  return redis.error_reply('token-limit lease fence mismatch')
end
local counters = KEYS[1]
local admitted_minute = redis.call('HGET', lease_key, 'minute_start')
local admitted_day = redis.call('HGET', lease_key, 'day_start')
local minute_matches = admitted_minute
  and redis.call('HGET', counters, 'minute_start') == admitted_minute
local day_matches = admitted_day
  and redis.call('HGET', counters, 'day_start') == admitted_day
local minute_count = tonumber(redis.call('HGET', counters, 'minute_count') or '0')
local day_count = tonumber(redis.call('HGET', counters, 'day_count') or '0')
if minute_matches and minute_count < 1 then
  return redis.error_reply('token-limit minute counter is corrupt')
end
if day_matches and day_count < 1 then
  return redis.error_reply('token-limit day counter is corrupt')
end
if minute_matches then
  redis.call('HINCRBY', counters, 'minute_count', -1)
  decoded.minute_count = minute_count - 1
end
if day_matches then
  redis.call('HINCRBY', counters, 'day_count', -1)
  decoded.day_count = day_count - 1
end
redis.call('ZREM', leases, lease_id)
redis.call('DEL', lease_key)
local active = tonumber(redis.call('ZCARD', leases))
decoded.decision = 'block'
decoded.reason_code = 'limit.compensated'
decoded.replayed = false
decoded.active_workflows = active
decoded.retry_at_epoch = cjson.null
local encoded = cjson.encode(decoded)
redis.call('HSET', idem_key, 'response', encoded)
return encoded
