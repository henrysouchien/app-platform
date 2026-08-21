local leases, lease_key, idem_key = KEYS[1], KEYS[2], KEYS[3]
local lease_id, lease_token, version = ARGV[1], ARGV[2], ARGV[3]
local digest, observed_expiry = ARGV[4], tonumber(ARGV[5])
local generation = ARGV[6]
if redis.call('HGET', KEYS[4], 'generation') ~= generation then
  return redis.error_reply('token-limit generation is not current')
end
local prior = redis.call('HGET', idem_key, 'digest')
if prior then
  if prior ~= digest then return redis.error_reply('token-limit reap idempotency conflict') end
  local response = redis.call('HGET', idem_key, 'response')
  if not response then return redis.error_reply('token-limit reap replay is corrupt') end
  local result = cjson.decode(response); result.replayed = true
  return cjson.encode(result)
end
local now = tonumber(redis.call('TIME')[1])
if redis.call('HGET', lease_key, 'lease_id') ~= lease_id
  or redis.call('HGET', lease_key, 'lease_token') ~= lease_token
  or redis.call('HGET', lease_key, 'lease_version') ~= version
  or tonumber(redis.call('HGET', lease_key, 'expires_at') or '0') ~= observed_expiry then
  return redis.error_reply('token-limit reap fence mismatch')
end
if now < observed_expiry then return redis.error_reply('token-limit lease has not expired') end
redis.call('ZREM', leases, lease_id); redis.call('DEL', lease_key)
local result = {outcome='expired', reason_code='limit.expired', lease_id=lease_id,
  lease_version=tonumber(version)+1, expires_at_epoch=observed_expiry,
  active_workflows=tonumber(redis.call('ZCARD', leases)), replayed=false}
local encoded = cjson.encode(result)
redis.call('HSET', idem_key, 'digest', digest, 'response', encoded)
redis.call('EXPIRE', idem_key, 86520)
return encoded
