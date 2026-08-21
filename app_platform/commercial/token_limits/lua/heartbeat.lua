local leases, lease_key, idem_key = KEYS[1], KEYS[2], KEYS[3]
local lease_id, lease_token, version = ARGV[1], ARGV[2], ARGV[3]
local digest, new_expiry = ARGV[4], tonumber(ARGV[5])
local generation = ARGV[6]
if redis.call('HGET', KEYS[4], 'generation') ~= generation then
  return redis.error_reply('token-limit generation is not current')
end
local prior = redis.call('HGET', idem_key, 'digest')
if prior then
  if prior ~= digest then return redis.error_reply('token-limit heartbeat idempotency conflict') end
  local response = redis.call('HGET', idem_key, 'response')
  if not response then return redis.error_reply('token-limit heartbeat replay is corrupt') end
  local result = cjson.decode(response); result.replayed = true
  return cjson.encode(result)
end
local now = tonumber(redis.call('TIME')[1])
local current_expiry = tonumber(redis.call('HGET', lease_key, 'expires_at') or '0')
if redis.call('HGET', lease_key, 'lease_id') ~= lease_id
  or redis.call('HGET', lease_key, 'lease_token') ~= lease_token
  or redis.call('HGET', lease_key, 'lease_version') ~= version then
  return redis.error_reply('token-limit heartbeat fence mismatch')
end
if now >= current_expiry then return redis.error_reply('token-limit lease already expired') end
if not new_expiry or new_expiry <= current_expiry or new_expiry <= now or new_expiry > now + 3600 then
  return redis.error_reply('invalid token-limit heartbeat expiry')
end
local next_version = tonumber(version) + 1
redis.call('HSET', lease_key, 'lease_version', next_version, 'expires_at', new_expiry)
redis.call('EXPIREAT', lease_key, new_expiry + 60)
redis.call('ZADD', leases, new_expiry, lease_id)
redis.call('EXPIREAT', leases, new_expiry + 86460)
local result = {outcome='heartbeat', reason_code='limit.heartbeat', lease_id=lease_id,
  lease_version=next_version, expires_at_epoch=new_expiry,
  active_workflows=tonumber(redis.call('ZCARD', leases)), replayed=false}
local encoded = cjson.encode(result)
redis.call('HSET', idem_key, 'digest', digest, 'response', encoded)
redis.call('EXPIRE', idem_key, 86520)
return encoded
