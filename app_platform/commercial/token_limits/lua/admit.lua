local counters = KEYS[1]
local leases = KEYS[2]
local lease_key = KEYS[3]
local idem_key = KEYS[4]
local generation_key = KEYS[5]

local workflow_id = ARGV[1]
local request_id = ARGV[2]
local lease_id = ARGV[3]
local lease_token = ARGV[4]
local lease_version = tonumber(ARGV[5])
local entitlement_revision = tonumber(ARGV[6])
local digest = ARGV[7]
local policy_digest = ARGV[8]
local expires_at = tonumber(ARGV[9])
local minute_limit = tonumber(ARGV[10])
local day_limit = tonumber(ARGV[11])
local concurrency_limit = tonumber(ARGV[12])
local generation = tonumber(ARGV[13])

if not lease_version or not entitlement_revision or not expires_at or not minute_limit
  or not day_limit or not concurrency_limit or lease_version < 1
  or entitlement_revision < 1 or not generation or generation < 1
  or minute_limit < 1 or day_limit < 1 or concurrency_limit < 1 then
  return redis.error_reply('invalid token-limit command')
end

local current_generation = redis.call('HGET', generation_key, 'generation')
if not current_generation and generation == 1 then
  redis.call('HSET', generation_key, 'generation', generation)
  current_generation = '1'
end
if current_generation ~= tostring(generation) then
  return redis.error_reply('token-limit generation is not current')
end

local prior_digest = redis.call('HGET', idem_key, 'digest')
if prior_digest then
  local response = redis.call('HGET', idem_key, 'response')
  if prior_digest == digest and response then
    local decoded = cjson.decode(response)
    decoded.replayed = true
    return cjson.encode(decoded)
  end
  return cjson.encode({decision='block', reason_code='limit.idempotency_conflict',
    lease_id=lease_id, lease_version=lease_version, replayed=false,
    minute_count=0, day_count=0, active_workflows=0, retry_at_epoch=cjson.null})
end

local clock = redis.call('TIME')
local now = tonumber(clock[1])
if expires_at <= now or expires_at > now + 3600 then
  return redis.error_reply('invalid token-limit expiry')
end
local minute_start = now - (now % 60)
local day_start = now - (now % 86400)
local stored_minute = tonumber(redis.call('HGET', counters, 'minute_start') or '-1')
local stored_day = tonumber(redis.call('HGET', counters, 'day_start') or '-1')
local minute_count = stored_minute == minute_start
  and tonumber(redis.call('HGET', counters, 'minute_count') or '0') or 0
local day_count = stored_day == day_start
  and tonumber(redis.call('HGET', counters, 'day_count') or '0') or 0

local current_revision = tonumber(redis.call('HGET', counters, 'entitlement_revision') or '0')
local current_policy = redis.call('HGET', counters, 'policy_digest')
if entitlement_revision < current_revision
  or (entitlement_revision == current_revision and current_policy and current_policy ~= policy_digest) then
  return cjson.encode({decision='block', reason_code='limit.authority_conflict',
    lease_id=lease_id, lease_version=lease_version, replayed=false,
    minute_count=minute_count, day_count=day_count,
    active_workflows=tonumber(redis.call('ZCARD', leases)), retry_at_epoch=cjson.null})
end
if entitlement_revision > current_revision then
  redis.call('HSET', counters, 'entitlement_revision', entitlement_revision,
    'policy_digest', policy_digest, 'minute_limit', minute_limit,
    'day_limit', day_limit, 'concurrency_limit', concurrency_limit)
  redis.call('EXPIREAT', counters, day_start + 86460)
end

if redis.call('EXISTS', lease_key) == 1 or redis.call('ZSCORE', leases, lease_id) then
  return cjson.encode({decision='block', reason_code='limit.lease_identity_conflict',
    lease_id=lease_id, lease_version=lease_version, replayed=false,
    minute_count=minute_count, day_count=day_count,
    active_workflows=tonumber(redis.call('ZCARD', leases)), retry_at_epoch=cjson.null})
end

local expired = redis.call('ZRANGEBYSCORE', leases, '-inf', now)
for _, expired_id in ipairs(expired) do
  redis.call('ZREM', leases, expired_id)
end
local active = tonumber(redis.call('ZCARD', leases))

local decision = 'allow'
local reason = 'limit.allowed'
local retry_at = cjson.null
if minute_count >= minute_limit then
  decision = 'block'; reason = 'limit.requests_per_minute'; retry_at = minute_start + 60
elseif day_count >= day_limit then
  decision = 'block'; reason = 'limit.requests_per_day'; retry_at = day_start + 86400
elseif active >= concurrency_limit then
  decision = 'block'; reason = 'limit.concurrent_workflows'
end

if decision == 'allow' then
  minute_count = minute_count + 1
  day_count = day_count + 1
  active = active + 1
  redis.call('HSET', counters, 'minute_start', minute_start, 'minute_count', minute_count,
    'day_start', day_start, 'day_count', day_count)
  redis.call('EXPIREAT', counters, day_start + 86460)
  redis.call('HSET', lease_key, 'workflow_id', workflow_id, 'request_id', request_id,
    'lease_id', lease_id, 'lease_token', lease_token, 'lease_version', lease_version,
    'entitlement_revision', entitlement_revision, 'expires_at', expires_at, 'digest', digest,
    'minute_start', minute_start, 'day_start', day_start)
  redis.call('EXPIREAT', lease_key, expires_at + 60)
  redis.call('ZADD', leases, expires_at, lease_id)
  redis.call('EXPIREAT', leases, expires_at + 86460)
end

local result = {decision=decision, reason_code=reason, lease_id=lease_id,
  lease_version=lease_version, replayed=false, minute_count=minute_count,
  day_count=day_count, active_workflows=active, retry_at_epoch=retry_at}
local encoded = cjson.encode(result)
redis.call('HSET', idem_key, 'digest', digest, 'response', encoded)
redis.call('EXPIRE', idem_key, 86520)
return encoded
