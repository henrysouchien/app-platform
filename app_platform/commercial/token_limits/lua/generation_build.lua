local command = cjson.decode(ARGV[1])
local counters, leases, manifest = KEYS[1], KEYS[2], KEYS[3]
local target = tostring(command.target_generation)
local digest = command.snapshot_sha256
local existing = redis.call('HGET', manifest, 'snapshot_sha256')
if existing then
  if existing == digest and redis.call('HGET', manifest, 'generation') == target then
    return cjson.encode({decision='allow', reason_code='limit.rebuild_replayed', generation=tonumber(target), snapshot_sha256=digest, replayed=true})
  end
  return cjson.encode({decision='block', reason_code='limit.rebuild_conflict', generation=tonumber(target), snapshot_sha256=digest, replayed=false})
end
for index=1,#KEYS do
  if redis.call('EXISTS', KEYS[index]) == 1 then
    return cjson.encode({decision='block', reason_code='limit.rebuild_conflict', generation=tonumber(target), snapshot_sha256=digest, replayed=false})
  end
end
redis.call('HSET', counters, 'entitlement_revision', command.entitlement_revision,
  'policy_digest', command.policy_sha256, 'minute_limit', command.requests_per_minute,
  'day_limit', command.requests_per_day, 'concurrency_limit', command.concurrent_workflows,
  'minute_start', command.minute_start_epoch, 'minute_count', command.minute_count,
  'day_start', command.day_start_epoch, 'day_count', command.day_count)
redis.call('EXPIREAT', counters, tonumber(command.day_start_epoch) + 86460)
local max_expiry = 0
for index,item in ipairs(command.leases) do
  local key = KEYS[3 + index]
  redis.call('HSET', key, 'workflow_id', item.workflow_run_id, 'request_id', item.request_id,
    'lease_id', item.lease_id, 'lease_token', item.lease_token,
    'lease_version', item.lease_version, 'entitlement_revision', item.entitlement_revision,
    'expires_at', item.expires_at_epoch, 'digest', item.admission_digest)
  redis.call('EXPIREAT', key, tonumber(item.expires_at_epoch) + 60)
  redis.call('ZADD', leases, item.expires_at_epoch, item.lease_id)
  if tonumber(item.expires_at_epoch) > max_expiry then max_expiry = tonumber(item.expires_at_epoch) end
end
if max_expiry > 0 then redis.call('EXPIREAT', leases, max_expiry + 86460) end
redis.call('HSET', manifest, 'generation', target, 'snapshot_sha256', digest,
  'lease_count', #command.leases)
redis.call('EXPIRE', manifest, 86520)
return cjson.encode({decision='allow', reason_code='limit.rebuild_staged', generation=tonumber(target), snapshot_sha256=digest, replayed=false})
