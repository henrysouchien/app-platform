local expected, target, digest, lease_count = ARGV[1], ARGV[2], ARGV[3], ARGV[4]
local command = cjson.decode(ARGV[5])
local current = redis.call('HGET', KEYS[1], 'generation')
local replay = false
if current ~= expected then
  if current == target and redis.call('HGET', KEYS[4], 'snapshot_sha256') == digest then
    replay = true
  else
    return cjson.encode({decision='block', reason_code='limit.generation_cas_conflict', generation=tonumber(target), snapshot_sha256=digest, replayed=false})
  end
end
if redis.call('HGET', KEYS[4], 'generation') ~= target
  or redis.call('HGET', KEYS[4], 'snapshot_sha256') ~= digest
  or redis.call('HGET', KEYS[4], 'lease_count') ~= lease_count then
  return redis.error_reply('token generation manifest mismatch')
end
local counter_fields = {
  entitlement_revision=command.entitlement_revision, policy_digest=command.policy_sha256,
  minute_limit=command.requests_per_minute, day_limit=command.requests_per_day,
  concurrency_limit=command.concurrent_workflows, minute_start=command.minute_start_epoch,
  minute_count=command.minute_count, day_start=command.day_start_epoch,
  day_count=command.day_count}
if redis.call('EXISTS', KEYS[2]) ~= 1 then
  return redis.error_reply('token generation core key missing')
end
for field,value in pairs(counter_fields) do
  if redis.call('HGET', KEYS[2], field) ~= tostring(value) then
    return redis.error_reply('token generation counter mismatch')
  end
end
if tonumber(redis.call('ZCARD', KEYS[3])) ~= #command.leases then
  return redis.error_reply('token generation lease index mismatch')
end
for index=5,#KEYS do
  local item = command.leases[index - 4]
  if redis.call('EXISTS', KEYS[index]) ~= 1
    or redis.call('HGET', KEYS[index], 'lease_id') ~= item.lease_id
    or redis.call('HGET', KEYS[index], 'workflow_id') ~= item.workflow_run_id
    or redis.call('HGET', KEYS[index], 'request_id') ~= item.request_id
    or redis.call('HGET', KEYS[index], 'lease_token') ~= item.lease_token
    or redis.call('HGET', KEYS[index], 'lease_version') ~= tostring(item.lease_version)
    or redis.call('HGET', KEYS[index], 'entitlement_revision') ~= tostring(item.entitlement_revision)
    or redis.call('HGET', KEYS[index], 'expires_at') ~= tostring(item.expires_at_epoch)
    or redis.call('HGET', KEYS[index], 'digest') ~= item.admission_digest
    or tonumber(redis.call('ZSCORE', KEYS[3], item.lease_id) or '-1') ~= tonumber(item.expires_at_epoch) then
    return redis.error_reply('token generation lease mismatch')
  end
end
if not replay then redis.call('HSET', KEYS[1], 'generation', target, 'snapshot_sha256', digest) end
return cjson.encode({decision='allow', reason_code='limit.generation_swapped', generation=tonumber(target), snapshot_sha256=digest, replayed=replay})
