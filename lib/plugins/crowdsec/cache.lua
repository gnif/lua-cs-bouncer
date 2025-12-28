-- lua/plugins/crowdsec/cache.lua
--
-- Memcached-backed cache for captcha state (lua-nginx-memcached).
-- Provides: get(key) -> value, flags
--           set(key, value, ttl_seconds, flags)
--           delete(key)
--
-- Features:
--  - Primary + backup memcached failover
--  - Primary backoff window (default 10s) to avoid request latency when primary is down
--  - Connection keepalive/pool
--  - Optional ngx.shared fallback only when memcached is unreachable

local memcached = require "nginx.memcached"

local _M = {}
_M.__index = _M

local function parse_hostport(s)
  if not s or s == "" then
    return nil
  end

  -- Accept "host:port" or "host" (default port 11211)
  local host, port = s:match("^%s*([^:]+)%s*:%s*(%d+)%s*$")
  if host then
    return { host = host, port = tonumber(port) }
  end

  host = s:match("^%s*(%S+)%s*$")
  if host then
    return { host = host, port = 11211 }
  end

  return nil
end

local function now()
  return ngx.time()
end

local function safe_tonumber(v, dflt)
  local n = tonumber(v)
  if n == nil then return dflt end
  return n
end

local function is_not_found(err)
  -- lua-resty-memcached uses "NOT_FOUND"
  -- other variants sometimes use lowercase; be tolerant
  if not err then return false end
  local e = tostring(err)
  return e == "NOT_FOUND" or e == "not found"
end

function _M.new(opts)
  opts = opts or {}

  local self = {
    primary = parse_hostport(opts.primary),
    backup  = parse_hostport(opts.backup),

    timeout_ms  = safe_tonumber(opts.timeout_ms, 20),
    keepalive_ms = safe_tonumber(opts.keepalive_ms, 60000),
    pool_size   = safe_tonumber(opts.pool_size, 100),

    -- how long to avoid trying primary again after a detected failure
    primary_backoff_sec = safe_tonumber(opts.primary_backoff_sec, 10),

    key_prefix = opts.key_prefix or "crowdsec:captcha:",

    -- shared dict used ONLY for health/backoff + optional fallback storage
    shm = opts.shm or ngx.shared.crowdsec_cache,

    -- local fallback TTL (only used if memcached is unreachable)
    fallback_ttl_sec = safe_tonumber(opts.fallback_ttl_sec, 120),

    -- internal keys in shm
    shm_primary_down_until_key = (opts.shm_primary_down_until_key or "memc_primary_down_until"),
    shm_fallback_prefix = (opts.shm_fallback_prefix or "memc_fallback/"),
  }

  if not self.primary and not self.backup then
    ngx.log(ngx.ERR, "[crowdsec][memc] no servers configured; using shm fallback only")
  end  

  return setmetatable(self, _M)
end

function _M:_full_key(k)
  return self.key_prefix .. k
end

function _M:_fallback_key(k)
  return self.shm_fallback_prefix .. k
end

function _M:_primary_down_until()
  if not self.shm then return 0 end
  local v = self.shm:get(self.shm_primary_down_until_key)
  if not v then return 0 end
  return tonumber(v) or 0
end

function _M:_mark_primary_down()
  if not self.shm then return end
  local until_ts = now() + self.primary_backoff_sec
  -- store as number; no expiry needed, but we can set one anyway
  self.shm:set(self.shm_primary_down_until_key, until_ts, self.primary_backoff_sec + 1)
end

function _M:_clear_primary_down()
  if not self.shm then return end
  self.shm:delete(self.shm_primary_down_until_key)
end

function _M:_connect(server)
  local mc = memcached:new()
  mc:set_timeout(self.timeout_ms)

  local ok, err = mc:connect(server.host, server.port)
  if not ok then
    return nil, err
  end

  return mc, nil
end

function _M:_try_op_on(server, op_fn)
  local mc, err = self:_connect(server)
  if not mc then
    return nil, nil, err, false
  end

  local res, flags, op_err = op_fn(mc)
  if op_err == nil and type(flags) == "string" and (res == nil or res == false) then
    op_err = flags
    flags = nil
  end

  -- now return socket to pool
  local ok2, err2 = mc:set_keepalive(self.keepalive_ms, self.pool_size)
  if not ok2 then
    ngx.log(ngx.ERR, "[crowdsec][memc] set_keepalive failed: ", err2 or "unknown")
  end

  return res, flags, op_err, true
end

function _M:_memc_get(k)
  local key = self:_full_key(k)

  local primary_down_until = self:_primary_down_until()
  if self.primary and primary_down_until <= now() then
    local res, flags, err, connected = self:_try_op_on(self.primary, function(mc)
      return mc:get(key)
    end)

    if connected then
      if err == nil then
        -- primary works; clear any previous down marker
        self:_clear_primary_down()
        return res, flags, nil, "primary"
      end

      if is_not_found(err) then
        -- miss is not an error
        self:_clear_primary_down()
        return nil, nil, "NOT_FOUND", "primary"
      end

      ngx.log(ngx.ERR, "[crowdsec][memc] primary get error: ", err)
      return nil, nil, err, "primary"
    end

    -- connection failure talking to primary -> mark down
    ngx.log(ngx.ERR, "[crowdsec][memc] primary get connect error: ", err)
    self:_mark_primary_down()
  end

  -- if primary is down/backing off, or failed: use backup if present
  if self.backup then
    local res, flags, err = self:_try_op_on(self.backup, function(mc)
      return mc:get(key)
    end)

    if err == nil or is_not_found(err) then
      return res, flags, err, "backup"
    end

    ngx.log(ngx.ERR, "[crowdsec][memc] backup get error: ", err)
    return nil, nil, err, "backup"
  end

  return nil, nil, "NO_BACKUP", "none"
end

function _M:_memc_set(k, value, ttl, flags)
  local key = self:_full_key(k)
  ttl = ttl or 0
  flags = flags or 0

  local primary_down_until = self:_primary_down_until()
  if self.primary and primary_down_until <= now() then
    local ok, _, err, connected = self:_try_op_on(self.primary, function(mc)
      -- lua-resty-memcached signature: set(key, value, exptime, flags)
      return mc:set(key, value, ttl, flags)
    end)

    if connected then
      if ok then
        self:_clear_primary_down()
        return true, nil, "primary"
      end

      ngx.log(ngx.ERR, "[crowdsec][memc] primary set error: ", err or "set failed")
      return false, err or "set failed", "primary"
    end

    ngx.log(ngx.ERR, "[crowdsec][memc] primary set connect error: ", err)
    self:_mark_primary_down()
  end

  if self.backup then
    local ok, _, err = self:_try_op_on(self.backup, function(mc)
      return mc:set(key, value, ttl, flags)
    end)

    if ok then
      return true, nil, "backup"
    end

    return false, err or "set failed", "backup"
  end

  return false, "no memcached servers available", "none"
end

function _M:_memc_delete(k)
  local key = self:_full_key(k)

  local primary_down_until = self:_primary_down_until()
  if self.primary and primary_down_until <= now() then
    local ok, _, err, connected = self:_try_op_on(self.primary, function(mc)
      return mc:delete(key)
    end)

    if connected then
      if ok or is_not_found(err) then
        self:_clear_primary_down()
        return true, nil, "primary"
      end

      ngx.log(ngx.ERR, "[crowdsec][memc] primary delete error: ", err or "delete failed")
      return false, err or "delete failed", "primary"
    end

    ngx.log(ngx.ERR, "[crowdsec][memc] primary delete connect error: ", err)
    self:_mark_primary_down()
  end

  if self.backup then
    local ok, _, err = self:_try_op_on(self.backup, function(mc)
      return mc:delete(key)
    end)

    if ok or is_not_found(err) then
      return true, nil, "backup"
    end

    return false, err or "delete failed", "backup"
  end

  return false, "no memcached servers available", "none"
end

-- Public API: mimic ngx.shared semantics for captcha keys (value + flags)

function _M:get(k)
  local val, flags, err, which = self:_memc_get(k)
  if err == nil then
    return val, flags
  end

  if is_not_found(err) then
    return nil, nil
  end

  -- memcached unreachable: fall back to shm (best-effort, avoids slowing site)
  if self.shm then
    local fkey = self:_fallback_key(k)
    local v, f = self.shm:get(fkey)
    return v, f
  end

  return nil, nil
end

function _M:set(k, value, ttl_seconds, flags)
  local ok, err, which = self:_memc_set(k, value, ttl_seconds, flags)
  if ok then
    -- if it exists in fallback, remove it
    if self.shm then
      self.shm:delete(self:_fallback_key(k))
    end
    return true, nil
  end

  -- memcached unreachable: write to shm fallback so captcha still works locally
  if self.shm then
    local fkey = self:_fallback_key(k)
    local ttl = ttl_seconds
    if not ttl or ttl <= 0 then
      ttl = self.fallback_ttl_sec
    end
    local succ, shm_err = self.shm:set(fkey, value, ttl, flags or 0)
    if succ then
      return true, nil
    end
    return false, ("memcached set failed (" .. tostring(err) .. ") and shm fallback failed (" .. tostring(shm_err) .. ")")
  end

  return false, err
end

function _M:delete(k)
  local ok, err, which = self:_memc_delete(k)
  if self.shm then
    self.shm:delete(self:_fallback_key(k))
  end
  if ok then
    return true, nil
  end
  if is_not_found(err) then
    return true, nil
  end
  return false, err
end

return _M
