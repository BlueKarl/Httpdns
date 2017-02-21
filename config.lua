local _M = {}

_M.REDIS_HOST = os.getenv("REDIS_HOST") and os.getenv("REDIS_HOST") or '10.100.1.156'
_M.REDIS_PORT = os.getenv("REDIS_PORT") and os.getenv("REDIS_PORT") or '7777'
_M.DEFAULT_TTL = tonumber(os.getenv("DEFAULT_TTL")) and tonumber(os.getenv("DEFAULT_TTL")) or 300
_M.DEFAULT_HOST_PRIORITY = tonumber(os.getenv("DEFAULT_HOST_PRIORITY")) and tonumber(os.getenv("DEFAULT_HOST_PRIORITY")) or 0
_M.MATCHED_HOST_PRIORITY = tonumber(os.getenv("MATCHED_HOST_PRIORITY")) and tonumber(os.getenv("MATCHED_HOST_PRIORITY")) or 5
_M.SWITCH = tonumber(os.getenv("SWITCH")) and tonumber(os.getenv("SWITCH")) or 0

return _M
