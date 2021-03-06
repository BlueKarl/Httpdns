local _M = {}

_M.HTTPDNS_DOMAIN = 'httpdns:domain'
_M.HTTPDNS_IP_RANGE = 'httpdns:ip:ranges'
_M.HTTPDNS_PROVIDER = 'httpdns:ip:provider:%s'
_M.HTTPDNS_SP_DN_CACHE = 'httpdns:cache:sp:%s:dn:%s'
_M.HTTPDNS_DOMAIN_SP = 'httpdns:domain:%s:%s'
_M.HTTPDNS_TOTAL_REQUESTS = 'httpdns:total:requests'
_M.HTTPDNS_SP_REQUESTS = 'httpdns:sp:requests'
_M.HTTPDNS_DEFAULT_IP = 'httpdns:default:ip'
_M.HTTPDNS_WAIT_TIME = 'httpdns:default'

_M.HTTPDNS_DEFAULT_SP = 0

return _M
