local _M = {}

local common = require "common"
local redis = require "redtool"
local rds = redis:new()

function _M.total_request_count(p)
    rds:incr(common.HTTPDNS_TOTAL_REQUESTS)
end

function _M.sp_request_count(p, sp_num)
    local key = string.format("%s", sp_num)
    rds:hincrby(common.HTTPDNS_SP_REQUESTS, key, 1)
end

function _M.get_stats()
    local result = {}
    result["total"], _ = rds:get(common.HTTPDNS_TOTAL_REQUESTS)
    local stats, err = rds:hgetall(common.HTTPDNS_SP_REQUESTS)
    result["sp"] = {}
    for i=1,#stats,2 do
        result["sp"][stats[i]] = stats[i + 1]
    end
    return result
end

return _M
