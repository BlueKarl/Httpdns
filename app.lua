local common = require "common"
local config = require "config"
local redis = require "redtool"
local utils = require "utils"
local stat = require "stat"

local rds = redis:new()

local function get_errcode()
    if config.SWITCH ~= 0 then
        errcode = 102
    else
        errcode = 0
    end
    return errcode
end

local function get_domains()
    if errcode == 0 then
        local domains, _ = cache:get("__domains__")
        if not domains then
            domains, err = rds:smembers(common.HTTPDNS_DOMAIN)
            if err ~= nil then
                errcode = 101
                ngx.log(ngx.ERR, err)
                ngx.exit(ngx.HTTP_BAD_REQUEST)
            end
            if not domains then
                ngx.exit(ngx.HTTP_NOT_FOUND)
            end
            cache:set("__domains__", domains, config.DEFAULT_TTL * 2)
        end
    end
    return domains
end

local function default_ip()
    if errcode == 0 then
        ip, err = rds:smembers(common.HTTPDNS_DEFAULT_IP)
        if err ~= nil then
            errcode = 101
            ngx.log(ngx.ERR, err)
            ngx.exit(ngx.HTTP_BAD_REQUEST)
        end
    end
    return ip
end

local function wait_time()
    if errcode == 0 then
        wait_time, err = rds:hget(common.HTTPDNS_WAIT_TIME, 'wait_time')
        if err ~= nil then
            errcode = 101
            ngx.log(ngx.ERR, err)
            ngx.exit(ngx.HTTP_BAD_REQUEST)
        end
    end
    return wait_time
end

local function config_set()
    ip = default_ip()
    wait_time = wait_time()
    conf = {request_addr=ip, wait_time=tonumber(wait_time)}
    return conf
end

local domains = get_domains()

local function get_remote_ip()
    local args = ngx.req.get_uri_args()
    local flag = 0
    local remote = ngx.var.arg_eip
    for name, data in pairs(args) do
        if name == "cip" then
            remote = data
            flag = 1
        end
    end
    if flag ~= 1 then
        local headers = ngx.req.get_headers()
        local x_forwarded_for = headers['x-forwarded-for']
        local x_real_ip = headers['x-real-ip']

        if not remote and x_forwarded_for then
            local s, _ = string.find(x_forwarded_for, ", ")
            if s then
                remote = string.sub(x_forwarded_for, 1, s-1)
            else
                remote = x_forwarded_for
            end
        elseif not remote and x_real_ip then
            remote = x_real_ip
        else
            remote = ngx.var.remote_addr
        end
    end
    return remote
end

local function get_sp_num(remote)
    local long_ip = string.format('%d', utils.ip2long(remote))
    local ip_range_id, err = rds:zrangebyscore(common.HTTPDNS_IP_RANGE, long_ip, '+inf', 'limit', 0, 1)
    if err ~= nil then
        errcode = 101
        ngx.log(ngx.ERR, err)
        ngx.exit(ngx.HTTP_BAD_REQUEST)
    end
    local sp_num = common.HTTPDNS_DEFAULT_SP
    if ip_range_id ~= nil then
        sp_num, err = rds:hget(string.format(common.HTTPDNS_PROVIDER, ip_range_id[1]), 'isp')
        if err ~= nil then
            errcode = 101
            ngx.log(ngx.ERR, err)
            ngx.exit(ngx.HTTP_BAD_REQUEST)
        end
    end
    return tonumber(sp_num)
end

string.split = function(s, p)
    local rt= {}
    string.gsub(s, '[^'..p..']+', function(w) table.insert(rt, w) end )
    return rt
end

function table_is_empty(t)
    return _G.next(t) == nil
end

local function get_domains_test(sp_num)
    local cache_key = string.format(common.HTTPDNS_SP_CACHE, sp_num)
    local data, _ = cache:get(cache_key) 
    local args = ngx.req.get_uri_args()
    local domains_name = {}
    if not data then
        local default_hosts, domain_hosts, err
        for k,v in pairs(args) do
            if k == "dn" then
                local domain_list = string.split(v, ',')
                for _, domain_choose in ipairs(domain_list) do
                    local default_hosts_key = string.format(common.HTTPDNS_DOMAIN_SP, domain_choose, common.HTTPDNS_DEFAULT_SP)
                    default_hosts, err = rds:smembers(default_hosts_key)
                    if sp_num ~= common.HTTPDNS_DEFAULT_SP and err == nil then
                        local domain_hosts_key = string.format(common.HTTPDNS_DOMAIN_SP, domain_choose, sp_num)
                        domain_hosts, err = rds:smembers(domain_hosts_key)
                    end
                    if not err then
                        local hosts_info = {}
                        local count = 1
                        if default_hosts then
                            for _, ip in ipairs(default_hosts) do
                                hosts_info[count] = {priority=config.DEFAULT_HOST_PRIORITY, ip=ip}
                                count = count + 1
                            end
                        end
                        if domain_hosts then
                            for _, ip in ipairs(domain_hosts) do
                                hosts_info[count] = {priority=config.MATCHED_HOST_PRIORITY, ip=ip}
                                count = count + 1
                            end
                        end
                        if table_is_empty(hosts_info) then
                            hosts_info = nil
                        end
                        domains_name[_] = {dn=domain_choose, data=hosts_info, ttl=config.DEFAULT_TTL}
                    else
                    ngx.log(ngx.ERR, err)
                    end
                end
            end
        end
        cache:set(cache_key, domains_info, config.DEFAULT_TTL)
    else
        domains_name = data
    end
    return domains_name
end 

ngx.timer.at(0, stat.total_request_count)
local remote = get_remote_ip()
local sp_num = get_sp_num(remote)
local k = get_domains_test(sp_num)
local code = get_errcode()
local conf = config_set()
local result = {}

result['errcode'] = code
result['conf'] = conf 
if errcode == 0 then
    result['content'] = k
else 
    result['content'] = ''
end

ngx.timer.at(0, stat.sp_request_count, sp_num)
ngx.say(cjson.encode(result))
