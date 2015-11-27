local common = require "common"
local config = require "config"
local redis = require "redtool"
local utils = require "utils"
local stat = require "stat"

local rds = redis:new()

local function get_domains()
    local domains, _ = cache:get("__domains__")
    if not domains then
        domains, err = rds:smembers(common.HTTPDNS_DOMAIN)
        if err ~= nil then
            ngx.log(ngx.ERR, err)
            ngx.exit(ngx.HTTP_BAD_REQUEST)
        end
        if not domains then
            ngx.exit(ngx.HTTP_NOT_FOUND)
        end
        cache:set("__domains__", domains, config.DEFAULT_TTL * 2)
    end
    return domains
end

local domains = get_domains()

local function get_remote_ip()
    local headers = ngx.req.get_headers()
    local x_forwarded_for = headers['x-forwarded-for']
    local x_real_ip = headers['x-real-ip']

    local remote = ngx.var.arg_eip
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
    return remote
end

local function get_sp_num(remote)
    local long_ip = string.format('%d', utils.ip2long(remote))
    local ip_range_id, err = rds:zrangebyscore(common.HTTPDNS_IP_RANGE, long_ip, '+inf', 'limit', 0, 1)
    if err ~= nil then
        ngx.log(ngx.ERR, err)
        ngx.exit(ngx.HTTP_BAD_REQUEST)
    end

    local sp_num = common.HTTPDNS_DEFAULT_SP
    if ip_range_id ~= nil then
        sp_num, err = rds:hget(string.format(common.HTTPDNS_PROVIDER, ip_range_id[1]), 'isp')
        if err ~= nil then
            ngx.log(ngx.ERR, err)
            ngx.exit(ngx.HTTP_BAD_REQUEST)
        end
    end
    return tonumber(sp_num)
end

local function get_domains_info(sp_num)
    local cache_key = string.format(common.HTTPDNS_SP_CACHE, sp_num)
    local data, _ = cache:get(cache_key)
    local domains_info = {}
    if not data then
        for index, domain in ipairs(domains) do
            local default_hosts_key = string.format(common.HTTPDNS_DOMAIN_SP, domain, common.HTTPDNS_DEFAULT_SP)
            local default_hosts, domain_hosts, err
            default_hosts, err = rds:smembers(default_hosts_key)
            if sp_num ~= common.HTTPDNS_DEFAULT_SP and err == nil then
                local domain_hosts_key = string.format(common.HTTPDNS_DOMAIN_SP, domain, sp_num)
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
                domains_info[index] = {domain=domain, dns=hosts_info}
            else
                ngx.log(ngx.ERR, err)
            end
        end
        cache:set(cache_key, domains_info, config.DEFAULT_TTL)
    else
        domains_info = data
    end
    return domains_info
end

ngx.timer.at(0, stat.total_request_count)
local remote = get_remote_ip()
local sp_num = get_sp_num(remote)
local domains_info = get_domains_info(sp_num)

local result = {}
result['device_ip'] = remote
result['device_isp'] = sp_num
result['ttl'] = config.DEFAULT_TTL
result['domains'] = domains_info

ngx.timer.at(0, stat.sp_request_count, sp_num)
ngx.say(cjson.encode(result))


