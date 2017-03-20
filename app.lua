local common = require "common"
local config = require "config"
local redis = require "redtool"
local utils = require "utils"
local stat = require "stat"

local rds = redis:new()

local function get_errcode()  --获取错误码
    if config.SWITCH ~= 0 then
        errcode = 102
    else
        errcode = 0
    end
    return errcode
end

local function get_domains()  --获取域名
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

local function default_ip()  --获取request_addr
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

local function wait_time()  --获取延迟时间
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

local function config_set()  --组装conf字段
    if default_ip() then
        local ip = {}
        RandFetch(ip, #default_ip(), #default_ip(), default_ip())
        wait_time = wait_time()
        conf = {request_addr=ip, wait_time=tonumber(wait_time)}
        return conf
    else 
        return nil
    end
end

local domains = get_domains()

local function get_remote_ip() -- 获取cip的value
    local remote = ngx.var.arg_cip
    if not remote then   
        --如果客户端没有通过代理服务器来访问，那么用 HTTP_X_FORWARDED_FOR 取到的值将是空的。
        local x_forwarded_for = ngx.var.http_x_forwarded_for
        if x_forwarded_for then
            remote = x_forwarded_for
        else
            remote = ngx.var.remote_addr
        end
    end
    return remote
end

local function get_sp_num(remote)  --获取remoteip对应的isp
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

string.split = function(s, p)  --字符串分割
    local rt= {}
    string.gsub(s, '[^'..p..']+', function(w) table.insert(rt, w) end )
    return rt
end

function table_is_empty(t)
    return _G.next(t) == nil
end

function RandFetch(list,num,poolSize,pool) -- list: 筛选结果，num: 筛取个数，poolSize: 筛取源大小，pool: 筛取源
    pool = pool or {}
    math.randomseed(tonumber(tostring(os.time()):reverse():sub(1,6)))
    for i = 1, num do
        local rand = math.random(i,poolSize)
        local tmp = pool[rand] or rand
        pool[rand] = pool[i] or i
        pool[i] = tmp
        table.insert(list, tmp)
    end
end

local function get_domains_test(sp_num)  --获取domain返回的信息
    local cache_key = string.format(common.HTTPDNS_SP_DN_CACHE, sp_num, ngx.var.arg_dn)
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
                    default_hosts, err = rds:smembers(default_hosts_key)  --域名的default解析结果
                    if sp_num ~= common.HTTPDNS_DEFAULT_SP and err == nil then
                        local domain_hosts_key = string.format(common.HTTPDNS_DOMAIN_SP, domain_choose, sp_num)
                        domain_hosts, err = rds:smembers(domain_hosts_key)  --域名非默认的解析结果
                    end
                    if not err then
                        local hosts_info = {}
                        local hosts = {}
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
                            hosts = nil
                        else
                            RandFetch(hosts, #hosts_info, #hosts_info, hosts_info)
                        end
                        domains_name[_] = {dn=domain_choose, data=hosts, ttl=config.DEFAULT_TTL}  --拼接解析结果
                    else
                    ngx.log(ngx.ERR, err)
                    end
                end
            end
        end
        cache:set(cache_key, domains_name, config.DEFAULT_TTL)
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
