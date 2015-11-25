local _M = {}

function _M.ip2long(ip)
    local long = 0
    ip:gsub("%d+", function(s) long = long * 256 + tonumber(s) end)
    return long
end

return _M

