HttpDNS
========

httpdns v0.2

rewrited by [OpenResty](https://github.com/openresty/lua-nginx-module)

Usage
=====

```
http :5000/dns/
```

```
http :5000/dns/?eip=1.1.1.1
```

```
http ':5000/dns/' 'X-Forwarded-For:12.1.1.1, 12.1.1.2, 12.1.1.3'
```

```
http ':5000/dns/' X-Real-IP:14.125.63.255
```

Remote IP Priority
==================

1. eip params
2. by X-Forwarded-For
3. by X-Real-IP
4. http_remote
