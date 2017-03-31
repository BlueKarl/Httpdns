HttpDNS
========

httpdns v2.1.0

rewrited by [OpenResty](https://github.com/openresty/lua-nginx-module)

Usage
=====

```
URL/httpdns?dn=domainname1,domainname2,...
```

Random sorting of analytical result and according to the ISP region decision priority

Multiple domain names can be requested at the same time,eg:

```
127.0.0.1:6666/httpdns?dn=www.a.com,www.b.com,www.c.com
```



