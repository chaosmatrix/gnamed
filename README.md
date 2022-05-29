# gnamed

## Description

### Why create this tools
1. more flexible dns query filter to block some domains
2. prevent dns injection and other security issue under some network

### What it can do
1. flexible rule to block domains, rules equal/prefix/suffix/regexp were supported
2. multi dns query protocol support, dns/dns-over-https/dns-over-tls were supported
3. flexible dns cache rule support (this might violated dns rfc)
4. forward different domain/zone to different nameservers, to get better result
5. collect personal dns query log, to identify security issue or something

## Install
```
go build
```

## Usage

### Help
```
$ gnamed --help
Usage of gnamed:
  -config-file string
        config file (default "./configx/config.json")
  -dump-json
        dump configuration with json format, then exit
  -verbose
        verbose
```

### Run
```
$ gnamed
{"level":"debug","address":"127.0.1.2:53","network":"tcp","protocol":"dns","server_type":"dns","time":"2021-12-12T21:57:17+08:00"}
{"level":"debug","address":"127.0.1.2:53","network":"udp","protocol":"dns","server_type":"dns","time":"2021-12-12T21:57:17+08:00"}
{"level":"debug","address":"127.0.1.2:443","network":"tcp","protocol":"https","error":"Protocol Unsupport","time":"2021-12-12T21:57:17+08:00"}
{"level":"debug","address":"127.0.1.2:853","network":"tcp","protocol":"tls-tcp","error":"Protocol Unsupport","time":"2021-12-12T21:57:17+08:00"}
{"level":"debug","name":"twitter.com.","qtype":"A","view_name":"twitter.com.","nameserver_tag":"tag_doh_cf_json_01","query_type":"query_doh","rcode":"NOERROR","cache":"update","time":"2021-12-12T21:57:34+08:00"}
{"level":"debug","name":"twitter.com.","qtype":"AAAA","view_name":"twitter.com.","nameserver_tag":"tag_doh_cf_json_01","query_type":"query_doh","rcode":"NOERROR","cache":"update","time":"2021-12-12T21:57:35+08:00"}
{"level":"debug","name":"www.twitter.com.","qtype":"A","view_name":"www.twitter.com.","nameserver_tag":"tag_dot_cf","query_type":"query_dot","rcode":"NOERROR","cache":"update","time":"2021-12-12T21:57:42+08:00"}
{"level":"debug","name":"www.twitter.com.","qtype":"AAAA","view_name":"www.twitter.com.","nameserver_tag":"tag_dot_cf","query_type":"query_dot","error":"context deadline exceeded","time":"2021-12-12T21:57:44+08:00"}
{"level":"debug","name":"bing.com.","qtype":"A","view_name":".","nameserver_tag":"tag_dns_8","query_type":"query_dns","rcode":"NOERROR","cache":"update","time":"2021-12-12T21:57:58+08:00"}
{"level":"debug","name":"bing.com.","qtype":"AAAA","view_name":".","nameserver_tag":"tag_dns_8","query_type":"query_dns","rcode":"NOERROR","cache":"update","time":"2021-12-12T21:57:58+08:00"}
```

## Features

### TODO-List
* [x] server: dns protocol support
* [x] server: dns-over-https protocol support
* [ ] server: dns-over-tls protocol support
* [x] server: ensure singleflight incoming query
* [x] query: dns protocol support
* [x] query: dns-over-https protocol support
* [x] query: dns-over-tls protocol support
* [ ] query: flexible view match rules, for example 'contains'
* [ ] cache: delete expired cache actively
* [x] reply: update ttl when response from cache
* [ ] api: cache operations: delete/flush
* [ ] api: dns query statistics
* [ ] api: update blacklist/whitelist
* [ ] web: web ui make api easy use
* [ ] doc: openapi https://github.com/swaggo/swag#how-to-use-it-with-gin
* [ ] optimization: blacklist/whitelist `contains` rule match algorithm, Aho-Corasick or flashtext
* [ ] optimization: singleflight outgoing query (dns-over-https)
* [ ] optimization: select lowest rtt record (cdn domain)
* [ ] optimization: log format and fields
* [ ] optimization: algorithm to get dns response cache ttl

## References
### NameServers
1. https://developers.cloudflare.com/1.1.1.1/
2. https://my.nextdns.io/start
