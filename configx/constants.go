package configx

import (
	"time"
)

const (
	ResolveTypeForward = "forward"
	ResolveTypeLocal   = "local"

	ProtocolTypeDNS = "dns"
	ProtocolTypeDoH = "https"
	ProtocolTypeDoT = "tls-tcp"
	ProtocolTypeDoQ = "quic"

	// TODO
	cachePassiveEvict = false // evict expired element while get element
	cacheActiveEvict  = false // skiplist - while add new element, evict first two expired elements & evict the getting expired element

	CacheModeSkipList  = "skiplist"
	CacheModeHashTable = "hashtable"

	defaultPortDns   = 53
	defaultPortDoT   = 853
	defaultPortDoH   = 443
	defaultPortDoQ   = 784
	defaultPortAdmin = 6677

	defaultTimeoutDurationIdle    = 30 * time.Second
	defaultTimeoutDurationConnect = 2 * time.Second
	defaultTimeoutDurationRead    = 5 * time.Second
	defaultTimeoutDurationWrite   = 5 * time.Second

	defaultPoolIdleTimeoutDuration = 30 * time.Second
	defaultPoolWaitTimeoutDuration = 3 * time.Second
	defaultPoolSize                = 5
	defaultPoolQueriesPerConn      = 32

	// edns-client-subnet
	defaultEcsFamilyIPv4 uint16 = 1
	defaultEcsFamilyIPv6 uint16 = 2
	defaultEcsAddress           = ""

	maxCnameCounts = 5
)

var (
	defaultExternalNameServers = []string{"8.8.8.8:53"}

	// RrHTTPS
	// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
	defaultRrHTTPSAlpn = []string{"h3", "h2", "spdy/3", "spdy/2", "spdy/1", "http/1.1"}
)
