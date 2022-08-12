package configx

import (
	"time"
)

const (
	ResolveTypeForward = "forward"
	ResolveTypeLocal   = "local"

	NetworkTypeTcp = "tcp"
	NetworkTypeUdp = "udp"

	ProtocolTypeDNS = "dns"
	ProtocolTypeDoH = "https"
	ProtocolTypeDoT = "tls-tcp"
	ProtocolTypeDoQ = "quic"

	// TODO
	CachePassiveEvict = false // evict expired element while get element
	CacheActiveEvict  = false // skiplist - while add new element, evict first two expired elements & evict the getting expired element

	CacheModeSkipList  = "skiplist"
	CacheModeHashTable = "hashtable"

	DefaultPortDns   = 53
	DefaultPortDoT   = 853
	DefaultPortDoH   = 443
	DefaultPortDoQ   = 784
	DefaultPortAdmin = 6677

	DefaultTimeoutDurationIdle    = 30 * time.Second
	DefaultTimeoutDurationConnect = 2 * time.Second
	DefaultTimeoutDurationRead    = 5 * time.Second
	DefaultTimeoutDurationWrite   = 5 * time.Second

	DefaultPoolIdleTimeoutDuration = 30 * time.Second
	DefaultPoolWaitTimeoutDuration = 3 * time.Second
	DefaultPoolSize                = 5
	DefaultPoolQueriesPerConn      = 32

	DefaultDnsOptDnssec       = false
	DefaultDnsOptEcs          = false
	DefaultDnsOptRandomDomain = false

	DefaultCachePolicy       = ""
	DefaultCacheTtl          = 60 * time.Second
	DefaultCacheScanInterval = 10 * time.Second

	// edns-client-subnet
	DefaultEcsFamilyIPv4 uint16 = 1
	DefaultEcsFamilyIPv6 uint16 = 2
	DefaultEcsAddress           = ""

	MaxCnameCounts = 5
)

var (
	defaultExternalNameServers = []string{"8.8.8.8:53"}
)
