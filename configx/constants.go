package configx

import "time"

const (
	ResolveTypeForward = "forward"
	ResolveTypeLocal   = "local"

	NetworkTypeTcp = "tcp"
	NetworkTypeUdp = "udp"

	ProtocolTypeDNS = "dns"
	ProtocolTypeDoH = "https"
	ProtocolTypeDoT = "tls-tcp"

	CachePolicyTypeNegative  = "cache-positive-only"
	CachePolicyTypeAll       = "cache-all"
	CachePolicyTypePermanent = "cache-permanent"
	CachePolicyTypeHardCode  = "cache-hardcode"
	CachePolicyTypeTtl       = "cache-ttl"

	DefaultPortDns   = 53
	DefaultPortDoT   = 853
	DefaultPortDoH   = 443
	DefaultPortAdmin = 6677

	DefaultQueryTimeoutDurationConnect = 5 * time.Second
	DefaultQueryTimeoutDurationRead    = 5 * time.Second
	DefaultQueryTimeoutDurationWrite   = 5 * time.Second

	DefaultDnsOptDnssec       = false
	DefaultDnsOptEcs          = false
	DefaultDnsOptRandomDomain = false

	DefaultCachePolicy       = ""
	DefaultCacheTtl          = 60 * time.Second
	DefaultCacheScanInterval = 10 * time.Second

	MaxCnameCounts = 5
)
