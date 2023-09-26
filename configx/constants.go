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

	defaultPortDns   = 53
	defaultPortDoT   = 853
	defaultPortDoH   = 443
	defaultPortDoQ   = 784
	defaultPortAdmin = 6677

	defaultTimeoutDurationIdle    = 65 * time.Second
	defaultTimeoutDurationConnect = 2 * time.Second
	defaultTimeoutDurationRead    = 5 * time.Second
	defaultTimeoutDurationWrite   = 5 * time.Second

	// edns-client-subnet
	defaultEcsFamilyIPv4 uint16 = 1
	defaultEcsFamilyIPv6 uint16 = 2
	defaultEcsAddress           = ""
)

var (
	defaultExternalNameServers = []string{"8.8.8.8:53"}

	// RrHTTPS
	// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
	defaultRrHTTPSAlpn = []string{"h3", "h2", "http/1.1"}
)
