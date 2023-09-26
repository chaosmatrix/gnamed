package libnamed

import (
	"net"
)

// true if has any valid IPv6 Address
func IsIPv6Enable() bool {
	ifis, err := net.Interfaces()
	if err != nil {
		return false
	}

	for _, ifi := range ifis {
		if ifi.Flags&(net.FlagRunning|net.FlagUp) == 0 {
			continue
		}

		// need another way to filter these kind of interfaces
		name := ifi.Name
		if len(name) == 0 || name[0] == 'V' || name[0] == 'v' {
			// virtual machine's Network Adapter
			continue
		}

		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ip, _, _ := net.ParseCIDR(addr.String()); ip != nil {
				if ip.To4() == nil && ip.IsGlobalUnicast() {
					return true
				}
			}
		}
	}
	return false
}
