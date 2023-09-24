package serverx

import (
	"net"
	"strings"
)

func getAddrIpPort(addr net.Addr) (ip string, port string) {
	s := addr.String()
	if i := strings.LastIndex(s, ":"); i > 0 && i+1 < len(s) {
		if s[0] == '[' {
			return s[1 : i-1], s[i+1:]
		}
		return s[:i], s[i+1:]
	}
	return "", ""
}

func getAddrIP(addr net.Addr) string {
	ip, _ := getAddrIpPort(addr)
	return ip
}
