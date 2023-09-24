package libnamed

import (
	"fmt"
	"testing"
)

func TestIPv6Reachable(t *testing.T) {
	res := IsIPv6Enable()
	fmt.Printf("IPv6Enable: %v\n", res)
}
