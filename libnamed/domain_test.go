package libnamed

import (
	"testing"
)

func TestValidateDomain(t *testing.T) {
	testCase := map[string]bool{
		"a-b.com": true, "a_b.com": true, ".ab.com": false,
		"ab-.com": false, "-ab.com": false, "ab.com.": true,
		"ab_.com": true, "_tcp.ab.com": true, ".": true,
	}
	for k, v := range testCase {
		if ValidateDomain(k) != v {
			t.Errorf("'%s' should be %v\n", k, v)
		}
	}
}
