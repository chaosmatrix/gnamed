package libnamed

import (
	"fmt"
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

func TestRandomUpperDomain(t *testing.T) {
	testCase := map[string]bool{
		"a-b.com.": true, "google.com.": true, "github.com.": true,
		"example.com.": true, "www.example.com.": true, "bing.com.": true,
		"123.456.com.": true, "123.com.": true, "123.example.com.": true,
	}

	for i := 1; i < 10; i++ {
		for k := range testCase {
			fmt.Printf("%s %s\n", k, RandomUpperDomain(k))
		}
	}
}

func BenchmarkRandomUpperDomain(b *testing.B) {
	s := "www.122.example.com."
	for i := 0; i < b.N; i++ {
		RandomUpperDomain(s)
	}
}
