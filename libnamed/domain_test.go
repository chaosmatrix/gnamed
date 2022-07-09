package libnamed

import (
	"fmt"
	"os"
	"strings"
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

	diff := 0
	times := 10
	for i := 0; i < times; i++ {
		for k := range testCase {
			v := RandomUpperDomain(k)
			if v != k && strings.EqualFold(v, k) {
				diff++
			}
		}
	}
	if diff == 0 {
		t.Errorf("[+] after %d times with %d domains RandomUpper ops, all domain equal", times, len(testCase))
	} else {
		fmt.Fprintf(os.Stderr, "[+] RandomUpperDomain change ratio: %f\n", float64(diff)/float64(times*len(testCase)))
	}
}

func BenchmarkRandomUpperDomain(b *testing.B) {
	s := "www.122.example.com."
	for i := 0; i < b.N; i++ {
		RandomUpperDomain(s)
	}
}
