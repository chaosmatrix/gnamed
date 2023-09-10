package configx

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/FastFilter/xorfilter"
	"github.com/OneOfOne/xxhash"
	bloom "github.com/bits-and-blooms/bloom/v3"
	"github.com/dlclark/regexp2"
	cuckoofilter "github.com/panmari/cuckoofilter"
	"github.com/twmb/murmur3"
)

// test result show that, normally the fp is < 0.01, with 1 millions lookup and 0.5 millions dataset
// combine with different probabilistic algrothms or hash functions can significantly lower the false positive, even down into 0
// take attention, false positive is base on given data set, and it's different in different data set
// all of these are probabilistic algorithms,
// when using, must accept it's probabilistic of false positive
//
// all of these probabilistic algrothms try to lower or stable the false positive by increase memory usage
// but, there is a lower bound, and it's hard to make the false positive reached 0
// it's limited by hash function and the algorithm itself
//
// for example, in this data set for cuckoofilter (lookup 1 million from 0.5 million),
// to make false positive down into 1, need to use 30X space
// to make false positive down into 0, need to use 60X space
//
// But, combine 0.5X ~ space of cuckoo filter with 0.001 false positive (1X space) of bloom filter
// it can easy to make false positive down into 0

// data source
// https://hackertarget.com/top-million-site-list-download/

var file2parser = map[string]string{
	"../data/filters/urlhaus-filter-domains-online.txt":    "default",
	"../data/filters/urlhaus-filter-agh-online.txt":        "agh",
	"../data/filters/phishing_army_blocklist_extended.txt": "default",
	"../data/filters/oisd_big_abp.txt":                     "agh",
	"../data/filters/1hosts-lite-domains.txt":              "default",
}

func getvalues() map[string]bool {
	set := make(map[string]bool)
	for fn := range file2parser {
		bs, err := os.ReadFile(fn)
		if err != nil {
			continue
		}
		for _, bsl := range bytes.Split(bs, []byte("\n")) {
			if bytes.HasPrefix(bsl, []byte("#")) || bytes.HasPrefix(bsl, []byte("!")) {
				continue
			}
			bsl = bytes.TrimSpace(bsl)
			if len(bsl) < 3 {
				continue
			}

			if bytes.HasPrefix(bsl, []byte("^")) {
				bsl = bsl[1 : len(bsl)-1]
			}
			set[string(bsl)] = true

		}
	}

	return set
}

func getTestDomains() []string {
	res := []string{}
	fname := "../data/filters/top-1m.csv"
	bs, err := os.ReadFile(fname)
	if err != nil {
		return res
	}
	for _, lbs := range bytes.Split(bs, []byte("\n")) {

		if len(lbs) < 3 {
			continue
		}
		res = append(res, string(bytes.Split(lbs, []byte(","))[1]))
	}
	return res
}

func TestHashTableFilter(t *testing.T) {
	set := getvalues()
	fmt.Printf("table size: %d\n", len(set))
}

func TestBloomFilter(t *testing.T) {

	fmt.Fprintf(os.Stderr, "bloom filter\n")
	set := getvalues()

	// to stable the fp, it increase cap (more memory usage)
	bfilter := bloom.NewWithEstimates(uint(len(set)), 1.0/1000.0)
	for k := range set {
		bfilter.AddString(k)
	}

	fmt.Printf("total count: %d, bloom filter size: %d, cap: %d\n", len(set), bfilter.ApproximatedSize(), bfilter.Cap())

	top1ms := getTestDomains()

	fp := 0 // false positive
	for _, k := range top1ms {
		if !set[k] && bfilter.TestString(k) {
			fp++
		}
	}

	fmt.Printf("total lookup: %d, false positive: %d(%f)\n", len(top1ms), fp, float64(fp)/float64(len(top1ms)))
}

func TestCuckooFilter(t *testing.T) {

	set := getvalues()

	// increase numElements to decrease the fpp
	cf := cuckoofilter.NewFilter(uint(float64(len(set)) * 33))

	for k := range set {
		cf.Insert([]byte(k))
	}

	fmt.Printf("total size: %d, cuckoo filter: %d, load filter: %f\n", len(set), cf.Count(), cf.LoadFactor())

	top1ms := getTestDomains()

	fp := 0
	for _, k := range top1ms {
		if !set[k] && cf.Lookup([]byte(k)) {
			fp++
		}
	}

	fmt.Printf("total lookup: %d, false positive: %d(%f)\n", len(top1ms), fp, float64(fp)/float64(len(top1ms)))
}

// only decrease fp, when increase the numElements of one of the cuckoo filter
func TestCuckoo2Filter(t *testing.T) {

	set := getvalues()

	// increase numElements to decrease the fpp
	cf1 := cuckoofilter.NewFilter(uint(float64(len(set)) * 1))
	cf2 := cuckoofilter.NewFilter(uint(float64(len(set)) * 2))

	for k := range set {
		cf1.Insert([]byte(k))
		cf2.Insert([]byte(k))
	}

	fmt.Printf("total size: %d, cuckoo filter: %d, load filter: %f\n", len(set), cf1.Count(), cf1.LoadFactor())
	fmt.Printf("total size: %d, cuckoo filter: %d, load filter: %f\n", len(set), cf2.Count(), cf2.LoadFactor())

	top1ms := getTestDomains()

	fp := 0
	for _, k := range top1ms {
		if !set[k] && cf1.Lookup([]byte(k)) && cf2.Lookup([]byte(k)) {
			fp++
		}
	}

	fmt.Printf("total lookup: %d, false positive: %d(%f)\n", len(top1ms), fp, float64(fp)/float64(len(top1ms)))
}

// decrease fp, by using different filter
// even decrease down into 0
func TestBothBloomCuckooFilter(t *testing.T) {
	set := getvalues()

	// increase numElements to decrease the fpp
	cf := cuckoofilter.NewFilter(uint(float64(len(set)) * 0.5))
	bfilter := bloom.NewWithEstimates(uint(len(set)), 1.0/1000.0)

	for k := range set {
		cf.Insert([]byte(k))
		bfilter.AddString(k)
	}

	fmt.Printf("total size: %d, cuckoo filter: %d, load filter: %f\n", len(set), cf.Count(), cf.LoadFactor())
	fmt.Printf("total size: %d, bloom filter size: %d, cap: %d\n", len(set), bfilter.ApproximatedSize(), bfilter.Cap())

	top1ms := getTestDomains()

	fp := 0
	for _, k := range top1ms {
		if !set[k] && cf.Lookup([]byte(k)) && bfilter.TestString(k) {
			fp++
		}
	}

	fmt.Printf("total lookup: %d, false positive: %d(%f)\n", len(top1ms), fp, float64(fp)/float64(len(top1ms)))
}

func TestXorXxxhashFilter(t *testing.T) {
	xorHashFilter(xxhash.ChecksumString64)
}

func TestXorXfnvFilter(t *testing.T) {
	sum64 := func(s string) uint64 {
		fsum := fnv.New64()
		fsum.Write([]byte(s))
		return fsum.Sum64()
	}
	xorHashFilter(sum64)
}

func TestXorXmurmur3Filter(t *testing.T) {
	sum64 := func(s string) uint64 {
		hasher := murmur3.New64()
		hasher.Write([]byte(s))
		return hasher.Sum64()
	}
	xorHashFilter(sum64)
}

// depend on hash function, normally < 0.005 in 0.5 millions
func xorHashFilter(sum64 func(string) uint64) {
	nums := []uint64{}
	set := getvalues()

	cnts := make(map[uint64]bool)
	for k := range set {
		u6 := sum64(k)
		nums = append(nums, u6)
		cnts[u6] = true
	}
	dupCnt := len(nums) - len(cnts)
	fmt.Printf("key duplicate count: %d, hash collision rate: %f\n", dupCnt, float64(dupCnt)/float64(len(nums)))

	// all of them are has approximate fp, a round 0.00398
	xpbf, _ := xorfilter.PopulateBinaryFuse8(nums)
	xpf, _ := xorfilter.PopulateFuse8(nums)
	xf, _ := xorfilter.Populate(nums)

	fmt.Printf("total size: %d\n", len(set))

	top1ms := getTestDomains()

	xpbfFp := 0
	xpfFp := 0
	xfFp := 0
	fp := 0

	for _, k := range top1ms {
		if !set[k] {
			u6 := sum64(k)
			if xpbf.Contains(u6) {
				xpbfFp++
			}
			if xpf.Contains(u6) {
				xpfFp++
			}
			if xf.Contains(u6) {
				xfFp++
			}

			// this can significantly lower the false positive
			if xpbf.Contains(u6) && xpf.Contains(u6) && xf.Contains(u6) {
				fp++
			}
		}
	}

	fmt.Printf("total lookup: %d, all false positive: %d(%f)\n", len(top1ms), fp, float64(fp)/float64(len(top1ms)))
	fmt.Printf("total lookup: %d, PopulateBinaryFuse8 false positive: %d(%f)\n", len(top1ms), xpbfFp, float64(xpbfFp)/float64(len(top1ms)))
	fmt.Printf("total lookup: %d, PopulateFuse8 false positive: %d(%f)\n", len(top1ms), xpfFp, float64(xpfFp)/float64(len(top1ms)))
	fmt.Printf("total lookup: %d, Populate false positive: %d(%f)\n", len(top1ms), xfFp, float64(xfFp)/float64(len(top1ms)))
}

// using multi hash can lower the false positive
func TestXorXHashsFilter(t *testing.T) {
	sum64S := []func(string) uint64{}
	//sum64S = append(sum64S, xxhash.ChecksumString64)
	fnvSum64 := func(s string) uint64 {
		fsum := fnv.New64()
		fsum.Write([]byte(s))
		return fsum.Sum64()
	}
	sum64S = append(sum64S, fnvSum64)
	mm3Sum64 := func(s string) uint64 {
		hasher := murmur3.New64()
		hasher.Write([]byte(s))
		return hasher.Sum64()
	}
	sum64S = append(sum64S, mm3Sum64)

	xorHashsFilter(sum64S)
}

func xorHashsFilter(sum64s []func(string) uint64) {
	set := getvalues()

	cntss := make([]map[uint64]bool, len(sum64s))
	numss := make([][]uint64, len(sum64s))
	for i := 0; i < len(numss); i++ {
		numss[i] = []uint64{}
		cntss[i] = make(map[uint64]bool)
	}

	for k := range set {
		for i, sum64 := range sum64s {
			u6 := sum64(k)
			numss[i] = append(numss[i], u6)
			cntss[i][u6] = true
		}
	}

	for i := 0; i < len(numss); i++ {
		cnts := cntss[i]
		nums := numss[i]
		dupCnt := len(nums) - len(cnts)
		fmt.Printf("key duplicate count: %d, hash collision rate: %f\n", dupCnt, float64(dupCnt)/float64(len(nums)))
	}

	// all of them are has approximate fp, a round 0.00398
	xfs := make([]*xorfilter.Xor8, len(sum64s))
	for i := 0; i < len(xfs); i++ {
		xf, err := xorfilter.Populate(numss[i])
		if err != nil {
			panic(err)
		}
		xfs[i] = xf
	}

	fmt.Printf("total size: %d\n", len(set))

	top1ms := getTestDomains()

	fp := 0

	for _, k := range top1ms {
		if !set[k] {
			isFp := true
			for i := 0; i < len(xfs); i++ {
				u6 := sum64s[i](k)
				if !xfs[i].Contains(u6) {
					isFp = false
					break
				}
			}
			if isFp {
				fp++
			}
		}
	}

	fmt.Printf("total lookup: %d, all false positive: %d(%f)\n", len(top1ms), fp, float64(fp)/float64(len(top1ms)))
}

func TestFilterSyntaxRegexp(t *testing.T) {
	ts := map[string][]map[string]string{
		"(?<=0.0.0\\s{1,8})[a-z.A-Z0-9-].+?(?=(\\s|$).*)": {
			{"0.0.0.0 example.com": "example.com"},
			{"0.0.0.0 example.com.": "example.com."},
			{"0.0.0.0 example.com # hosts": "example.com"},
			{"#0.0.0.0 example.com": "example.com"},
		},
	}
	// regexp not support "?<="
	// error parsing regexp: missing argument to repetition operator: `?`
	for rx, ms := range ts {
		rxp, err := regexp2.Compile(rx, regexp2.None)
		if err != nil {
			t.Errorf("regexp: '%s' is invalid, %v\n", rx, err)
			continue
		}

		for _, rs := range ms {
			for k, v := range rs {
				if s, _ := rxp.FindStringMatch(k); s.String() != v {
					t.Errorf("regexp find result '%s' != '%s'\n", s, v)
				}
			}

		}
	}
}

func TestSyntaxbuiltInFilterSyntaxDnsmasq(t *testing.T) {
	ts := map[string]string{
		"server=/teams.events.data.microsoft.com/": "teams.events.data.microsoft.com.",
		"server=/fp.measure.office.com/":           "fp.measure.office.com.",
		"server=/app-measurement.com/":             "app-measurement.com.",
		"server=//":                                "",
		"server=/":                                 "",
	}

	for k, v := range ts {
		if rs, _ := builtInFilterSyntaxDnsmasq(k); rs != v {
			t.Errorf("%s != %s\n", rs, v)
		}
	}
}

func TestSyntaxbuiltInFilterSyntaxHosts(t *testing.T) {
	ts := map[string]string{
		"127.0.0.1 oralse.cx       # en.wikipedia.org/wiki/List_of_shock_sites": "oralse.cx.",
		"127.0.0.1 oralse.cx":     "oralse.cx.",
		"127.0.0.1 oralse.cx ":    "oralse.cx.",
		"127.0.0.1   oralse.cx ":  "oralse.cx.",
		" 127.0.0.1   oralse.cx ": "oralse.cx.",
		"0.0.0.0 0000130.com":     "0000130.com.",
	}

	for k, v := range ts {
		if rs, _ := builtInFilterSyntaxHosts(k); rs != v {
			t.Errorf("%s != %s\n", rs, v)
		}
	}
}

func TestSyntaxfilterSyntaxParse(t *testing.T) {
	ts := map[string]string{
		"example.com": "example.com.",
		"127.0.0.1":   "127.0.0.1",
		"to":          "to.",
		"":            "",
	}

	for k, v := range ts {
		if rs, _ := filterSyntaxParse(k); rs != v {
			t.Errorf("%s != %s\n", rs, v)
		}
	}
}

func BenchmarkSyntaxHosts(b *testing.B) {
	s := "127.0.0.1 oralse.cx       # en.wikipedia.org/wiki/List_of_shock_sites"
	for i := 0; i < b.N; i++ {
		builtInFilterSyntaxHosts(s)
	}
}

func BenchmarkParseAddr(b *testing.B) {
	s := "123.123.123.123"
	for i := 0; i < b.N; i++ {
		netip.ParseAddr(s)
		//sa.String()
	}
}

func BenchmarkParseIP(b *testing.B) {
	s := "123.123.123.123"
	for i := 0; i < b.N; i++ {
		net.ParseIP(s)
		//sa.String()
	}
}

func TestParseIP(t *testing.T) {
	ts := map[string]string{
		"1.1.1.1":   "1.1.1.1",
		"127.0.0.1": "127.0.0.1",
	}

	for k, v := range ts {
		sip := net.ParseIP(k)
		sa, _ := netip.ParseAddr(k)
		s := sip.String()
		ssa := sa.String()
		if s != ssa || s != v || ssa != v {
			t.Errorf("[+] ERROR parseIP: %s, parseAddr: %s, source: %s ans: %s\n", s, ssa, k, v)
		}
	}
}
