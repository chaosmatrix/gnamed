package cachex

import (
	"fmt"
	"gnamed/ext/faketimer"
	"gnamed/ext/runner"
	"math"
	"math/rand"
	"sort"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"github.com/miekg/dns"
)

func newTestMsgWithString(s string) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(s, dns.TypeA)

	return msg
}

func TestSklCache(t *testing.T) {

	fmt.Printf("[+] test SklCache\n")
	fmt.Printf("[+]\n")

	c := &SklCacheConfig{MaxLevel: 32, Probability: 0.5}
	sklc := c.newSklCache()

	type testEntry struct {
		domain string
		qtype  uint16
		vals   *dns.Msg
		ttl    uint32
		ts     int64
	}

	fti := faketimer.FakeTimerInfo{Precision: "1s"}
	if err := fti.Parse(); err != nil {
		t.Error(err)
	}
	defer runner.ExecShutdown(30 * time.Second)

	if diff := time.Now().Unix() - faketimer.GetFakeTimerUnixSecond(); diff > 1 {
		t.Errorf("[+] FakeTimer return time less than system time %d large than 5s\n", diff)
	}

	now := faketimer.GetFakeTimerUnixSecond()

	tes := []testEntry{
		{
			domain: "example.com",
			qtype:  5,
			vals:   newTestMsgWithString("1"),
			ttl:    300,
			ts:     now + 300,
		},
		{
			domain: "www.example.com",
			qtype:  5,
			vals:   newTestMsgWithString("1"),
			ttl:    300,
			ts:     now + 300,
		},
		{
			domain: "www1.example.com",
			qtype:  5,
			vals:   newTestMsgWithString("1"),
			ttl:    60,
			ts:     now + 60,
		},
		{
			domain: "google.com",
			qtype:  5,
			vals:   newTestMsgWithString("1"),
			ttl:    600,
			ts:     now + 600,
		},
		{
			domain: "www1.google.com",
			qtype:  5,
			vals:   newTestMsgWithString("1"),
			ttl:    600,
			ts:     now + 600,
		},
		{
			domain: "www2.google.com",
			qtype:  5,
			vals:   newTestMsgWithString("1"),
			ttl:    900,
			ts:     now + 900,
		},
		{
			domain: "www.google.com",
			qtype:  5,
			vals:   newTestMsgWithString("1"),
			ttl:    600,
			ts:     now + 600,
		},
		{
			domain: "localhost",
			qtype:  5,
			vals:   newTestMsgWithString("1"),
			ttl:    900,
			ts:     now + 900,
		},
	}

	// should be updated
	sklc.Set("google.com", 5, newTestMsgWithString("3"), 900)

	for _, te := range tes {
		sklc.Set(te.domain, te.qtype, te.vals, te.ttl)
	}

	sort.Slice(tes, func(i, j int) bool {
		return tes[i].ts < tes[j].ts
	})

	fmt.Printf("[+]\n")
	fmt.Printf("[+] show tables\n")
	fmt.Printf("%v\n", sklc.tables[tes[0].qtype].table)
	/*
		sklc.Set("example.com", 5, newTestMsgWithString("1"), 300)
		sklc.Set("www.example.com", 5, newTestMsgWithString("2"), 300)
		sklc.Set("www1.example.com", 5, newTestMsgWithString("2"), 500)
		ts := time.Now().Unix() + 200

		sklc.Set("www.google.com", 5, newTestMsgWithString("2"), 600)
		sklc.Set("google.com", 5, newTestMsgWithString("2"), 600)
		sklc.Set("google.com", 5, newTestMsgWithString("3"), 900)
		//fmt.Printf("%v %v\n", sklc.skls[5].Head.Level[0].Value, sklc.skls[5].Head.Level[0].vals)
		//fmt.Printf("%v %v\n", sklc.skls[5].Head.Level[0].Level[0].Value, sklc.skls[5].Head.Level[0].Level[0].vals)
	*/

	veryTestCase := func(start int, skip int) {
		i := start
		// skip first 0
		fmt.Printf("[+] SkipList head level %d, head maxLevel %d\n", len(sklc.skls[5].head.forward), sklc.skls[5].level)
		curr := sklc.skls[5].head.forward[0]
		for curr != nil {
			if i == skip {
				i++
				continue
			}
			fmt.Printf("[+] level %d\n", len(curr.forward))
			// 5 * time.Second
			diff := tes[i].ts - curr.value
			ts := tes[i].ts
			if diff >= 0 && diff < 5 {
				cnt := 0
				for ; i < len(tes) && ts == tes[i].ts; i++ {
					if _, found := curr.vals[tes[i].domain]; found {
						cnt++
					}

					if p, found := sklc.tables[tes[i].qtype].table[tes[i].domain]; found {
						if *(*uint64)(unsafe.Pointer(p.sklNode)) != *(*uint64)(unsafe.Pointer(curr)) {
							t.Errorf("[+] domain %s pointer address not equal, pointer in table %p, pointer in skiplist %p\n", tes[i].domain, p, curr)
						}
					}
				}

				if cnt != len(curr.vals) {
					t.Errorf("[+] entry count not match, require %d, only %d, vals: %v\n", len(curr.vals), cnt, curr.vals)
				} else {
					fmt.Printf("[+] utc: %d values: %v pointer: %p\n", curr.value, curr.vals, curr)
				}
			} else {
				t.Errorf("[+] utc diff %d > 5s, entry sequence not match\n", diff)
			}

			curr = curr.forward[0]
		}
	}

	veryTestCase(0, -1)

	j := 0

	fmt.Printf("[+]\n")
	fmt.Printf("[+] Remove %#v\n", tes[j])
	sklc.Remove(tes[j].domain, tes[j].qtype)
	veryTestCase(0, j)

	fmt.Printf("[+]\n")
	fmt.Printf("[+] Insert %#v\n", tes[j])
	sklc.Set(tes[j].domain, tes[j].qtype, tes[j].vals, tes[j].ttl)
	veryTestCase(0, -1)

	fmt.Printf("[+]\n")

	k := len(tes) / 2
	te := tes[k]
	fmt.Printf("[+] Erase entrys before utc %d\n", te.ts)

	//sklc.skls[5].EraseBefore(ts)
	sklc.EraseBefore(te.qtype, te.ts)

	i := k
	for ; i < len(tes) && tes[k].ts == tes[i].ts; i++ {
	}
	veryTestCase(i, -1)

	fmt.Printf("[+]\n")
	fmt.Printf("[+] output full skiplist\n")
	skl := sklc.skls[tes[k].qtype].head.forward[0]
	for skl != nil {
		fmt.Printf("[+] utc: %d values: %v pointer: %p\n", skl.value, skl.vals, skl)
		skl = skl.forward[0]

	}

	fmt.Printf("%v\n", sklc.Dump())

}

func TestSklCacheRandom(t *testing.T) {
	size := 1 << 16
	removePercent := 100 // 1/100

	c := &SklCacheConfig{MaxLevel: 32, Probability: 0.5}
	sklc := c.newSklCache()

	for i := 300; i < size; i++ {
		ok := sklc.Set(strconv.Itoa(i), uint16(i%32+3), newTestMsgWithString(strconv.Itoa(i)), uint32(i&math.MaxUint32))
		if !ok {
			t.Errorf("[+] bug: insert key '%d'\n", i)
		}
	}

	for i := 300; i < size; i++ {
		if i%removePercent != 0 {
			continue
		}
		ok := sklc.Remove(strconv.Itoa(i), uint16(i%32+3))

		if !ok {
			t.Errorf("[+] bug: key '%d' exist, but failed to remove\n", i)
		}
	}

	for i := 300; i < size; i++ {
		val, _, found := sklc.Get(strconv.Itoa(i), uint16(i%32+3))

		if found {
			if i%removePercent == 0 || val == nil || val.Question[0].Name != strconv.Itoa(i) {
				t.Errorf("[+] bug: key '%d' exist, but not found\n", i)
			}
		} else {
			if i%removePercent != 0 {
				t.Errorf("[+] bug: key '%d' already remove, but found\n", i)
			}
		}

	}
}

func BenchmarkSklCacheInsert(b *testing.B) {

	c := &SklCacheConfig{MaxLevel: 32, Probability: 0.5}
	sklc := c.newSklCache()

	for i := 300; i < b.N; i++ {
		sklc.Set(strconv.Itoa(i), 1, newTestMsgWithString(strconv.Itoa(i)), uint32(i&math.MaxUint32))
	}

	for i := 300; i < b.N; i++ {
		if val, _, found := sklc.Get(strconv.Itoa(i), 1); !found || val.Question[0].Name != strconv.Itoa(i) {
			fmt.Printf("[+] bug: SklCache get key '%d' val '%v' success '%v'\n", i, val, found)
		}
	}

	for i := 300; i < b.N; i++ {
		if found := sklc.Remove(strconv.Itoa(i), 1); !found {
			fmt.Printf("[+] bug: SklCache delete key '%d'\n", i)
		}
	}
}

func BenchmarkSkl(b *testing.B) {
	skl := NewSkipList(32, 0.5)
	for i := 0; i < b.N; i++ {
		skl.Insert(int64(i))
	}

	for i := 0; i < b.N; i++ {
		if node, found := skl.Get(int64(i)); !found || uint32(node.value) != uint32(i&math.MaxUint32) {
			fmt.Printf("[+] bug: SkipList get %d\n", i)
		}
	}
}

func newTestMsg() *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion("bing.com.", dns.TypeA)

	rss := []string{
		"bing.com.               60       IN      A       13.107.21.200",
		"bing.com.               60       IN      A       204.79.197.200",
	}
	for _, rs := range rss {
		rr, _ := dns.NewRR(rs)
		msg.Answer = append(msg.Answer, rr)
	}
	return msg
}

// Pack() == Copy() == 1/3 * Unpack()
// Pack() && Unpack() increase When msg size increase
func BenchmarkMsgPack(b *testing.B) {
	msg := newTestMsg()

	for i := 0; i < b.N; i++ {
		msg.Pack()
	}
}

func BenchmarkMsgPackBuffer(b *testing.B) {
	msg := newTestMsg()
	buf := make([]byte, 1500)
	for i := 0; i < b.N; i++ {
		msg.PackBuffer(buf)
	}
}

func BenchmarkMsgUnpack(b *testing.B) {
	msg := newTestMsg()
	bmsg, err := msg.Pack()
	if err != nil {
		panic(err)
	}
	for i := 0; i < b.N; i++ {
		msg.Unpack(bmsg)
	}
}

func BenchmarkMsgCopy(b *testing.B) {
	msg := newTestMsg()
	for i := 0; i < b.N; i++ {
		msg.Copy()
	}
}

func BenchmarkRandFloat64(b *testing.B) {
	rd := rand.New(rand.NewSource(time.Now().Unix()))
	for i := 0; i < b.N; i++ {
		if rd.Float64() > 0.5 {
		}
	}
}

func BenchmarkRandInt(b *testing.B) {
	rd := rand.New(rand.NewSource(time.Now().Unix()))
	for i := 0; i < b.N; i++ {
		if rd.Intn(100) < 50 {
		}
	}
}

func TestRandFloat64(t *testing.T) {
	rd := rand.New(rand.NewSource(time.Now().Unix()))

	for i := 0; i < 100; i++ {
		level := 1
		for rd.Float64() <= 0.5 && level < 32 {
			level++
			//fmt.Printf("[+] %f\n", v)
		}
		fmt.Printf("[+] %d\n", level)
	}
}
