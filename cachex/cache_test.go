package cachex

import (
	"fmt"
	"gnamed/libnamed"
	"math"
	"sort"
	"strconv"
	"testing"
	"time"
	"unsafe"
)

func TestSklCache(t *testing.T) {

	fmt.Printf("[+] test SklCache\n")
	fmt.Printf("[+]\n")

	sklc := newSklCache(32, 0.5)

	type testEntry struct {
		domain string
		qtype  uint16
		vals   []byte
		ttl    uint32
		ts     int64
	}

	fakeTimer := libnamed.NewFakeTimer(1 * time.Second)
	fakeTimer.Run()

	if diff := time.Now().Unix() - libnamed.GetFakeTimerUnixSecond(); diff > 5 {
		t.Errorf("[+] FakeTimer return time less than system time %d large than 5s\n", diff)
	}

	now := libnamed.GetFakeTimerUnixSecond()

	tes := []testEntry{
		{
			domain: "example.com",
			qtype:  5,
			vals:   []byte("1"),
			ttl:    300,
			ts:     now + 300,
		},
		{
			domain: "www.example.com",
			qtype:  5,
			vals:   []byte("1"),
			ttl:    300,
			ts:     now + 300,
		},
		{
			domain: "www1.example.com",
			qtype:  5,
			vals:   []byte("1"),
			ttl:    60,
			ts:     now + 60,
		},
		{
			domain: "google.com",
			qtype:  5,
			vals:   []byte("1"),
			ttl:    600,
			ts:     now + 600,
		},
		{
			domain: "www1.google.com",
			qtype:  5,
			vals:   []byte("1"),
			ttl:    600,
			ts:     now + 600,
		},
		{
			domain: "www2.google.com",
			qtype:  5,
			vals:   []byte("1"),
			ttl:    900,
			ts:     now + 900,
		},
		{
			domain: "www.google.com",
			qtype:  5,
			vals:   []byte("1"),
			ttl:    600,
			ts:     now + 600,
		},
		{
			domain: "localhost",
			qtype:  5,
			vals:   []byte("1"),
			ttl:    900,
			ts:     now + 900,
		},
	}

	// should be updated
	sklc.Set("google.com", 5, []byte("3"), 900)

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
		sklc.Set("example.com", 5, []byte("1"), 300)
		sklc.Set("www.example.com", 5, []byte("2"), 300)
		sklc.Set("www1.example.com", 5, []byte("2"), 500)
		ts := time.Now().Unix() + 200

		sklc.Set("www.google.com", 5, []byte("2"), 600)
		sklc.Set("google.com", 5, []byte("2"), 600)
		sklc.Set("google.com", 5, []byte("3"), 900)
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

	fakeTimer.Stop()
}

func TestSklCacheRandom(t *testing.T) {
	size := 1 << 16
	removePercent := 100 // 1/100

	sklc := newSklCache(32, 0.5)

	for i := 300; i < size; i++ {
		ok := sklc.Set(strconv.Itoa(i), uint16(i%32+3), []byte{byte(i)}, uint32(i&math.MaxUint32))
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
			if i%removePercent == 0 || len(val) == 0 || val[0] != byte(i) {
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

	sklc := newSklCache(32, 0.5)

	for i := 300; i < b.N; i++ {
		sklc.Set(strconv.Itoa(i), 1, []byte{byte(i)}, uint32(i&math.MaxUint32))
	}

	for i := 300; i < b.N; i++ {
		if val, _, found := sklc.Get(strconv.Itoa(i), 1); !found || val[0] != byte(i) {
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
