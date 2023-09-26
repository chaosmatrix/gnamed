package skiplist

import (
	"fmt"
	"math"
	"math/rand"
	"sort"
	"strconv"
	"testing"
)

func TestSkipList(t *testing.T) {
	skl := NewSkipList(16, 0.5)

	type S struct {
		position int
		key      string
		val      string
	}

	skl.Insert(-200, "-200", "-100")
	skl.Insert(-100, "-100", "-100")
	skl.Insert(-100, "-200", "-100")
	if delCnt := skl.RemoveNLessEqual(5, 600); delCnt != 3 {
		t.Errorf("[+] RemoveFirstNLessEqual: should delete %d, but deleted %d\n", 3, delCnt)
	}

	skl.Insert(-200, "-100", "-100")
	skl.Insert(-200, "-200", "-100")
	if delCnt := skl.RemoveN(3); delCnt != 2 {
		t.Errorf("[+] RemoveN: should delete %d, but deleted %d\n", 2, delCnt)
	}

	skl.Insert(-500, "-500", "-100")
	skl.Insert(-300, "-300", "-100")
	skl.Insert(-200, "-200", "-100")
	skl.Insert(-100, "-100", "-100")
	skl.Insert(-100, "-200", "-100")

	total := 0
	skl.Walk(func(position int, key string, val interface{}) {
		total++
	})
	if total != skl.elementCount {
		t.Errorf("[+] walk: should count: %d, but %d return\n", skl.elementCount, total)
	}

	if delCnt := skl.RemoveNNodeLessEqual(3, 600); delCnt != 3 {
		t.Errorf("[+] RemoveNNodeLessEqual: should delete %d, but deleted %d\n", 3, delCnt)
	}

	if delCnt := skl.RemoveNNode(3); delCnt != 1 {
		t.Errorf("[+] RemoveNNode: should delete %d, but deleted %d\n", 1, delCnt)
	}

	skl.Insert(-500, "-500", "-100")
	skl.Insert(-300, "-300", "-100")
	skl.Insert(-200, "-200", "-100")
	skl.Insert(-100, "-100", "-100")
	skl.Insert(-100, "-200", "-100")

	total = 0
	if _, delCnt := skl.RemoveFunc(func(position int, key string) TypeRemoveMask {
		total++
		return RemoveMaskDelete
	}); delCnt != total || total != 5 || delCnt != 5 || skl.elementCount != 0 {
		t.Errorf("[+] RemoveFunc: should delete %d, but deleted %d\n", total, delCnt)
	}

	skl.Insert(-600, "-500", "-100")
	skl.Insert(-500, "-500", "-100")
	skl.Insert(-300, "-300", "-100")
	skl.Insert(-200, "-200", "-100")
	skl.Insert(-100, "-100", "-100")
	skl.Insert(-100, "-200", "-100")

	total = 0
	if _, delCnt := skl.RemoveNodeFunc(func(position int) TypeRemoveMask {
		total++
		return RemoveMaskDelete
	}); delCnt != total || total != 5 || delCnt != 5 || skl.elementCount != 0 || skl.nodeCount != 2 {
		t.Errorf("[+] RemoveFunc: should delete %d, but deleted %d\n", total, delCnt)
	}

	ts := []S{
		{position: 100, key: "100", val: "a100"},
		{position: 200, key: "200", val: "a200"},

		{position: 500, key: "500", val: "a500"},
		{position: 600, key: "600", val: "a600"},
		{position: 300, key: "300", val: "a300"},
		{position: 300, key: "301", val: "a301"},
		{position: 300, key: "302", val: "a302"},
		{position: math.MaxInt64, key: "301", val: "a301"},
		{position: math.MinInt64, key: "301", val: "a301"},
	}

	cm := make(map[int]int)
	for _, s := range ts {
		cm[s.position]++
	}
	randCnt := 1_000_00
	for i := 1; i < randCnt; i++ {
		v := (rand.Intn(randCnt*1000) + 601)
		//v := i + 601
		cnt := rand.Intn(10) + 1

		// for delete test, the vals that latest add position must not larger than same position before
		if _, found := cm[v]; found {
			continue
		} else {
			cm[v] = cnt
		}

		for j := 0; j < cnt; j++ {
			ts = append(ts, S{position: v, key: strconv.Itoa(v + j), val: "a" + strconv.Itoa(v+j)})
		}
	}

	nodes := make([]*SkipNode, len(ts))
	for i := len(ts) - 1; i >= 0; i-- {
		s := ts[i]
		node := skl.Insert(s.position, s.key, s.val)
		if node == nil {
			t.Errorf("[+] bug insert position: %d key: %s, val: %s\n", s.position, s.key, s.val)
		}
		nodes[i] = node
	}

	for i := len(ts) - 1; i >= 0; i-- {
		s := ts[i]
		found, val := skl.Search(s.position, s.key)
		if !found || val != s.val {
			t.Errorf("[+] bug: position: %d key: %s val: %s, result: %v %v, count: %d(should) != %d(result)\n", s.position, s.key, s.val, found, val, cm[s.position], len(nodes[i].vals))
		}

		// test get node
		node := skl.GetNode(s.position)
		if node == nil {
			t.Errorf("[+] bug: try get node in position: %d, but found %v\n", s.position, node)
		} else if node.position != s.position {
			t.Errorf("[+] bug: try get node in position: %d, but node with position %d get\n", s.position, node.position)
		}

	}

	// test delete
	// ts exist duplicate position, but ensure form right to left same position's val's count is less, to pass this test-case
	for i := len(ts) - 1; i >= 0; i-- {
		s := ts[i]
		node := skl.Delete(s.position, s.key)
		if cm[s.position] > 0 && node == nil {
			fmt.Printf("[+] bug delete wrong node, position: %d key: %s return val: %v != %v, count: %d\n", s.position, s.key, node, s.val, cm[s.position])
		}
		if node != nil {
			cm[s.position]--
		}
	}
	cm = nil

	// test remove
	for _, node := range nodes {
		skl.Remove(node)
	}
	nodes = nil

	for _, s := range ts {
		skl.Insert(s.position, s.key, s.val)
	}

	walk := func(skl *SkipList, direction int, dm map[int]bool, sortedTs []S) {
		switch direction {
		case 1:
			i := 0
			for curr := skl.head; curr != nil && curr.next != nil; curr = curr.next[0] {
				for dm != nil && dm[sortedTs[i].position] {
					i += direction
				}
				if curr.position != sortedTs[i].position {
					t.Errorf("[+] bug: walk %d != %d\n", curr.position, sortedTs[i].position)
				}
				for curr.position == sortedTs[i].position {
					i += direction
				}
			}
		case -1:
			i := len(sortedTs) - 1
			for curr := skl.tail; curr != nil && curr.prev != nil; curr = curr.prev[0] {
				for dm != nil && dm[sortedTs[i].position] {
					i += direction
				}
				if curr.position != sortedTs[i].position {
					t.Errorf("[+] bug: walk %d != %d\n", curr.position, sortedTs[i].position)
				}
				for curr.position == sortedTs[i].position {
					i += direction
				}
			}
		default:
			t.Errorf("[+] bug: unknow walk direction\n")
		}
	}

	sort.Slice(ts, func(i, j int) bool {
		return ts[i].position < ts[j].position
	})

	for i := 1; i < len(ts); i++ {
		s := ts[i]
		// test getLessEqual
		ln := skl.getLessEqualNodeFromHead(s.position)
		if ln.position != s.position {
			t.Errorf("[+] bug: getLessEqualNodeFromHead: position: %d(search) != %d(return)\n", s.position, ln.position)
		}

		if s.position-1 >= ts[i-1].position {
			ln = skl.getLessEqualNodeFromHead(s.position - 1)
			ln2 := skl.getLessEqualNodeFromHead(ts[i-1].position)
			if ln.position != ln2.position {
				t.Errorf("[+] bug: getLessEqualNodeFromHead: position: %d(search), %d(return) != %d(require)\n", s.position-1, ln.position, ln2.position)
			}
		}

		ln = skl.getLessEqualNodeFromTail(s.position)
		if ln.position != s.position {
			t.Errorf("[+] bug: getLessEqualNodeFromTail: position: %d(search) != %d(return)\n", s.position, ln.position)
		}

		if s.position-1 >= ts[i-1].position {
			ln = skl.getLessEqualNodeFromTail(s.position - 1)
			ln2 := skl.getLessEqualNodeFromTail(ts[i-1].position)
			if ln.position != ln2.position {
				t.Errorf("[+] bug: getLessEqualNodeFromTail: position: %d(search), %d(return) != %d(require)\n", s.position-1, ln.position, ln2.position)
			}
		}
	}

	walk(skl, 1, nil, ts)
	walk(skl, -1, nil, ts)

	// random remove
	rand.Shuffle(len(ts), func(i, j int) {
		ts[i], ts[j] = ts[j], ts[i]
	})
	dm := make(map[int]bool)
	delCnt := len(ts) % 100
	if delCnt >= len(ts) {
		delCnt = len(ts) / 2
	}
	for i := delCnt; i >= 0; i-- {
		v := rand.Intn(len(ts))
		node := skl.Insert(ts[v].position, ts[v].key, ts[v].val)
		skl.Remove(node)
		if ts[v].position != math.MinInt64 && ts[v].position != math.MaxInt64 {
			dm[ts[v].position] = true
		}
	}

	sort.Slice(ts, func(i, j int) bool {
		return ts[i].position < ts[j].position
	})
	walk(skl, 1, dm, ts)
	walk(skl, -1, dm, ts)
}

// ref: https://skiplist.readthedocs.io/en/latest/performance.html
//
// metrics:
// 1. 1_000_000 ~ 500ns/op
func BenchmarkSkipList(b *testing.B) {
	skl := NewSkipList(16, 0.5)

	type S struct {
		position int
		key      string
		val      string
	}

	ts := []S{
		{position: 100, key: "100", val: "a100"},
		{position: 200, key: "200", val: "a200"},

		{position: 500, key: "500", val: "a500"},
		{position: 600, key: "600", val: "a600"},
		{position: 300, key: "300", val: "a300"},
		{position: 300, key: "301", val: "a301"},
		{position: math.MaxInt64, key: "301", val: "a301"},
		{position: math.MinInt64, key: "301", val: "a301"},
	}

	for _, s := range ts {
		skl.Insert(s.position, s.key, s.val)
	}

	randCnt := 2_000_000
	for i := 1; i < randCnt; i += 2 {
		//v := (rand.Intn(randCnt) + 1)
		v := i + 1000

		cnt := 2
		for i := 0; i < cnt; i++ {
			skl.Insert(v, strconv.Itoa(v+i), "a"+strconv.Itoa(v+i))
		}
	}

	randCnt = 1_000
	for i := 0; i < randCnt; i += 2 {
		//v := (rand.Intn(randCnt) + 1)
		v := i * 1000

		cnt := 10
		for i := 0; i < cnt; i++ {
			skl.Insert(v, strconv.Itoa(v+i), "a"+strconv.Itoa(v+i))
		}
	}

	//fmt.Printf("[+] nodeCount: %d elementCount: %d\n", skl.nodeCount, skl.elementCount)
	b.ReportAllocs()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		node := skl.Insert(10001, "key10001", "val10001")
		skl.Remove(node)
		//skl.Delete(node.position, "key10001")
	}

}
