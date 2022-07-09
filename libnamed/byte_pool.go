package libnamed

import (
	"sort"
	"sync"
)

// when know about the content size before read content, aka. dns-over-tcp, dns-over-quic (not draft version)
// find the fixed-length buf from sync.Pool can save memory usage
// and prevent allocate memory frequently

type BytePool struct {
	pool   *sync.Pool
	length int
}

type BytePools []BytePool

func NewBytePoolWithLengthSlice(lengths []int) *BytePools {
	sort.Ints(lengths)
	pools := make(BytePools, len(lengths))

	for i := 0; i < len(pools); i++ {
		length := lengths[i]
		pools[i] = BytePool{
			pool: &sync.Pool{
				New: func() interface{} {
					return make([]byte, length)
				},
			},
			length: length,
		}
	}

	return &pools
}

func NewBytePool(minByteLen int, maxByteLen int, stepByteLen int) *BytePools {
	size := (maxByteLen-minByteLen)/stepByteLen + 1
	if size*stepByteLen != maxByteLen {
		size++
	}
	pools := make(BytePools, size)
	for i := 0; i < len(pools); i++ {
		length := minByteLen + i*stepByteLen
		pools[i] = BytePool{
			pool: &sync.Pool{
				New: func() interface{} {
					return make([]byte, length)
				},
			},
			length: length,
		}
	}

	last := len(pools) - 1
	if pools[last].length != maxByteLen {
		pools[last] = BytePool{
			pool: &sync.Pool{
				New: func() interface{} {
					return make([]byte, maxByteLen)
				},
			},
			length: maxByteLen,
		}
	}

	return &pools
}

func (pst *BytePools) getIndex(length int) int {
	ps := *pst
	return sort.Search(len(ps), func(i int) bool {
		return ps[i].length >= length
	})
}

func (pst *BytePools) Put(buf []byte) {
	length := len(buf)
	k := pst.getIndex(length)
	ps := *pst
	if k >= len(ps) {
		return
	}
	ps[k].pool.Put(buf)
}

func (pst *BytePools) Get(length int) []byte {
	k := pst.getIndex(length)
	ps := *pst
	if k >= len(ps) {
		return make([]byte, length)
	}
	return ps[k].pool.Get().([]byte)
}
