package bytespool

import (
	"fmt"
	"sync"
	"testing"
	"unsafe"

	"github.com/miekg/dns"
)

func TestBytePools(t *testing.T) {
	minByteLen, maxByteLen, stepByteLen := 512, 65535, 128
	bytePools := NewBytePool(512, 65535, 128)
	for length := 32; length <= minByteLen; length++ {
		buf := bytePools.Get(length)
		if len(buf) != minByteLen || len(buf) < length {
			t.Errorf("[bytePool] increate length buffer get from bytePool, get %d need %d\n", len(buf), length)
		}
		bytePools.Put(buf)
	}

	for length := minByteLen - stepByteLen + 1; length <= maxByteLen+stepByteLen-1; length += stepByteLen {
		buf := bytePools.Get(length)
		if len(buf) < length || len(buf)-length >= 128 {
			t.Errorf("[bytePool] increate length buffer get from bytePool, get %d need %d\n", len(buf), length)
		}
		bytePools.Put(buf)
	}

	for length := maxByteLen + 1; length < maxByteLen*2; length++ {
		buf := bytePools.Get(length)
		if len(buf) != length {
			t.Errorf("[bytePool] increate length buffer get from bytePool, get %d need %d\n", len(buf), length)
		}
		bytePools.Put(buf)
	}
}

func TestNewDefaultBytesPool(t *testing.T) {
	maxByteLen := 65536
	bytePools := NewDefaultBytesPool(maxByteLen)
	pm := make(map[int]uintptr)
	for length := 0; length <= maxByteLen; length++ {
		buf := bytePools.Get(length)
		pointer := uintptr(unsafe.Pointer(&buf))
		if p, found := pm[len(buf)]; found {
			if p != pointer {
				t.Errorf("[bytesPool] new allocation happened, %d(old) != %d(new)\n", p, pointer)
			}
		} else {
			pm[len(buf)] = pointer
		}
		if len(buf) < length || (length > maxByteLen && length != len(buf)) {
			t.Errorf("[bytePool] increate length buffer get from bytePool, get %d need %d\n", len(buf), length)
		}
		bytePools.Put(buf)
	}
	if len(pm) != len(bytePools.pools) {
		t.Errorf("[bytesPool] additional bytesPool allocated, %d(need) != %d(allocation)\n", len(pm), len(bytePools.pools))
	}

	for length := maxByteLen; length <= maxByteLen*2; length *= 2 {
		buf := bytePools.Get(length)
		if len(buf) != length {
			t.Errorf("[bytePool] increate length buffer get from bytePool, get %d need %d\n", len(buf), length)
		}
		bytePools.Put(buf)
	}

}

func TestNewDefaultGlobalBytesPool(t *testing.T) {
	maxByteLen := 65536
	pm := make(map[int]uintptr)
	for length := 0; length <= maxByteLen; length++ {
		buf := Get(length)
		pointer := uintptr(unsafe.Pointer(&buf))
		if p, found := pm[len(buf)]; found {
			if p != pointer {
				t.Errorf("[bytesPool] new allocation happened, %d(old) != %d(new)\n", p, pointer)
			}
		} else {
			pm[len(buf)] = pointer
		}
		if len(buf) < length || (length > maxByteLen && length != len(buf)) {
			t.Errorf("[bytePool] increate length buffer get from bytePool, get %d need %d\n", len(buf), length)
		}
		Put(buf)
	}
	if len(pm) != len(_BytesPool.pools) {
		t.Errorf("[bytesPool] additional bytesPool allocated, %d(need) != %d(allocation)\n", len(pm), len(_BytesPool.pools))
	}

	for length := maxByteLen; length <= maxByteLen*2; length *= 2 {
		buf := Get(length)
		if len(buf) != length {
			t.Errorf("[bytePool] increate length buffer get from bytePool, get %d need %d\n", len(buf), length)
		}
		Put(buf)
	}

}

func BenchmarkBytePools(b *testing.B) {
	//bytePools := NewBytePool(512, 65535+2, 256)
	bytePools := NewDefaultBytesPool(-1)
	for i := 0; i < b.N; i++ {
		buf := bytePools.Get(1232)
		bytePools.Put(buf)
	}
}

func BenchmarkSyncPools512(b *testing.B) {
	pool := &sync.Pool{
		New: func() any {
			return make([]byte, 512)
		},
	}
	for i := 0; i < b.N; i++ {
		buf := pool.Get()
		pool.Put(buf)

	}
}

func BenchmarkByteArray512(b *testing.B) {
	var buf []byte
	for i := 0; i < b.N; i++ {
		buf = make([]byte, 512)
	}
	_ = buf
}

func newTestMsg() *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion("wwww.example.com.", dns.TypeA)

	rss := []string{
		"wwww.example.com.	60	IN	A	123.123.123.123",
		"wwww.example.com.	60	IN	A	123.123.123.223",
		"wwww.example.com.	60	IN	A	123.123.123.133",
	}
	for _, rs := range rss {
		rr, err := dns.NewRR(rs)
		if err != nil {
			panic(err)
		}
		msg.Answer = append(msg.Answer, rr)
	}
	return msg
}

// unCompress(35ns/op) 6x faster than Compress (230ns/op)
func BenchmarkMsgLen(b *testing.B) {
	msg := newTestMsg()
	msg.Compress = true
	for i := 0; i < b.N; i++ {
		msg.Len()
	}
}

func BenchmarkMsgLenGet(b *testing.B) {
	msg := newTestMsg()
	//msg.Compress = true
	for i := 0; i < b.N; i++ {
		getMsgUnCompressLen(msg)
	}
}

func TestByteGraw(t *testing.T) {
	bs := make([]byte, 10, 11)

	fmt.Printf("[+] %03d. %p\n", 0, bs)

	for i := 1; i < 100; i++ {
		bs = append(bs, 0)[:len(bs)]
		fmt.Printf("[+] %03d. %p\n", i, bs)
	}
}
