package libnamed

import (
	"testing"
)

func TestBytePools(t *testing.T) {
	bytePools := NewBytePool(512, 65535+2, 128)
	for length := 510; length <= 65535+128; length += 127 {
		buf := bytePools.Get(length)
		if len(buf) < length || len(buf) > length+128 {
			t.Errorf("[bytePool] increate length buffer get from bytePool, get %d need %d\n", len(buf), length)
		}
		bytePools.Put(buf)
	}
}

func BenchmarkBytePools(b *testing.B) {
	bytePools := NewBytePool(512, 65535+2, 256)
	for i := 0; i < b.N; i++ {
		buf := bytePools.Get(1232)
		bytePools.Put(buf)

	}
}

func BenchmarkByteArray(b *testing.B) {
	var buf []byte
	for i := 0; i < b.N; i++ {
		buf = make([]byte, 1232)
	}
	_ = buf
}
