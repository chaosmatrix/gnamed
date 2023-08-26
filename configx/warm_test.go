package configx

import (
	"encoding/json"
	"os"
	"testing"
)

// BenchmarkWarmUpdateLastTime-8                181           6773876 ns/op
// 2607 ~ 7ms
func BenchmarkWarmUpdateLastTime(b *testing.B) {
	fname := "../data/test/warm_test_data.json"
	wri := &WarmRunnerInfo{}
	wri.FileName = fname
	fr, err := os.Open(fname)
	if err != nil {
		b.Error(err)
	}

	owf := &WarmFormat{}
	err = json.NewDecoder(fr).Decode(owf)
	if err != nil {
		b.Error(err)
	}

	for i := 0; i < b.N; i++ {
		wri.updateLastUsedTime(owf)

	}
}
