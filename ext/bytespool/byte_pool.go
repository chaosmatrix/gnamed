package bytespool

import (
	"encoding/binary"
	"fmt"
	"gnamed/ext/xlog"
	"io"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

// when know about the content size before read content, aka. dns-over-tcp, dns-over-quic (not draft version)
// find the fixed-length buf from sync.Pool can save memory usage
// and prevent allocate memory frequently

type bytesPool struct {
	pool   *sync.Pool
	length int
}

type BytesPools struct {
	pools         []bytesPool
	poolIndexFunc func(length int) int
	unfixed       *atomic.Uint64
	getCount      *atomic.Uint64
	putCount      *atomic.Uint64
	allocated     *atomic.Uint64
}

var _BytesPool *BytesPools

func init() {
	_BytesPool = NewDefaultBytesPool(-1)
}

func Put(buf []byte) {
	_BytesPool.Put(buf)
}

func Get(length int) []byte {
	return _BytesPool.Get(length)
}

// https://www.rfc-editor.org/rfc/rfc9250.html#section-4.2
// doq max dns message size 65535 + 2 was the most safe size but increase memory usage
// in most implementation and use case, 4096 + 2 should be enough
// but in most real network, 1500 is the max MTU, dns query should not large than it
// first 2-octet length field indicate the dns msg size in wire format
// in draft version, unable to know reading dns message size
// in rfc9250, able to use 2-octet field to get dns msg size
//
// notes: 99.7% of their traffic is also smaller than 1,232 bytes.
// ref: https://blog.apnic.net/2021/06/16/are-large-dns-messages-falling-to-bits/
// https://tools.ietf.org/id/draft-madi-dnsop-udp4dns-00.html
// 1232 recommended for dual-stack
// 1500 can convert most user case
//
// in most case:
// > request: 18(basic) + len(qname) + len(dns_extension, ecs_v4 22, ecs_v6 35) ~= 18 + 63 + 35 = 106 ~= 128
// > response: 256, 512, 768, 1232, 4096
func NewDefaultBytesPool(maxByteLen int) *BytesPools {
	//lengths := []int{2, 72, 128, 256, 512, 768, 1232, 1500, 4096, 65536}
	lengths := []int{3, 73, 131, 257, 523, 829, 1237, 1511, 1619, 65536}

	if maxByteLen > 0 {
		j := sort.Search(len(lengths), func(i int) bool {
			return lengths[i] >= maxByteLen
		})
		if j >= len(lengths) {
			lengths = append(lengths, maxByteLen)
		} else if lengths[j] > maxByteLen {
			lengths[j] = maxByteLen
			lengths = lengths[:j+1]
		}
	}

	return NewBytePoolWithLengthSlice(lengths)
}

func NewBytePoolWithLengthSlice(lengths []int) *BytesPools {
	sort.Ints(lengths)
	pool := make([]bytesPool, len(lengths))

	allocated := new(atomic.Uint64)
	for i := 0; i < len(pool); i++ {
		length := lengths[i]
		pool[i] = bytesPool{
			pool: &sync.Pool{
				New: func() interface{} {
					allocated.Add(1)
					return make([]byte, length, length+1)
				},
			},
			length: length,
		}
	}

	bps := &BytesPools{
		pools:     pool,
		unfixed:   new(atomic.Uint64),
		allocated: allocated,
		putCount:  new(atomic.Uint64),
		getCount:  new(atomic.Uint64),
	}
	if len(pool) > 10 {
		bps.poolIndexFunc = func(length int) int {
			return sort.Search(len(bps.pools), func(i int) bool {
				return bps.pools[i].length >= length
			})
		}
	} else {
		bps.poolIndexFunc = func(length int) int {
			for i := 0; i < len(bps.pools); i++ {
				if bps.pools[i].length >= length {
					return i
				}
			}
			return len(bps.pools)
		}
	}

	return bps
}

func NewBytePool(minByteLen int, maxByteLen int, stepByteLen int) *BytesPools {
	length := make([]int, 0, (maxByteLen-minByteLen)/stepByteLen+2)
	for bl := minByteLen; bl < maxByteLen; bl += stepByteLen {
		length = append(length, bl)
	}
	length = append(length, maxByteLen)
	return NewBytePoolWithLengthSlice(length)
}

func (pst *BytesPools) Put(buf []byte) {
	if len(buf) == 0 || cap(buf)-len(buf) != 1 {
		return
	}
	i := pst.poolIndexFunc(len(buf))
	if i >= len(pst.pools) || pst.pools[i].length != len(buf) {
		return
	}
	pst.putCount.Add(1)

	pst.pools[i].pool.Put(buf)
}

func (pst *BytesPools) Get(length int) []byte {
	i := pst.poolIndexFunc(length)
	if i >= len(pst.pools) {
		return make([]byte, length)
	}

	buf := pst.pools[i].pool.Get().([]byte)

	getCount := pst.getCount.Add(1)
	if xlog.Logger().Trace().Enabled() {
		stats := zerolog.Dict().Uint64("get", getCount).Uint64("put", pst.putCount.Load()).Uint64("allocate", pst.allocated.Load()).Uint64("unfixed", pst.unfixed.Load())
		xlog.Logger().Trace().Str("log_type", "bytespool").Str("op_type", "get").Int("require_size", length).Int("allocated_size", len(buf)).Dict("stats", stats).Msg("")
	}

	return buf

}

// for dns message

type TypeMask uint8

const (
	MaskEncodeWithoutLength       TypeMask = 1 << iota // normal dns message wire format encode
	MaskEncodeWithLength                               // dns-over-tcp/dns-over-quic/dns-over-tls, append 2-octs to identify the length of dns message wire format
	MaskDisableAutoCompress                            // disable change Compress bit, in default, less than 512: disable compress, large than 512: enable compress
	MaskDisableAutoCompressLt1024                      // disable change Compress bit, if message size lt 1024, tcp or quic protocol, message size less than MSS can be sended in one round

	// AutoCompress Rule:
	// 1. lt 512: disable compress
	// 2. gt 512: enable compress
	MaskAutoCompressFlags = MaskDisableAutoCompress | MaskDisableAutoCompressLt1024

	MaskEncodeWithOptionalLength = MaskEncodeWithoutLength | MaskEncodeWithLength // unable to identify
	MaskEncodeFlags              = MaskEncodeWithoutLength | MaskEncodeWithLength
)

const (
	AutoCompressSizeThreshold512  = 512 - 2  // 2-octs reverse for length field
	AutoCompressSizeThreshold1024 = 1024 - 2 // for tcp or quic like protocol
)

func PackMsg(msg *dns.Msg, tmask TypeMask) (buf []byte, off int, reuse bool, err error) {
	return _BytesPool.PackMsgWitBufSize(msg, 0, tmask)
}

func PackMsgWitBufSize(msg *dns.Msg, bufSize int, tmask TypeMask) (buf []byte, off int, reuse bool, err error) {
	return _BytesPool.PackMsgWitBufSize(msg, bufSize, tmask)
}

func (pst *BytesPools) PackMsgWitBufSize(msg *dns.Msg, bufSize int, tmask TypeMask) (buf []byte, off int, reuse bool, err error) {

	l := 0
	switch tmask & MaskEncodeFlags {
	case MaskEncodeWithOptionalLength:
		err = fmt.Errorf("unable to know the length field should exist or not")
		return
	case MaskEncodeWithLength:
		l = 2
	default:
	}

	msgSize := getMsgUnCompressLen(msg) + 3 // 2-octs, 1 to identify []byte re-allocate or not

	switch tmask & MaskAutoCompressFlags {
	case MaskDisableAutoCompress:
		// do nothing
		if bufSize < 0 {
			err = fmt.Errorf("invalid bufSize: %d", bufSize)
			return
		}
	case MaskDisableAutoCompressLt1024:
		msg.Compress = msg.Compress || msgSize >= AutoCompressSizeThreshold1024
	default:
		msg.Compress = msg.Compress || msgSize >= AutoCompressSizeThreshold512
	}

	if msgSize > bufSize {
		bufSize = msgSize
	}

	buf = pst.Get(bufSize)
	size := len(buf)

	var bmsg []byte
	bmsg, err = msg.PackBuffer(buf[l:])
	if err != nil {
		return
	}

	if len(buf)-l < len(bmsg) {
		pst.Put(buf)
		buf = bmsg
		reuse = false
		pst.unfixed.Add(1)
		xlog.Logger().Trace().Str("log_type", "bytespool").Str("op_type", "get").Int("pool_size", size).Int("need_size", len(buf)).Uint64("unfixed", pst.unfixed.Load()).Msg("pool size not enough")
	} else {
		reuse = true
	}

	if l > 0 {
		if !reuse {
			buf = append([]byte{0, 0}, buf...)
		}
		binary.BigEndian.PutUint16(buf, uint16(len(bmsg)))
	}
	off = len(bmsg) + l

	return
}

func UnpackMsgWitBufSize(reader io.Reader, bufSize int, tmask TypeMask) (msg *dns.Msg, lfmask TypeMask, err error) {
	return _BytesPool.UnpackMsgWitBufSize(reader, bufSize, tmask)
}

func (pst *BytesPools) UnpackMsgWitBufSize(reader io.Reader, bufSize int, tmask TypeMask) (msg *dns.Msg, lfmask TypeMask, err error) {
	if bufSize < 0 {
		err = fmt.Errorf("invalid bufSize: %d", bufSize)
		return
	}

	l := 0
	pktLen := 0
	var buf []byte

	switch tmask & MaskEncodeFlags {
	case MaskEncodeWithLength, MaskEncodeWithOptionalLength:
		l = 2
		buf2 := pst.Get(2)
		n, err1 := reader.Read(buf2[:2])
		if err1 != nil || n != 2 {
			err = fmt.Errorf("failed to read msg length field: %v", err1)
			return
		}
		pktLen = int(binary.BigEndian.Uint16(buf2[:2]))
		if v := pktLen + 3; bufSize < v {
			bufSize = v // 2 + 1
		}
		buf = pst.Get(bufSize)
		buf[0], buf[1] = buf2[0], buf2[1]
		pst.Put(buf2)
	default:
		if bufSize < 32 {
			bufSize = 32
		}
		buf = pst.Get(bufSize)
	}

	size := len(buf)
	defer func() {
		if len(buf) == size {
			pst.Put(buf)
		}
	}()

	var n int
	n, err = reader.Read(buf[l:])
	if err != nil && err != io.EOF {
		return
	}

	off := n + l
	if pktLen != n {
		switch tmask & MaskEncodeFlags {
		case MaskEncodeWithLength:
			err = fmt.Errorf("invalid message, length field not match message size")
			return
		default:
			lfmask = MaskEncodeWithoutLength
			l = 0
		}
	} else {
		lfmask = MaskEncodeWithLength
	}

	if off == len(buf) && err != io.EOF {
		if len(buf) == cap(buf) {
			buf = append(buf, '0')[:len(buf)]
		}
		for off > dns.MaxMsgSize {
			n, err = reader.Read(buf[len(buf):cap(buf)])
			if err != nil && err != io.EOF {
				return
			}
			if err == io.EOF || n == 0 {
				break
			}
			off += n
			buf = append(buf, '0')[:len(buf)]
		}
		if off > dns.MaxMsgSize {
			err = fmt.Errorf("message size too large, limit %d, readed: %d", dns.MaxMsgSize, off)
			return
		}
		pst.unfixed.Add(1)
		xlog.Logger().Trace().Str("log_type", "bytespool").Str("op_type", "get").Int("pool_size", size).Int("need_size", len(buf)).Uint64("unfixed", pst.unfixed.Load()).Msg("pool size not fit with reader")
	}

	msg = new(dns.Msg)
	if err = msg.Unpack(buf[l:off]); err != nil && tmask&MaskEncodeFlags == MaskEncodeWithOptionalLength && l > 0 {
		l = 0
		lfmask = MaskEncodeWithoutLength
		err = msg.Unpack(buf[:off])
	}

	switch tmask & MaskAutoCompressFlags {
	case MaskDisableAutoCompress:
		// do nothing
	case MaskDisableAutoCompressLt1024:
		msg.Compress = off >= AutoCompressSizeThreshold1024 || getMsgUnCompressLen(msg) >= AutoCompressSizeThreshold1024
	default:
		msg.Compress = off >= AutoCompressSizeThreshold512 || getMsgUnCompressLen(msg) >= AutoCompressSizeThreshold512
	}

	return
}

func ReadMsgWitBufSize(reader io.Reader, bufSize int) (buf []byte, off int, reuse bool, err error) {
	return _BytesPool.ReadMsgWitBufSize(reader, bufSize)
}

func (pst *BytesPools) ReadMsgWitBufSize(reader io.Reader, bufSize int) (buf []byte, off int, reuse bool, err error) {
	if bufSize < 0 {
		err = fmt.Errorf("invalid bufSize: %d", bufSize)
		return
	} else if bufSize == 0 {
		bufSize = 1500
	}

	buf = pst.Get(bufSize)
	size := len(buf)

	var n int
	n, err = reader.Read(buf)
	if err != nil && err != io.EOF {
		return
	}

	off = n
	if off == len(buf) && err != io.EOF {
		if len(buf) == cap(buf) {
			buf = append(buf, '0')[:len(buf)]
		}
		for off > dns.MaxMsgSize {
			n, err = reader.Read(buf[len(buf):cap(buf)])
			if err != nil && err != io.EOF {
				return
			}
			if err == io.EOF || n == 0 {
				break
			}
			off += n
			buf = append(buf, '0')[:len(buf)]
		}
		if off > dns.MaxMsgSize {
			err = fmt.Errorf("message size too large, limit %d, readed: %d", dns.MaxMsgSize, off)
			return
		}
		pst.unfixed.Add(1)
		xlog.Logger().Trace().Str("log_type", "bytespool").Str("op_type", "get").Int("pool_size", size).Int("need_size", len(buf)).Uint64("unfixed", pst.unfixed.Load()).Msg("pool size not fit with reader")
	}

	reuse = len(buf) == size
	return
}

func getMsgUnCompressLen(msg *dns.Msg) int {
	old := msg.Compress
	msg.Compress = false
	pktLen := msg.Len()
	msg.Compress = old
	return pktLen
}
