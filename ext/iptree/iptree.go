package iptree

import (
	"net"
)

type element struct {
	next [2]*element
	val  *net.IPNet // store cidr
}

type IPTree struct {
	v4 *IPTypeTree
	v6 *IPTypeTree
}

type IPTypeTree struct {
	root *element
	val  *net.IPNet // for /0
}

//     0
//  0    1
// 0 1  0 1

// {v1, v2, ..., v8}
// level -> mask -> val

func NewIPTree() *IPTree {

	iptree := &IPTree{
		v4: &IPTypeTree{
			root: &element{},
			val:  nil,
		},
		v6: &IPTypeTree{
			root: &element{},
			val:  nil,
		},
	}

	return iptree
}

var bitmask = []uint8{1, 2, 4, 8, 16, 32, 64, 128}
var onemap = []uint8{
	0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 1,
}

func (t *IPTree) InsertCIDR(cidr string) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	t.insert(ipnet)
	return nil
}

func (t *IPTree) Insert(ipnet *net.IPNet) {
	t.insert(ipnet)
}

func (t *IPTree) insert(ipnet *net.IPNet) {

	var curr *element

	ip := ipnet.IP
	ipv4 := ip.To4()
	switch ipv4 {
	case nil:
		curr = t.v6.root
	default:
		ip = ipv4
		curr = t.v4.root
	}

	ones, _ := ipnet.Mask.Size()

	for i := 0; i < len(ip) && ones > 0; i++ {
		v := uint8(ip[i])
		for j := len(bitmask) - 1; j >= 0 && ones > 0; j-- {
			bit := onemap[v&bitmask[j]]
			if curr.next[bit] == nil {
				curr.next[bit] = &element{}
			}
			curr = curr.next[bit]
			ones--
		}
	}
	curr.val = ipnet
}

// search the longest match cidr, O(len(ip))
func (t *IPTree) SearchLongestCIDR(s string) string {

	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	if ipnet := t.searchLongest(ip); ipnet != nil {
		return ipnet.String()
	}
	return ""
}

func (t *IPTree) SearchLongest(ip net.IP) net.IPNet {
	if ipnet := t.searchLongest(ip); ipnet != nil {
		return *ipnet
	}
	return net.IPNet{}
}

func (t *IPTree) searchLongest(ip net.IP) *net.IPNet {

	var curr *element

	ipv4 := ip.To4()
	switch ipv4 {
	case nil:
		curr = t.v6.root
	default:
		ip = ipv4
		curr = t.v4.root
	}

	var res *net.IPNet

	for i := 0; i < len(ip); i++ {
		v := uint8(ip[i])
		for j := len(bitmask) - 1; j >= 0; j-- {
			bit := onemap[v&bitmask[j]]

			if curr == nil {
				return res
			}

			if curr.val != nil {
				res = curr.val
			}
			if curr.next[bit] == nil {
				return res
			}
			curr = curr.next[bit]
		}
	}
	if curr != nil && curr.val != nil {
		return curr.val
	}
	return res
}

// search the shortest match cidr, O(len(ip))
func (t *IPTree) SearchShortestCIDR(s string) string {

	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	if ipnet := t.searchShortest(ip); ipnet != nil {
		return ipnet.String()
	}
	return ""
}

func (t *IPTree) SearchShortest(ip net.IP) net.IPNet {
	if ipnet := t.searchShortest(ip); ipnet != nil {
		return *ipnet
	}
	return net.IPNet{}
}

func (t *IPTree) searchShortest(ip net.IP) *net.IPNet {
	var curr *element

	ipv4 := ip.To4()
	switch ipv4 {
	case nil:
		curr = t.v6.root
	default:
		ip = ipv4
		curr = t.v4.root
	}

	for i := 0; i < len(ip); i++ {
		v := uint8(ip[i])
		for j := len(bitmask) - 1; j >= 0; j-- {
			bit := onemap[v&bitmask[j]]

			if curr == nil {
				return nil
			}

			if curr.val != nil {
				return curr.val
			}
			if curr.next[bit] == nil {
				return nil
			}
			curr = curr.next[bit]
		}
	}
	if curr != nil && curr.val != nil {
		return curr.val
	}
	return nil
}

// NOT Implement
func (t *IPTree) Walk(walkFunc func(ipnet *net.IPNet)) {
}
