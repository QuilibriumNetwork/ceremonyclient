package manet

import (
	"fmt"
	"net"
	"sync"

	ma "github.com/multiformats/go-multiaddr"
)

// FromNetAddrFunc is a generic function which converts a net.Addr to Multiaddress
type FromNetAddrFunc func(a net.Addr) (ma.Multiaddr, error)

// ToNetAddrFunc is a generic function which converts a Multiaddress to net.Addr
type ToNetAddrFunc func(ma ma.Multiaddr) (net.Addr, error)

var defaultCodecs = NewCodecMap()

func init() {
	RegisterFromNetAddr(parseTCPNetAddr, "tcp", "tcp4", "tcp6")
	RegisterFromNetAddr(parseUDPNetAddr, "udp", "udp4", "udp6")
	RegisterFromNetAddr(parseIPNetAddr, "ip", "ip4", "ip6")
	RegisterFromNetAddr(parseIPPlusNetAddr, "ip+net")
	RegisterFromNetAddr(parseUnixNetAddr, "unix")

	RegisterToNetAddr(parseBasicNetMaddr, "tcp", "udp", "ip6", "ip4", "unix")
}

// CodecMap holds a map of NetCodecs indexed by their Protocol ID
// along with parsers for the addresses they use.
// It is used to keep a list of supported network address codecs (protocols
// which addresses can be converted to and from multiaddresses).
type CodecMap struct {
	addrParsers  map[string]FromNetAddrFunc
	maddrParsers map[string]ToNetAddrFunc
	lk           sync.Mutex
}

// NewCodecMap initializes and returns a CodecMap object.
func NewCodecMap() *CodecMap {
	return &CodecMap{
		addrParsers:  make(map[string]FromNetAddrFunc),
		maddrParsers: make(map[string]ToNetAddrFunc),
	}
}

// RegisterFromNetAddr registers a conversion from net.Addr instances to multiaddrs.
func RegisterFromNetAddr(from FromNetAddrFunc, networks ...string) {
	defaultCodecs.RegisterFromNetAddr(from, networks...)
}

// RegisterToNetAddr registers a conversion from multiaddrs to net.Addr instances.
func RegisterToNetAddr(to ToNetAddrFunc, protocols ...string) {
	defaultCodecs.RegisterToNetAddr(to, protocols...)
}

// RegisterFromNetAddr registers a conversion from net.Addr instances to multiaddrs
func (cm *CodecMap) RegisterFromNetAddr(from FromNetAddrFunc, networks ...string) {
	cm.lk.Lock()

	for _, n := range networks {
		cm.addrParsers[n] = from
	}

	cm.lk.Unlock()
}

// RegisterToNetAddr registers a conversion from multiaddrs to net.Addr instances
func (cm *CodecMap) RegisterToNetAddr(to ToNetAddrFunc, protocols ...string) {
	cm.lk.Lock()

	for _, p := range protocols {
		cm.maddrParsers[p] = to
	}

	cm.lk.Unlock()
}

func (cm *CodecMap) getAddrParser(net string) (FromNetAddrFunc, error) {
	cm.lk.Lock()

	parser, ok := cm.addrParsers[net]
	if !ok {
		return nil, fmt.Errorf("unknown network %v", net)
	}

	cm.lk.Unlock()
	return parser, nil
}

func (cm *CodecMap) getMaddrParser(name string) (ToNetAddrFunc, error) {
	cm.lk.Lock()

	p, ok := cm.maddrParsers[name]
	if !ok {
		return nil, fmt.Errorf("network not supported: %s", name)
	}

	cm.lk.Unlock()
	return p, nil
}
