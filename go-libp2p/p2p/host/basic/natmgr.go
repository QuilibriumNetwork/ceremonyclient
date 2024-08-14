package basichost

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	inat "github.com/libp2p/go-libp2p/p2p/net/nat"

	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

// NATManager is a simple interface to manage NAT devices.
// It listens Listen and ListenClose notifications from the network.Network,
// and tries to obtain port mappings for those.
type NATManager interface {
	GetMapping(ma.Multiaddr) ma.Multiaddr
	HasDiscoveredNAT() bool
	io.Closer
}

// NewNATManager creates a NAT manager.
func NewNATManager(net network.Network) NATManager {
	return newNATManager(net)
}

type entry struct {
	protocol string
	port     int
}

type nat interface {
	AddMapping(ctx context.Context, protocol string, port int) error
	RemoveMapping(ctx context.Context, protocol string, port int) error
	GetMapping(protocol string, port int) (netip.AddrPort, bool)
	io.Closer
}

// so we can mock it in tests
var discoverNAT = func(ctx context.Context) (nat, error) { return inat.DiscoverNAT(ctx) }

// natManager takes care of adding + removing port mappings to the nat.
// Initialized with the host if it has a NATPortMap option enabled.
// natManager receives signals from the network, and check on nat mappings:
//   - natManager listens to the network and adds or closes port mappings
//     as the network signals Listen() or ListenClose().
//   - closing the natManager closes the nat and its mappings.
type natManager struct {
	net   network.Network
	natMx sync.RWMutex
	nat   nat

	syncFlag chan struct{} // cap: 1

	tracked map[entry]bool // the bool is only used in doSync and has no meaning outside of that function

	refCount  sync.WaitGroup
	ctx       context.Context
	ctxCancel context.CancelFunc
}

func newNATManager(net network.Network) *natManager {
	ctx, cancel := context.WithCancel(context.Background())
	nmgr := &natManager{
		net:       net,
		syncFlag:  make(chan struct{}, 1),
		ctx:       ctx,
		ctxCancel: cancel,
		tracked:   make(map[entry]bool),
	}
	nmgr.refCount.Add(1)
	go nmgr.background(ctx)
	return nmgr
}

// Close closes the natManager, closing the underlying nat
// and unregistering from network events.
func (nmgr *natManager) Close() error {
	nmgr.ctxCancel()
	nmgr.refCount.Wait()
	return nil
}

func (nmgr *natManager) HasDiscoveredNAT() bool {
	nmgr.natMx.RLock()
	h := nmgr.nat != nil
	nmgr.natMx.RUnlock()
	return h
}

func (nmgr *natManager) background(ctx context.Context) {
	discoverCtx, cancel := context.WithTimeout(ctx, 10*time.Second)

	natInstance, err := discoverNAT(discoverCtx)
	if err != nil {
		log.Info("DiscoverNAT error:", err)
		nmgr.refCount.Done()
		nmgr.natMx.Lock()
		if nmgr.nat != nil {
			nmgr.nat.Close()
		}
		nmgr.natMx.Unlock()
		cancel()
		return
	}

	nmgr.natMx.Lock()
	nmgr.nat = natInstance
	nmgr.natMx.Unlock()

	// sign natManager up for network notifications
	// we need to sign up here to avoid missing some notifs
	// before the NAT has been found.
	nmgr.net.Notify((*nmgrNetNotifiee)(nmgr))

	nmgr.doSync() // sync one first.
	for {
		select {
		case <-nmgr.syncFlag:
			nmgr.doSync() // sync when our listen addresses change.
		case <-ctx.Done():
			nmgr.refCount.Done()
			nmgr.natMx.Lock()
			if nmgr.nat != nil {
				nmgr.nat.Close()
			}
			nmgr.natMx.Unlock()
			cancel()
			nmgr.net.StopNotify((*nmgrNetNotifiee)(nmgr))
			return
		}
	}
}

func (nmgr *natManager) sync() {
	select {
	case nmgr.syncFlag <- struct{}{}:
	default:
	}
}

// doSync syncs the current NAT mappings, removing any outdated mappings and adding any
// new mappings.
func (nmgr *natManager) doSync() {
	for e := range nmgr.tracked {
		nmgr.tracked[e] = false
	}
	var newAddresses []entry
	for _, maddr := range nmgr.net.ListenAddresses() {
		// Strip the IP
		maIP, rest, err := ma.SplitFirst(maddr)
		if maIP == nil || rest == nil || err != nil {
			continue
		}

		switch maIP.Protocol().Code {
		case ma.P_IP6, ma.P_IP4:
		default:
			continue
		}

		// Only bother if we're listening on an unicast / unspecified IP.
		ip := net.IP(maIP.RawValue())
		if !ip.IsGlobalUnicast() && !ip.IsUnspecified() {
			continue
		}

		// Extract the port/protocol
		proto, _, err := ma.SplitFirst(rest)
		if proto == nil || err != nil {
			continue
		}

		var protocol string
		switch proto.Protocol().Code {
		case ma.P_TCP:
			protocol = "tcp"
		case ma.P_UDP:
			protocol = "udp"
		default:
			continue
		}
		port, err := strconv.ParseUint(proto.Value(), 10, 16)
		if err != nil {
			// bug in multiaddr
			panic(err)
		}
		e := entry{protocol: protocol, port: int(port)}
		if _, ok := nmgr.tracked[e]; ok {
			nmgr.tracked[e] = true
		} else {
			newAddresses = append(newAddresses, e)
		}
	}

	// Close old mappings
	for e, v := range nmgr.tracked {
		if !v {
			nmgr.nat.RemoveMapping(nmgr.ctx, e.protocol, e.port)
			delete(nmgr.tracked, e)
		}
	}

	// Create new mappings.
	for _, e := range newAddresses {
		if err := nmgr.nat.AddMapping(nmgr.ctx, e.protocol, e.port); err != nil {
			log.Errorf("failed to port-map %s port %d: %s", e.protocol, e.port, err)
		}
		nmgr.tracked[e] = false
	}
}

func (nmgr *natManager) GetMapping(addr ma.Multiaddr) ma.Multiaddr {
	nmgr.natMx.Lock()

	if nmgr.nat == nil { // NAT not yet initialized
		nmgr.natMx.Unlock()
		return nil
	}

	var found bool
	var proto int // ma.P_TCP or ma.P_UDP
	transport, rest, err := ma.SplitFunc(addr, func(c ma.Component) bool {
		if found {
			return true
		}
		proto = c.Protocol().Code
		found = proto == ma.P_TCP || proto == ma.P_UDP
		return false
	})
	if err != nil {
		nmgr.natMx.Unlock()
		return nil
	}

	if !manet.IsThinWaist(transport) {
		nmgr.natMx.Unlock()
		return nil
	}

	naddr, err := manet.ToNetAddr(transport)
	if err != nil {
		log.Error("error parsing net multiaddr %q: %s", transport, err)
		nmgr.natMx.Unlock()
		return nil
	}

	var (
		ip       net.IP
		port     int
		protocol string
	)
	switch naddr := naddr.(type) {
	case *net.TCPAddr:
		ip = naddr.IP
		port = naddr.Port
		protocol = "tcp"
	case *net.UDPAddr:
		ip = naddr.IP
		port = naddr.Port
		protocol = "udp"
	default:
		nmgr.natMx.Unlock()
		return nil
	}

	if !ip.IsGlobalUnicast() && !ip.IsUnspecified() {
		// We only map global unicast & unspecified addresses ports, not broadcast, multicast, etc.
		nmgr.natMx.Unlock()
		return nil
	}

	extAddr, ok := nmgr.nat.GetMapping(protocol, port)
	if !ok {
		nmgr.natMx.Unlock()
		return nil
	}

	var mappedAddr net.Addr
	switch naddr.(type) {
	case *net.TCPAddr:
		mappedAddr = net.TCPAddrFromAddrPort(extAddr)
	case *net.UDPAddr:
		mappedAddr = net.UDPAddrFromAddrPort(extAddr)
	}
	mappedMaddr, err := manet.FromNetAddr(mappedAddr)
	if err != nil {
		log.Errorf("mapped addr can't be turned into a multiaddr %q: %s", mappedAddr, err)
		nmgr.natMx.Unlock()
		return nil
	}
	extMaddr := mappedMaddr
	if rest != nil {
		extMaddr = ma.Join(extMaddr, rest)
	}
	nmgr.natMx.Unlock()
	return extMaddr
}

type nmgrNetNotifiee natManager

func (nn *nmgrNetNotifiee) natManager() *natManager                          { return (*natManager)(nn) }
func (nn *nmgrNetNotifiee) Listen(network.Network, ma.Multiaddr)             { nn.natManager().sync() }
func (nn *nmgrNetNotifiee) ListenClose(n network.Network, addr ma.Multiaddr) { nn.natManager().sync() }
func (nn *nmgrNetNotifiee) Connected(network.Network, network.Conn)          {}
func (nn *nmgrNetNotifiee) Disconnected(network.Network, network.Conn)       {}
