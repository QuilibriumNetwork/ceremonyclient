package basichost

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	ma "github.com/multiformats/go-multiaddr"

	swarmt "github.com/libp2p/go-libp2p/p2p/net/swarm/testing"

	"go.uber.org/mock/gomock"
)

func setupMockNAT(t *testing.T) (mockNAT *MockNAT, reset func()) {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockNAT = NewMockNAT(ctrl)
	origDiscoverNAT := discoverNAT
	discoverNAT = func(ctx context.Context) (nat, error) { return mockNAT, nil }
	return mockNAT, func() {
		discoverNAT = origDiscoverNAT
		ctrl.Finish()
	}
}

func TestMapping(t *testing.T) {
	mockNAT, reset := setupMockNAT(t)
	defer reset()

	sw := swarmt.GenSwarm(t)
	defer sw.Close()
	m := newNATManager(sw)
	require.Eventually(t, func() bool {
		m.natMx.Lock()
		defer m.natMx.Unlock()
		return m.nat != nil
	}, time.Second, time.Millisecond)
	externalAddr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 4321)
	// pretend that we have a TCP mapping
	mockNAT.EXPECT().GetMapping("tcp", 1234).Return(externalAddr, true)
	m1, _ := ma.StringCast("/ip4/1.2.3.4/tcp/4321")
	m2, _ := ma.StringCast("/ip4/0.0.0.0/tcp/1234")
	require.Equal(t, m1, m.GetMapping(m2))

	// pretend that we have a QUIC mapping
	mockNAT.EXPECT().GetMapping("udp", 1234).Return(externalAddr, true)
	m3, _ := ma.StringCast("/ip4/1.2.3.4/udp/4321/quic-v1")
	m4, _ := ma.StringCast("/ip4/0.0.0.0/udp/1234/quic-v1")
	require.Equal(t, m3, m.GetMapping(m4))

	// pretend that there's no mapping
	mockNAT.EXPECT().GetMapping("tcp", 1234).Return(netip.AddrPort{}, false)
	m5, _ := ma.StringCast("/ip4/0.0.0.0/tcp/1234")
	require.Nil(t, m.GetMapping(m5))

	// make sure this works for WebSocket addresses as well
	mockNAT.EXPECT().GetMapping("tcp", 1234).Return(externalAddr, true)
	m6, _ := ma.StringCast("/ip4/1.2.3.4/tcp/4321/ws")
	m7, _ := ma.StringCast("/ip4/0.0.0.0/tcp/1234/ws")
	require.Equal(t, m6, m.GetMapping(m7))

	// make sure this works for WebTransport addresses as well
	mockNAT.EXPECT().GetMapping("udp", 1234).Return(externalAddr, true)
	m8, _ := ma.StringCast("/ip4/1.2.3.4/udp/4321/quic-v1/webtransport")
	m9, _ := ma.StringCast("/ip4/0.0.0.0/udp/1234/quic-v1/webtransport")
	require.Equal(t, m8, m.GetMapping(m9))
}

func TestAddAndRemoveListeners(t *testing.T) {
	mockNAT, reset := setupMockNAT(t)
	defer reset()

	sw := swarmt.GenSwarm(t)
	defer sw.Close()
	m := newNATManager(sw)
	require.Eventually(t, func() bool {
		m.natMx.Lock()
		defer m.natMx.Unlock()
		return m.nat != nil
	}, time.Second, time.Millisecond)

	added := make(chan struct{}, 1)
	// add a TCP listener
	mockNAT.EXPECT().AddMapping(gomock.Any(), "tcp", 1234).Do(func(context.Context, string, int) { added <- struct{}{} })
	m1, _ := ma.StringCast("/ip4/0.0.0.0/tcp/1234")
	require.NoError(t, sw.Listen(m1))
	select {
	case <-added:
	case <-time.After(time.Second):
		t.Fatal("didn't receive call to AddMapping")
	}

	// add a QUIC listener
	mockNAT.EXPECT().AddMapping(gomock.Any(), "udp", 1234).Do(func(context.Context, string, int) { added <- struct{}{} })
	m2, _ := ma.StringCast("/ip4/0.0.0.0/udp/1234/quic-v1")
	require.NoError(t, sw.Listen(m2))
	select {
	case <-added:
	case <-time.After(time.Second):
		t.Fatal("didn't receive call to AddMapping")
	}

	// remove the QUIC listener
	mockNAT.EXPECT().RemoveMapping(gomock.Any(), "udp", 1234).Do(func(context.Context, string, int) { added <- struct{}{} })
	m3, _ := ma.StringCast("/ip4/0.0.0.0/udp/1234/quic-v1")
	sw.ListenClose(m3)
	select {
	case <-added:
	case <-time.After(time.Second):
		t.Fatal("didn't receive call to RemoveMapping")
	}

	// test shutdown
	mockNAT.EXPECT().RemoveMapping(gomock.Any(), "tcp", 1234).MaxTimes(1)
	mockNAT.EXPECT().Close().MaxTimes(1)
}
