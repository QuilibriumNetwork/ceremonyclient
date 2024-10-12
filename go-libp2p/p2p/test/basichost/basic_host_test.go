package basichost

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	libp2pwebrtc "github.com/libp2p/go-libp2p/p2p/transport/webrtc"
	libp2pwebtransport "github.com/libp2p/go-libp2p/p2p/transport/webtransport"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func tStringCast(str string) ma.Multiaddr {
	m, _ := ma.StringCast(str)
	return m
}

func TestNoStreamOverTransientConnection(t *testing.T) {
	h1, err := libp2p.New(
		libp2p.NoListenAddrs,
		libp2p.EnableRelay(),
		libp2p.ResourceManager(&network.NullResourceManager{}),
	)
	require.NoError(t, err)

	h2, err := libp2p.New(
		libp2p.NoListenAddrs,
		libp2p.EnableRelay(),
		libp2p.ResourceManager(&network.NullResourceManager{}),
	)
	require.NoError(t, err)

	relay1, err := libp2p.New()
	require.NoError(t, err)

	_, err = relay.New(relay1)
	require.NoError(t, err)

	relay1info := peer.AddrInfo{
		ID:    relay1.ID(),
		Addrs: relay1.Addrs(),
	}
	err = h1.Connect(context.Background(), relay1info)
	require.NoError(t, err)

	err = h2.Connect(context.Background(), relay1info)
	require.NoError(t, err)

	h2.SetStreamHandler("/testprotocol", func(s network.Stream) {
		fmt.Println("testprotocol")

		// End the example
		s.Close()
	})

	_, err = client.Reserve(context.Background(), h2, relay1info)
	require.NoError(t, err)

	relayaddr := tStringCast("/p2p/" + relay1info.ID.String() + "/p2p-circuit/p2p/" + h2.ID().String())

	h2Info := peer.AddrInfo{
		ID:    h2.ID(),
		Addrs: []ma.Multiaddr{relayaddr},
	}
	err = h1.Connect(context.Background(), h2Info)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx = network.WithNoDial(ctx, "test")
	_, err = h1.NewStream(ctx, h2.ID(), "/testprotocol")

	require.Error(t, err)

	_, err = h1.NewStream(network.WithAllowLimitedConn(context.Background(), "test"), h2.ID(), "/testprotocol")
	require.NoError(t, err)
}

func TestNewStreamTransientConnection(t *testing.T) {
	h1, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/udp/0/quic-v1"),
		libp2p.EnableRelay(),
		libp2p.ResourceManager(&network.NullResourceManager{}),
	)
	require.NoError(t, err)

	h2, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/udp/0/quic-v1"),
		libp2p.EnableRelay(),
		libp2p.ResourceManager(&network.NullResourceManager{}),
	)
	require.NoError(t, err)

	relay1, err := libp2p.New()
	require.NoError(t, err)

	_, err = relay.New(relay1)
	require.NoError(t, err)

	relay1info := peer.AddrInfo{
		ID:    relay1.ID(),
		Addrs: relay1.Addrs(),
	}
	err = h1.Connect(context.Background(), relay1info)
	require.NoError(t, err)

	err = h2.Connect(context.Background(), relay1info)
	require.NoError(t, err)

	h2.SetStreamHandler("/testprotocol", func(s network.Stream) {
		fmt.Println("testprotocol")

		// End the example
		s.Close()
	})

	_, err = client.Reserve(context.Background(), h2, relay1info)
	require.NoError(t, err)

	relayaddr := tStringCast("/p2p/" + relay1info.ID.String() + "/p2p-circuit/p2p/" + h2.ID().String())

	h1.Peerstore().AddAddr(h2.ID(), relayaddr, peerstore.TempAddrTTL)

	// NewStream should block transient connections till we have a direct connection
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	s, err := h1.NewStream(ctx, h2.ID(), "/testprotocol")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Nil(t, s)

	// NewStream should return a stream if a direct connection is established
	// while waiting
	done := make(chan bool, 2)
	go func() {
		h1.Peerstore().AddAddrs(h2.ID(), h2.Addrs(), peerstore.TempAddrTTL)
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ctx = network.WithNoDial(ctx, "test")
		s, err = h1.NewStream(ctx, h2.ID(), "/testprotocol")
		require.NoError(t, err)
		require.NotNil(t, s)
		defer s.Close()
		require.Equal(t, network.DirInbound, s.Conn().Stat().Direction)
		done <- true
	}()
	go func() {
		// connect h2 to h1 simulating connection reversal
		h2.Peerstore().AddAddrs(h1.ID(), h1.Addrs(), peerstore.TempAddrTTL)
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		ctx = network.WithForceDirectDial(ctx, "test")
		err := h2.Connect(ctx, peer.AddrInfo{ID: h1.ID()})
		assert.NoError(t, err)
		done <- true
	}()
	<-done
	<-done
}

func TestAddrFactorCertHashAppend(t *testing.T) {
	wtAddr := "/ip4/1.2.3.4/udp/1/quic-v1/webtransport"
	webrtcAddr := "/ip4/1.2.3.4/udp/2/webrtc-direct"
	addrsFactory := func(addrs []ma.Multiaddr) []ma.Multiaddr {
		return append(addrs,
			tStringCast(wtAddr),
			tStringCast(webrtcAddr),
		)
	}
	h, err := libp2p.New(
		libp2p.AddrsFactory(addrsFactory),
		libp2p.Transport(libp2pwebrtc.New),
		libp2p.Transport(libp2pwebtransport.New),
		libp2p.ListenAddrStrings(
			"/ip4/0.0.0.0/udp/0/quic-v1/webtransport",
			"/ip4/0.0.0.0/udp/0/webrtc-direct",
		),
	)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		addrs := h.Addrs()
		var hasWebRTC, hasWebTransport bool
		for _, addr := range addrs {
			if strings.HasPrefix(addr.String(), webrtcAddr) {
				if _, err := addr.ValueForProtocol(ma.P_CERTHASH); err == nil {
					hasWebRTC = true
				}
			}
			if strings.HasPrefix(addr.String(), wtAddr) {
				if _, err := addr.ValueForProtocol(ma.P_CERTHASH); err == nil {
					hasWebTransport = true
				}
			}
		}
		return hasWebRTC && hasWebTransport
	}, 5*time.Second, 100*time.Millisecond)
}
