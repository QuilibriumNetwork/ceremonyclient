package libp2pwebrtc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multihash"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func tStringCast(str string) ma.Multiaddr {
	m, _ := ma.StringCast(str)
	return m
}

func getTransport(t *testing.T, opts ...Option) (*WebRTCTransport, peer.ID) {
	t.Helper()
	privKey, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	require.NoError(t, err)
	rcmgr := &network.NullResourceManager{}
	transport, err := New(privKey, nil, nil, rcmgr, opts...)
	require.NoError(t, err)
	peerID, err := peer.IDFromPrivateKey(privKey)
	require.NoError(t, err)
	t.Cleanup(func() { rcmgr.Close() })
	return transport, peerID
}

func TestIsWebRTCDirectMultiaddr(t *testing.T) {
	invalid := []string{
		"/ip4/1.2.3.4/tcp/10/",
		"/ip6/1::3/udp/100/quic-v1/",
		"/ip4/1.2.3.4/udp/1/quic-v1/webrtc-direct",
	}

	valid := []struct {
		addr  string
		count int
	}{
		{
			addr:  "/ip4/1.2.3.4/udp/1234/webrtc-direct",
			count: 0,
		},
		{
			addr:  "/dns/test.test/udp/1234/webrtc-direct",
			count: 0,
		},
		{
			addr:  "/ip4/1.2.3.4/udp/1234/webrtc-direct/certhash/uEiAsGPzpiPGQzSlVHRXrUCT5EkTV7YFrV4VZ3hpEKTd_zg",
			count: 1,
		},
		{
			addr:  "/ip6/0:0:0:0:0:0:0:1/udp/1234/webrtc-direct/certhash/uEiAsGPzpiPGQzSlVHRXrUCT5EkTV7YFrV4VZ3hpEKTd_zg",
			count: 1,
		},
		{
			addr:  "/dns/test.test/udp/1234/webrtc-direct/certhash/uEiAsGPzpiPGQzSlVHRXrUCT5EkTV7YFrV4VZ3hpEKTd_zg",
			count: 1,
		},
		{
			addr:  "/dns/test.test/udp/1234/webrtc-direct/certhash/uEiAsGPzpiPGQzSlVHRXrUCT5EkTV7YFrV4VZ3hpEKTd_zg/certhash/uEiAsGPzpiPGQzSlVHRXrUCT5EkTV7ZGrV4VZ3hpEKTd_zg",
			count: 2,
		},
	}

	for _, addr := range invalid {
		a := tStringCast(addr)
		isValid, n := IsWebRTCDirectMultiaddr(a)
		require.Equal(t, 0, n)
		require.False(t, isValid)
	}

	for _, tc := range valid {
		a := tStringCast(tc.addr)
		isValid, n := IsWebRTCDirectMultiaddr(a)
		require.Equal(t, tc.count, n)
		require.True(t, isValid)
	}
}

func TestTransportWebRTC_CanDial(t *testing.T) {
	tr, _ := getTransport(t)
	invalid := []string{
		"/ip4/1.2.3.4/udp/1234/webrtc-direct",
		"/dns/test.test/udp/1234/webrtc-direct",
	}

	valid := []string{
		"/ip4/1.2.3.4/udp/1234/webrtc-direct/certhash/uEiAsGPzpiPGQzSlVHRXrUCT5EkTV7YFrV4VZ3hpEKTd_zg",
		"/ip6/0:0:0:0:0:0:0:1/udp/1234/webrtc-direct/certhash/uEiAsGPzpiPGQzSlVHRXrUCT5EkTV7YFrV4VZ3hpEKTd_zg",
		"/ip6/::1/udp/1234/webrtc-direct/certhash/uEiAsGPzpiPGQzSlVHRXrUCT5EkTV7YFrV4VZ3hpEKTd_zg",
		"/dns/test.test/udp/1234/webrtc-direct/certhash/uEiAsGPzpiPGQzSlVHRXrUCT5EkTV7YFrV4VZ3hpEKTd_zg",
	}

	for _, addr := range invalid {
		a := tStringCast(addr)
		require.False(t, tr.CanDial(a))
	}

	for _, addr := range valid {
		a := tStringCast(addr)
		require.True(t, tr.CanDial(a), addr)
	}
}

func TestTransportAddCertHasher(t *testing.T) {
	tr, _ := getTransport(t)
	addrs := []string{
		"/ip4/1.2.3.4/udp/1/webrtc-direct",
		"/ip6/1::3/udp/2/webrtc-direct",
	}
	for _, a := range addrs {
		addr, added := tr.AddCertHashes(tStringCast(a))
		require.True(t, added)
		_, err := addr.ValueForProtocol(ma.P_CERTHASH)
		require.NoError(t, err)
		require.True(t, strings.HasPrefix(addr.String(), a))
	}
}

func TestTransportWebRTC_ListenFailsOnNonWebRTCMultiaddr(t *testing.T) {
	tr, _ := getTransport(t)
	testAddrs := []string{
		"/ip4/0.0.0.0/udp/0",
		"/ip4/0.0.0.0/tcp/0/wss",
	}
	for _, addr := range testAddrs {
		listenMultiaddr, err := ma.NewMultiaddr(addr)
		require.NoError(t, err)
		listener, err := tr.Listen(listenMultiaddr)
		require.Error(t, err)
		require.Nil(t, listener)
	}
}

// using assert inside goroutines, refer: https://github.com/stretchr/testify/issues/772#issuecomment-945166599
func TestTransportWebRTC_DialFailsOnUnsupportedHashFunction(t *testing.T) {
	tr, _ := getTransport(t)
	hash := sha3.New512()
	certhash := func() string {
		_, err := hash.Write([]byte("test-data"))
		require.NoError(t, err)
		mh, err := multihash.Encode(hash.Sum([]byte{}), multihash.SHA3_512)
		require.NoError(t, err)
		certhash, err := multibase.Encode(multibase.Base58BTC, mh)
		require.NoError(t, err)
		return certhash
	}()
	testaddr, err := ma.NewMultiaddr("/ip4/1.2.3.4/udp/1234/webrtc-direct/certhash/" + certhash)
	require.NoError(t, err)
	_, err = tr.Dial(context.Background(), testaddr, "")
	require.ErrorContains(t, err, "unsupported hash function")
}

func TestTransportWebRTC_CanListenSingle(t *testing.T) {
	tr, listeningPeer := getTransport(t)
	tr1, connectingPeer := getTransport(t)
	listenMultiaddr := tStringCast("/ip4/127.0.0.1/udp/0/webrtc-direct")

	listener, err := tr.Listen(listenMultiaddr)
	require.NoError(t, err)
	defer listener.Close()

	done := make(chan struct{})
	go func() {
		_, err := tr1.Dial(context.Background(), listener.Multiaddr(), listeningPeer)
		assert.NoError(t, err)
		close(done)
	}()

	conn, err := listener.Accept()
	require.NoError(t, err)
	require.NotNil(t, conn)

	require.Equal(t, connectingPeer, conn.RemotePeer())
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.FailNow()
	}
}

// WithListenerMaxInFlightConnections sets the maximum number of connections that are in-flight, i.e
// they are being negotiated, or are waiting to be accepted.
func WithListenerMaxInFlightConnections(m uint32) Option {
	return func(t *WebRTCTransport) error {
		if m == 0 {
			t.maxInFlightConnections = DefaultMaxInFlightConnections
		} else {
			t.maxInFlightConnections = m
		}
		return nil
	}
}

func TestTransportWebRTC_CanListenMultiple(t *testing.T) {
	count := 3
	tr, listeningPeer := getTransport(t, WithListenerMaxInFlightConnections(uint32(count)))

	listenMultiaddr := tStringCast("/ip4/127.0.0.1/udp/0/webrtc-direct")
	listener, err := tr.Listen(listenMultiaddr)
	require.NoError(t, err)
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	go func() {
		for i := 0; i < count; i++ {
			conn, err := listener.Accept()
			assert.NoError(t, err)
			assert.NotNil(t, conn)
			defer conn.Close()
		}
		wg.Wait()
		cancel()
	}()

	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctr, _ := getTransport(t)
			conn, err := ctr.Dial(ctx, listener.Multiaddr(), listeningPeer)
			select {
			case <-ctx.Done():
			default:
				assert.NoError(t, err)
				assert.NotNil(t, conn)
				t.Cleanup(func() { conn.Close() })
			}
		}()
	}

	select {
	case <-ctx.Done():
	case <-time.After(30 * time.Second):
		t.Fatalf("timed out")
	}
}

func TestTransportWebRTC_CanCreateSuccessiveConnections(t *testing.T) {
	tr, listeningPeer := getTransport(t)
	listenMultiaddr := tStringCast("/ip4/127.0.0.1/udp/0/webrtc-direct")
	listener, err := tr.Listen(listenMultiaddr)
	require.NoError(t, err)
	defer listener.Close()

	count := 2

	var wg sync.WaitGroup
	wg.Add(count)
	go func() {
		for i := 0; i < count; i++ {
			ctr, _ := getTransport(t)
			conn, err := ctr.Dial(context.Background(), listener.Multiaddr(), listeningPeer)
			require.NoError(t, err)
			require.Equal(t, conn.RemotePeer(), listeningPeer)
			t.Cleanup(func() { conn.Close() })
			wg.Done()
		}
	}()

	for i := 0; i < count; i++ {
		conn, err := listener.Accept()
		require.NoError(t, err)
		defer conn.Close()
	}
	wg.Wait()
}

func TestTransportWebRTC_ListenerCanCreateStreams(t *testing.T) {
	tr, listeningPeer := getTransport(t)
	tr1, connectingPeer := getTransport(t)
	listenMultiaddr := tStringCast("/ip4/127.0.0.1/udp/0/webrtc-direct")
	listener, err := tr.Listen(listenMultiaddr)
	require.NoError(t, err)
	defer listener.Close()

	streamChan := make(chan network.MuxedStream)
	go func() {
		conn, err := tr1.Dial(context.Background(), listener.Multiaddr(), listeningPeer)
		require.NoError(t, err)
		t.Cleanup(func() { conn.Close() })
		t.Logf("connection opened by dialer")

		stream, err := conn.AcceptStream()
		require.NoError(t, err)
		t.Logf("dialer accepted stream")
		streamChan <- stream
	}()

	conn, err := listener.Accept()
	require.NoError(t, err)
	defer conn.Close()
	require.Equal(t, connectingPeer, conn.RemotePeer())
	t.Logf("listener accepted connection")

	stream, err := conn.OpenStream(context.Background())
	require.NoError(t, err)
	t.Logf("listener opened stream")
	_, err = stream.Write([]byte("test"))
	require.NoError(t, err)

	var str network.MuxedStream
	select {
	case str = <-streamChan:
	case <-time.After(3 * time.Second):
		t.Fatal("stream opening timed out")
	}
	buf := make([]byte, 100)
	stream.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := str.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "test", string(buf[:n]))
}

func TestTransportWebRTC_DialerCanCreateStreams(t *testing.T) {
	tr, listeningPeer := getTransport(t)
	listenMultiaddr := tStringCast("/ip4/127.0.0.1/udp/0/webrtc-direct")
	listener, err := tr.Listen(listenMultiaddr)
	require.NoError(t, err)
	defer listener.Close()

	tr1, connectingPeer := getTransport(t)
	done := make(chan struct{})

	go func() {
		lconn, err := listener.Accept()
		require.NoError(t, err)
		require.Equal(t, connectingPeer, lconn.RemotePeer())
		defer lconn.Close()

		stream, err := lconn.AcceptStream()
		require.NoError(t, err)
		buf := make([]byte, 100)
		n, err := stream.Read(buf)
		require.NoError(t, err)
		require.Equal(t, "test", string(buf[:n]))

		close(done)
	}()

	go func() {
		conn, err := tr1.Dial(context.Background(), listener.Multiaddr(), listeningPeer)
		require.NoError(t, err)
		defer conn.Close()
		t.Logf("dialer opened connection")
		stream, err := conn.OpenStream(context.Background())
		require.NoError(t, err)
		t.Logf("dialer opened stream")
		_, err = stream.Write([]byte("test"))
		require.NoError(t, err)
		<-done
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out")
	}
}

func TestTransportWebRTC_DialerCanCreateStreamsMultiple(t *testing.T) {
	tr, listeningPeer := getTransport(t)
	listenMultiaddr := tStringCast("/ip4/127.0.0.1/udp/0/webrtc-direct")
	listener, err := tr.Listen(listenMultiaddr)
	require.NoError(t, err)
	defer listener.Close()

	tr1, connectingPeer := getTransport(t)
	readerDone := make(chan struct{})

	const (
		numListeners = 10
		numStreams   = 100
		numWriters   = 10
		size         = 20 << 10
	)

	go func() {
		lconn, err := listener.Accept()
		require.NoError(t, err)
		require.Equal(t, connectingPeer, lconn.RemotePeer())
		defer lconn.Close()
		var wg sync.WaitGroup
		var doneStreams atomic.Int32
		for i := 0; i < numListeners; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					var nn int32
					if nn = doneStreams.Add(1); nn > int32(numStreams) {
						return
					}
					s, err := lconn.AcceptStream()
					require.NoError(t, err)
					n, err := io.Copy(s, s)
					require.Equal(t, n, int64(size))
					require.NoError(t, err)
					s.Close()
				}
			}()
		}
		wg.Wait()
		readerDone <- struct{}{}
	}()

	conn, err := tr1.Dial(context.Background(), listener.Multiaddr(), listeningPeer)
	require.NoError(t, err)
	defer conn.Close()

	var writerWG sync.WaitGroup
	var cnt atomic.Int32
	var streamsStarted atomic.Int32
	for i := 0; i < numWriters; i++ {
		writerWG.Add(1)
		go func() {
			defer writerWG.Done()
			buf := make([]byte, size)
			for {
				var nn int32
				if nn = streamsStarted.Add(1); nn > int32(numStreams) {
					return
				}
				rand.Read(buf)

				s, err := conn.OpenStream(context.Background())
				require.NoError(t, err)
				n, err := s.Write(buf)
				require.Equal(t, n, size)
				require.NoError(t, err)
				s.CloseWrite()
				resp := make([]byte, size+10)
				n, err = io.ReadFull(s, resp)
				require.ErrorIs(t, err, io.ErrUnexpectedEOF)
				require.Equal(t, n, size)
				if string(buf) != string(resp[:size]) {
					t.Errorf("bytes not equal: %d %d", len(buf), len(resp))
				}
				s.Close()
				t.Log("completed stream: ", cnt.Add(1), s.(*stream).id)
			}
		}()
	}
	writerWG.Wait()
	select {
	case <-readerDone:
	case <-time.After(100 * time.Second):
		t.Fatal("timed out")
	}
}

func TestTransportWebRTC_Deadline(t *testing.T) {
	tr, listeningPeer := getTransport(t)
	listenMultiaddr := tStringCast("/ip4/127.0.0.1/udp/0/webrtc-direct")
	listener, err := tr.Listen(listenMultiaddr)
	require.NoError(t, err)
	defer listener.Close()
	tr1, connectingPeer := getTransport(t)

	t.Run("SetReadDeadline", func(t *testing.T) {
		go func() {
			lconn, err := listener.Accept()
			require.NoError(t, err)
			t.Cleanup(func() { lconn.Close() })
			require.Equal(t, connectingPeer, lconn.RemotePeer())
			_, err = lconn.AcceptStream()
			require.NoError(t, err)
		}()

		conn, err := tr1.Dial(context.Background(), listener.Multiaddr(), listeningPeer)
		require.NoError(t, err)
		defer conn.Close()
		stream, err := conn.OpenStream(context.Background())
		require.NoError(t, err)

		// deadline set to the past
		stream.SetReadDeadline(time.Now().Add(-200 * time.Millisecond))
		_, err = stream.Read([]byte{0, 0})
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)

		// future deadline exceeded
		stream.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_, err = stream.Read([]byte{0, 0})
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	})

	t.Run("SetWriteDeadline", func(t *testing.T) {
		go func() {
			lconn, err := listener.Accept()
			require.NoError(t, err)
			t.Cleanup(func() { lconn.Close() })
			require.Equal(t, connectingPeer, lconn.RemotePeer())
			_, err = lconn.AcceptStream()
			require.NoError(t, err)
		}()

		conn, err := tr1.Dial(context.Background(), listener.Multiaddr(), listeningPeer)
		require.NoError(t, err)
		defer conn.Close()
		stream, err := conn.OpenStream(context.Background())
		require.NoError(t, err)

		stream.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		largeBuffer := make([]byte, 2*1024*1024)
		_, err = stream.Write(largeBuffer)
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)

		stream.SetWriteDeadline(time.Now().Add(-200 * time.Millisecond))
		smallBuffer := make([]byte, 1024)
		_, err = stream.Write(smallBuffer)
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	})
}

func TestTransportWebRTC_StreamWriteBufferContention(t *testing.T) {
	tr, listeningPeer := getTransport(t)
	listenMultiaddr := tStringCast("/ip4/127.0.0.1/udp/0/webrtc-direct")
	listener, err := tr.Listen(listenMultiaddr)
	require.NoError(t, err)
	defer listener.Close()

	tr1, connectingPeer := getTransport(t)

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		lconn, err := listener.Accept()
		require.NoError(t, err)
		t.Cleanup(func() { lconn.Close() })
		require.Equal(t, connectingPeer, lconn.RemotePeer())
		for i := 0; i < 2; i++ {
			go func() {
				defer wg.Done()
				_, err := lconn.AcceptStream()
				require.NoError(t, err)
			}()
		}
	}()

	conn, err := tr1.Dial(context.Background(), listener.Multiaddr(), listeningPeer)
	require.NoError(t, err)
	defer conn.Close()

	errC := make(chan error)
	// writers
	for i := 0; i < 2; i++ {
		go func() {
			stream, err := conn.OpenStream(context.Background())
			require.NoError(t, err)

			stream.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
			largeBuffer := make([]byte, 2*1024*1024)
			_, err = stream.Write(largeBuffer)
			errC <- err
		}()
	}

	require.ErrorIs(t, <-errC, os.ErrDeadlineExceeded)
	require.ErrorIs(t, <-errC, os.ErrDeadlineExceeded)
	wg.Wait()
}

func TestTransportWebRTC_RemoteReadsAfterClose(t *testing.T) {
	tr, listeningPeer := getTransport(t)
	listenMultiaddr := tStringCast("/ip4/127.0.0.1/udp/0/webrtc-direct")
	listener, err := tr.Listen(listenMultiaddr)
	require.NoError(t, err)
	defer listener.Close()

	tr1, _ := getTransport(t)

	done := make(chan error)
	go func() {
		lconn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		t.Cleanup(func() { lconn.Close() })

		stream, err := lconn.AcceptStream()
		if err != nil {
			done <- err
			return
		}
		_, err = stream.Write([]byte{1, 2, 3, 4})
		if err != nil {
			done <- err
			return
		}
		err = stream.Close()
		if err != nil {
			done <- err
			return
		}
		close(done)
	}()

	conn, err := tr1.Dial(context.Background(), listener.Multiaddr(), listeningPeer)
	require.NoError(t, err)
	defer conn.Close()
	// create a stream
	stream, err := conn.OpenStream(context.Background())

	require.NoError(t, err)
	// require write and close to complete
	require.NoError(t, <-done)
	stream.SetReadDeadline(time.Now().Add(5 * time.Second))

	buf := make([]byte, 10)
	n, err := stream.Read(buf)
	require.NoError(t, err)
	require.Equal(t, 4, n)
}

func TestTransportWebRTC_RemoteReadsAfterClose2(t *testing.T) {
	tr, listeningPeer := getTransport(t)
	listenMultiaddr := tStringCast("/ip4/127.0.0.1/udp/0/webrtc-direct")
	listener, err := tr.Listen(listenMultiaddr)
	require.NoError(t, err)
	defer listener.Close()

	tr1, _ := getTransport(t)

	awaitStreamClosure := make(chan struct{})
	readBytesResult := make(chan int)
	done := make(chan error)
	go func() {
		lconn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer lconn.Close()
		stream, err := lconn.AcceptStream()
		if err != nil {
			done <- err
			return
		}

		<-awaitStreamClosure
		buf := make([]byte, 16)
		n, err := stream.Read(buf)
		if err != nil {
			done <- err
			return
		}
		readBytesResult <- n
		close(done)
	}()

	conn, err := tr1.Dial(context.Background(), listener.Multiaddr(), listeningPeer)
	require.NoError(t, err)
	defer conn.Close()
	// create a stream
	stream, err := conn.OpenStream(context.Background())
	require.NoError(t, err)
	_, err = stream.Write([]byte{1, 2, 3, 4})
	require.NoError(t, err)
	err = stream.Close()
	require.NoError(t, err)
	// signal stream closure
	close(awaitStreamClosure)
	require.Equal(t, 4, <-readBytesResult)
}

func TestTransportWebRTC_Close(t *testing.T) {
	tr, listeningPeer := getTransport(t)
	listenMultiaddr := tStringCast("/ip4/127.0.0.1/udp/0/webrtc-direct")
	listener, err := tr.Listen(listenMultiaddr)
	require.NoError(t, err)
	defer listener.Close()

	tr1, connectingPeer := getTransport(t)

	t.Run("RemoteClosesStream", func(t *testing.T) {
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			lconn, err := listener.Accept()
			require.NoError(t, err)
			t.Cleanup(func() { lconn.Close() })
			require.Equal(t, connectingPeer, lconn.RemotePeer())
			stream, err := lconn.AcceptStream()
			require.NoError(t, err)
			time.Sleep(100 * time.Millisecond)
			_ = stream.Close()
		}()

		buf := make([]byte, 2)

		conn, err := tr1.Dial(context.Background(), listener.Multiaddr(), listeningPeer)
		require.NoError(t, err)
		defer conn.Close()
		stream, err := conn.OpenStream(context.Background())
		require.NoError(t, err)

		err = stream.SetReadDeadline(time.Now().Add(2 * time.Second))
		require.NoError(t, err)
		_, err = stream.Read(buf)
		require.ErrorIs(t, err, io.EOF)

		wg.Wait()
	})
}

func TestTransportWebRTC_PeerConnectionDTLSFailed(t *testing.T) {
	tr, listeningPeer := getTransport(t)
	listenMultiaddr := tStringCast("/ip4/127.0.0.1/udp/0/webrtc-direct")
	ln, err := tr.Listen(listenMultiaddr)
	require.NoError(t, err)
	defer ln.Close()

	encoded, err := hex.DecodeString("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
	require.NoError(t, err)
	encodedCerthash, err := multihash.Encode(encoded, multihash.SHA2_256)
	require.NoError(t, err)
	badEncodedCerthash, err := multibase.Encode(multibase.Base58BTC, encodedCerthash)
	require.NoError(t, err)
	badCerthash, err := ma.NewMultiaddr(fmt.Sprintf("/certhash/%s", badEncodedCerthash))
	require.NoError(t, err)
	badMultiaddr, _, _ := ma.SplitFunc(ln.Multiaddr(), func(c ma.Component) bool { return c.Protocol().Code == ma.P_CERTHASH })
	badMultiaddr = badMultiaddr.Encapsulate(badCerthash)

	tr1, _ := getTransport(t)
	conn, err := tr1.Dial(context.Background(), badMultiaddr, listeningPeer)
	require.Error(t, err)
	require.ErrorContains(t, err, "failed")
	require.Nil(t, conn)
}

func TestConnectionTimeoutOnListener(t *testing.T) {
	tr, listeningPeer := getTransport(t)
	tr.peerConnectionTimeouts.Disconnect = 100 * time.Millisecond
	tr.peerConnectionTimeouts.Failed = 150 * time.Millisecond
	tr.peerConnectionTimeouts.Keepalive = 50 * time.Millisecond

	listenMultiaddr := tStringCast("/ip4/127.0.0.1/udp/0/webrtc-direct")
	ln, err := tr.Listen(listenMultiaddr)
	require.NoError(t, err)
	defer ln.Close()

	var drop atomic.Bool
	proxy, err := quicproxy.NewQuicProxy("127.0.0.1:0", &quicproxy.Opts{
		RemoteAddr: fmt.Sprintf("127.0.0.1:%d", ln.Addr().(*net.UDPAddr).Port),
		DropPacket: func(quicproxy.Direction, []byte) bool { return drop.Load() },
	})
	require.NoError(t, err)
	defer proxy.Close()

	tr1, connectingPeer := getTransport(t)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		addr, err := manet.FromNetAddr(proxy.LocalAddr())
		require.NoError(t, err)
		_, webrtcComponent, _ := ma.SplitFunc(ln.Multiaddr(), func(c ma.Component) bool { return c.Protocol().Code == ma.P_WEBRTC_DIRECT })
		addr = addr.Encapsulate(webrtcComponent)
		conn, err := tr1.Dial(ctx, addr, listeningPeer)
		require.NoError(t, err)
		t.Cleanup(func() { conn.Close() })
		str, err := conn.OpenStream(ctx)
		require.NoError(t, err)
		str.Write([]byte("foobar"))
	}()

	conn, err := ln.Accept()
	require.NoError(t, err)
	require.Equal(t, connectingPeer, conn.RemotePeer())
	defer conn.Close()

	str, err := conn.AcceptStream()
	require.NoError(t, err)
	_, err = str.Write([]byte("test"))
	require.NoError(t, err)
	// start dropping all packets
	drop.Store(true)
	start := time.Now()
	for {
		if _, err := str.Write([]byte("test")); err != nil {
			if os.IsTimeout(err) {
				break
			}
			// If we write when a connection timeout happens, sctp provides
			// a "stream closed" error. This occurs concurrently with the
			// callback we receive for connection timeout.
			// Test once more after sleep that we provide the correct error.
			if strings.Contains(err.Error(), "stream closed") {
				time.Sleep(50 * time.Millisecond)
				_, err = str.Write([]byte("test"))
				require.True(t, os.IsTimeout(err), "invalid error type: %v", err)
			} else {
				t.Fatal("invalid error type", err)
			}
			break
		}

		if time.Since(start) > 5*time.Second {
			t.Fatal("timeout")
		}
		// make sure to not write too often, we don't want to fill the flow control window
		time.Sleep(20 * time.Millisecond)
	}
	// make sure that accepting a stream also returns an error...
	_, err = conn.AcceptStream()
	require.True(t, os.IsTimeout(err))
	// ... as well as opening a new stream
	_, err = conn.OpenStream(context.Background())
	require.True(t, os.IsTimeout(err))
}

func TestMaxInFlightRequests(t *testing.T) {
	const count = 3
	tr, listeningPeer := getTransport(t,
		WithListenerMaxInFlightConnections(count),
	)
	ln, err := tr.Listen(tStringCast("/ip4/127.0.0.1/udp/0/webrtc-direct"))
	require.NoError(t, err)
	defer ln.Close()

	var wg sync.WaitGroup
	var success, fails atomic.Int32
	for i := 0; i < count+1; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dialer, _ := getTransport(t)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if conn, err := dialer.Dial(ctx, ln.Multiaddr(), listeningPeer); err == nil {
				success.Add(1)
				t.Cleanup(func() { conn.Close() })
			} else {
				t.Log("failed to dial:", err)
				fails.Add(1)
			}
		}()
	}
	wg.Wait()
	require.Equal(t, count, int(success.Load()), "expected exactly 3 dial successes")
	require.Equal(t, 1, int(fails.Load()), "expected exactly 1 dial failure")
}
