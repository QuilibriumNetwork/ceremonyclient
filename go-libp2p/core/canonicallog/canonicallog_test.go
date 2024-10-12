package canonicallog

import (
	"fmt"
	"net"
	"testing"

	"github.com/libp2p/go-libp2p/core/test"

	logging "github.com/ipfs/go-log/v2"
	"github.com/multiformats/go-multiaddr"
)

func TestLogs(t *testing.T) {
	err := logging.SetLogLevel("canonical-log", "info")
	if err != nil {
		t.Fatal(err)
	}

	m, _ := multiaddr.StringCast("/ip4/1.2.3.4")
	LogMisbehavingPeer(test.RandPeerIDFatal(t), m, "somecomponent", fmt.Errorf("something"), "hi")

	netAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 80}
	LogMisbehavingPeerNetAddr(test.RandPeerIDFatal(t), netAddr, "somecomponent", fmt.Errorf("something"), "hello \"world\"")

	LogPeerStatus(1, test.RandPeerIDFatal(t), m, "extra", "info")
}
