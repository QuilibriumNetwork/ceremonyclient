//go:build nocover

package identify

import (
	"math/rand"
	"testing"

	"github.com/libp2p/go-libp2p/core/event"
)

func TestMetricsNoAllocNoCover(t *testing.T) {
	events := []any{
		event.EvtLocalAddressesUpdated{},
		event.EvtLocalProtocolsUpdated{},
		event.EvtNATDeviceTypeChanged{},
	}

	pushSupport := []identifyPushSupport{
		identifyPushSupportUnknown,
		identifyPushSupported,
		identifyPushUnsupported,
	}

	tr := NewMetricsTracer()
	tests := map[string]func(){
		"TriggeredPushes":  func() { tr.TriggeredPushes(events[rand.Intn(len(events))]) },
		"ConnPushSupport":  func() { tr.ConnPushSupport(pushSupport[rand.Intn(len(pushSupport))]) },
		"IdentifyReceived": func() { tr.IdentifyReceived(rand.Intn(2) == 0, rand.Intn(20), rand.Intn(20)) },
		"IdentifySent":     func() { tr.IdentifySent(rand.Intn(2) == 0, rand.Intn(20), rand.Intn(20)) },
	}
	for method, f := range tests {
		allocs := testing.AllocsPerRun(1000, f)
		if allocs > 0 {
			t.Fatalf("Alloc Test: %s, got: %0.2f, expected: 0 allocs", method, allocs)
		}
	}
}
