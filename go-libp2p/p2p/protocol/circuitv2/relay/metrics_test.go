//go:build nocover

package relay

import (
	"math/rand"
	"testing"
	"time"

	pbv2 "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/pb"
)

func TestNoCoverNoAlloc(t *testing.T) {
	statuses := []pbv2.Status{
		pbv2.Status_OK,
		pbv2.Status_NO_RESERVATION,
		pbv2.Status_RESOURCE_LIMIT_EXCEEDED,
		pbv2.Status_PERMISSION_DENIED,
	}
	mt := NewMetricsTracer()
	tests := map[string]func(){
		"RelayStatus":               func() { mt.RelayStatus(rand.Intn(2) == 1) },
		"ConnectionOpened":          func() { mt.ConnectionOpened() },
		"ConnectionClosed":          func() { mt.ConnectionClosed(time.Duration(rand.Intn(10)) * time.Second) },
		"ConnectionRequestHandled":  func() { mt.ConnectionRequestHandled(statuses[rand.Intn(len(statuses))]) },
		"ReservationAllowed":        func() { mt.ReservationAllowed(rand.Intn(2) == 1) },
		"ReservationClosed":         func() { mt.ReservationClosed(rand.Intn(10)) },
		"ReservationRequestHandled": func() { mt.ReservationRequestHandled(statuses[rand.Intn(len(statuses))]) },
		"BytesTransferred":          func() { mt.BytesTransferred(rand.Intn(1000)) },
	}
	for method, f := range tests {
		allocs := testing.AllocsPerRun(1000, f)
		if allocs > 0 {
			t.Fatalf("Alloc Test: %s, got: %0.2f, expected: 0 allocs", method, allocs)
		}
	}
}
