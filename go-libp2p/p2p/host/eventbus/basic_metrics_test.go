//go:build nocover

package eventbus

import (
	"math/rand"
	"reflect"
	"testing"

	"github.com/libp2p/go-libp2p/core/event"
)

func BenchmarkEventEmitted(b *testing.B) {
	b.ReportAllocs()
	types := []reflect.Type{
		reflect.TypeOf(new(event.EvtLocalAddressesUpdated)),
		reflect.TypeOf(new(event.EvtNATDeviceTypeChanged)),
		reflect.TypeOf(new(event.EvtLocalProtocolsUpdated)),
	}
	mt := NewMetricsTracer()
	for i := 0; i < b.N; i++ {
		mt.EventEmitted(types[i%len(types)])
	}
}

func BenchmarkSubscriberQueueLength(b *testing.B) {
	b.ReportAllocs()
	names := []string{"s1", "s2", "s3", "s4"}
	mt := NewMetricsTracer()
	for i := 0; i < b.N; i++ {
		mt.SubscriberQueueLength(names[i%len(names)], i)
	}
}

var eventTypes = []reflect.Type{
	reflect.TypeOf(new(event.EvtLocalAddressesUpdated)),
	reflect.TypeOf(new(event.EvtNATDeviceTypeChanged)),
	reflect.TypeOf(new(event.EvtLocalProtocolsUpdated)),
	reflect.TypeOf(new(event.EvtPeerIdentificationCompleted)),
}

var names = []string{
	"one",
	"two",
	"three",
	"four",
	"five",
}

func TestMetricsNoAllocNoCover(t *testing.T) {
	mt := NewMetricsTracer()
	tests := map[string]func(){
		"EventEmitted":          func() { mt.EventEmitted(eventTypes[rand.Intn(len(eventTypes))]) },
		"AddSubscriber":         func() { mt.AddSubscriber(eventTypes[rand.Intn(len(eventTypes))]) },
		"RemoveSubscriber":      func() { mt.RemoveSubscriber(eventTypes[rand.Intn(len(eventTypes))]) },
		"SubscriberQueueLength": func() { mt.SubscriberQueueLength(names[rand.Intn(len(names))], rand.Intn(100)) },
		"SubscriberQueueFull":   func() { mt.SubscriberQueueFull(names[rand.Intn(len(names))], rand.Intn(2) == 1) },
		"SubscriberEventQueued": func() { mt.SubscriberEventQueued(names[rand.Intn(len(names))]) },
	}
	for method, f := range tests {
		allocs := testing.AllocsPerRun(1000, f)
		if allocs > 0 {
			t.Fatalf("Alloc Test: %s, got: %0.2f, expected: 0 allocs", method, allocs)
		}
	}
}
