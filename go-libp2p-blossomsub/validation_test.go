package blossomsub

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

func TestRegisterUnregisterValidator(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getDefaultHosts(t, 1)
	psubs := getBlossomSubs(ctx, hosts)

	err := psubs[0].RegisterBitmaskValidator([]byte{0xf0, 0x00}, func(context.Context, peer.ID, *Message) bool {
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	err = psubs[0].UnregisterBitmaskValidator([]byte{0xf0, 0x00})
	if err != nil {
		t.Fatal(err)
	}

	err = psubs[0].UnregisterBitmaskValidator([]byte{0xf0, 0x00})
	if err == nil {
		t.Fatal("Unregistered bogus bitmask validator")
	}
}

func TestRegisterValidatorEx(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getDefaultHosts(t, 3)
	psubs := getBlossomSubs(ctx, hosts)

	err := psubs[0].RegisterBitmaskValidator([]byte{0x01, 0x00},
		Validator(func(context.Context, peer.ID, *Message) bool {
			return true
		}))
	if err != nil {
		t.Fatal(err)
	}

	err = psubs[1].RegisterBitmaskValidator([]byte{0x01, 0x00},
		ValidatorEx(func(context.Context, peer.ID, *Message) ValidationResult {
			return ValidationAccept
		}))
	if err != nil {
		t.Fatal(err)
	}

	err = psubs[2].RegisterBitmaskValidator([]byte{0x01, 0x00}, "bogus")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestValidate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getDefaultHosts(t, 2)
	psubs := getBlossomSubs(ctx, hosts)

	connect(t, hosts[0], hosts[1])
	bitmask := []byte{0x00, 0x01}

	err := psubs[1].RegisterBitmaskValidator(bitmask, func(ctx context.Context, from peer.ID, msg *Message) bool {
		return !bytes.Contains(msg.Data, []byte("illegal"))
	})
	if err != nil {
		t.Fatal(err)
	}

	b, err := psubs[0].Join(bitmask)
	if err != nil {
		t.Fatal(err)
	}

	sub, err := psubs[1].Subscribe(bitmask)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(time.Millisecond * 50)

	msgs := []struct {
		msg       []byte
		validates bool
	}{
		{msg: []byte("this is a legal message"), validates: true},
		{msg: []byte("there also is nothing controversial about this message"), validates: true},
		{msg: []byte("openly illegal content will be censored"), validates: false},
		{msg: []byte("but subversive actors will use leetspeek to spread 1ll3g4l content"), validates: true},
	}

	for _, tc := range msgs {
		err := b[0].Publish(ctx, b[0].bitmask, tc.msg)
		if err != nil {
			t.Fatal(err)
		}

		select {
		case msg := <-sub[0].ch:
			if !tc.validates {
				t.Log(msg)
				t.Error("expected message validation to filter out the message")
			}
		case <-time.After(333 * time.Millisecond):
			if tc.validates {
				t.Error("expected message validation to accept the message")
			}
		}
	}
}

func TestValidate2(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getDefaultHosts(t, 1)
	psubs := getBlossomSubs(ctx, hosts)

	bitmask := []byte{0x00, 0x01}

	err := psubs[0].RegisterBitmaskValidator(bitmask, func(ctx context.Context, from peer.ID, msg *Message) bool {
		return !bytes.Contains(msg.Data, []byte("illegal"))
	})
	if err != nil {
		t.Fatal(err)
	}

	msgs := []struct {
		msg       []byte
		validates bool
	}{
		{msg: []byte("this is a legal message"), validates: true},
		{msg: []byte("there also is nothing controversial about this message"), validates: true},
		{msg: []byte("openly illegal content will be censored"), validates: false},
		{msg: []byte("but subversive actors will use leetspeek to spread 1ll3g4l content"), validates: true},
	}

	b, err := psubs[0].Join(bitmask)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range msgs {
		err := b[0].Publish(ctx, b[0].bitmask, tc.msg)
		if tc.validates {
			if err != nil {
				t.Fatal(err)
			}
		} else {
			if err == nil {
				t.Fatal("expected validation to fail for this message")
			}
		}
	}
}

func TestValidateOverload(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type msg struct {
		msg       []byte
		validates bool
	}

	tcs := []struct {
		msgs []msg

		maxConcurrency int
	}{
		{
			maxConcurrency: 10,
			msgs: []msg{
				{msg: []byte("this is a legal message"), validates: true},
				{msg: []byte("but subversive actors will use leetspeek to spread 1ll3g4l content"), validates: true},
				{msg: []byte("there also is nothing controversial about this message"), validates: true},
				{msg: []byte("also fine"), validates: true},
				{msg: []byte("still, all good"), validates: true},
				{msg: []byte("this is getting boring"), validates: true},
				{msg: []byte([]byte{0xf0, 0x00}), validates: true},
				{msg: []byte([]byte{0x00, 0x01}), validates: true},
				{msg: []byte("foofoo"), validates: true},
				{msg: []byte("barfoo"), validates: true},
				{msg: []byte("oh no!"), validates: false},
			},
		},
		{
			maxConcurrency: 2,
			msgs: []msg{
				{msg: []byte("this is a legal message"), validates: true},
				{msg: []byte("but subversive actors will use leetspeek to spread 1ll3g4l content"), validates: true},
				{msg: []byte("oh no!"), validates: false},
			},
		},
	}

	for tci, tc := range tcs {
		t.Run(fmt.Sprintf("%d", tci), func(t *testing.T) {
			hosts := getDefaultHosts(t, 2)
			psubs := getBlossomSubs(ctx, hosts)

			connect(t, hosts[0], hosts[1])
			bitmask := []byte{0x00, 0x01}

			block := make(chan struct{})

			err := psubs[1].RegisterBitmaskValidator(bitmask,
				func(ctx context.Context, from peer.ID, msg *Message) bool {
					<-block
					return true
				},
				WithValidatorConcurrency(tc.maxConcurrency))

			if err != nil {
				t.Fatal(err)
			}

			sub, err := psubs[1].Subscribe(bitmask)
			if err != nil {
				t.Fatal(err)
			}

			time.Sleep(time.Millisecond * 50)

			if len(tc.msgs) != tc.maxConcurrency+1 {
				t.Fatalf("expected number of messages sent to be maxConcurrency+1. Got %d, expected %d", len(tc.msgs), tc.maxConcurrency+1)
			}

			p := psubs[0]
			b, err := p.Join(bitmask)
			if err != nil {
				t.Fatal(err)
			}

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				for _, tmsg := range tc.msgs {
					select {
					case msg := <-sub[0].ch:
						if !tmsg.validates {
							t.Log(msg)
							t.Error("expected message validation to drop the message because all validator goroutines are taken")
						}
					case <-time.After(time.Second):
						if tmsg.validates {
							t.Error("expected message validation to accept the message")
						}
					}
				}
				wg.Done()
			}()

			for _, tmsg := range tc.msgs {
				err := b[0].Publish(ctx, b[0].bitmask, tmsg.msg)
				if err != nil {
					t.Fatal(err)
				}
			}

			// wait a bit before unblocking the validator goroutines
			time.Sleep(500 * time.Millisecond)
			close(block)

			wg.Wait()
		})
	}
}

func TestValidateAssortedOptions(t *testing.T) {
	// this test adds coverage for various options that are not covered in other tests
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getDefaultHosts(t, 10)
	psubs := getBlossomSubs(ctx, hosts,
		WithValidateQueueSize(10),
		WithValidateThrottle(10),
		WithValidateWorkers(10))

	sparseConnect(t, hosts)

	for _, psub := range psubs {
		err := psub.RegisterBitmaskValidator([]byte{0x00, 0x80, 0x00, 0x00},
			func(context.Context, peer.ID, *Message) bool {
				return true
			},
			WithValidatorTimeout(100*time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}

		err = psub.RegisterBitmaskValidator([]byte{0x00, 0x20, 0x00, 0x00},
			func(context.Context, peer.ID, *Message) bool {
				return true
			},
			WithValidatorInline(true))
		if err != nil {
			t.Fatal(err)
		}
	}

	var subs1, subs2 []*Subscription
	var bitmasks1, bitmasks2 []*Bitmask
	for _, ps := range psubs {
		b, err := ps.Join([]byte{0x00, 0x80, 0x00, 0x00})
		if err != nil {
			t.Fatal(err)
		}
		bitmasks1 = append(bitmasks1, b...)

		b, err = ps.Join([]byte{0x00, 0x04, 0x00, 0x00})
		if err != nil {
			t.Fatal(err)
		}
		bitmasks2 = append(bitmasks2, b...)
		sub, err := ps.Subscribe([]byte{0x00, 0x80, 0x00, 0x00})
		if err != nil {
			t.Fatal(err)
		}
		subs1 = append(subs1, sub...)

		sub, err = ps.Subscribe([]byte{0x00, 0x04, 0x00, 0x00})
		if err != nil {
			t.Fatal(err)
		}
		subs2 = append(subs2, sub...)
	}

	time.Sleep(time.Second)

	for i := 0; i < 10; i++ {
		msg := []byte(fmt.Sprintf("message1 %d", i))

		bitmasks1[i].Publish(ctx, bitmasks1[i].bitmask, msg)
		for _, sub := range subs1 {
			assertReceive(t, sub, msg)
		}
		msg = []byte(fmt.Sprintf("message2 %d", i))

		bitmasks2[i].Publish(ctx, bitmasks2[i].bitmask, msg)
		for _, sub := range subs2 {
			assertReceive(t, sub, msg)
		}
	}
}
