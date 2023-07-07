package blossomsub

import (
	"context"
	"sync"
)

// Subscription handles the details of a particular Bitmask subscription.
// There may be many subscriptions for a given Bitmask.
type Subscription struct {
	bitmask  []byte
	ch       chan *Message
	cancelCh chan<- *Subscription
	ctx      context.Context
	err      error
	once     sync.Once
}

// Bitmask returns the bitmask []byte associated with the Subscription
func (sub *Subscription) Bitmask() []byte {
	return sub.bitmask
}

// Next returns the next message in our subscription
func (sub *Subscription) Next(ctx context.Context) (*Message, error) {
	select {
	case msg, ok := <-sub.ch:
		if !ok {
			return msg, sub.err
		}

		return msg, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Cancel closes the subscription. If this is the last active subscription then pubsub will send an unsubscribe
// announcement to the network.
func (sub *Subscription) Cancel() {
	select {
	case sub.cancelCh <- sub:
	case <-sub.ctx.Done():
	}
}

func (sub *Subscription) close() {
	sub.once.Do(func() {
		close(sub.ch)
	})
}
