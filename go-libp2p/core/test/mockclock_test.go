package test

import (
	"testing"
	"time"
)

func TestMockClock(t *testing.T) {
	cl := NewMockClock()
	t1 := cl.InstantTimer(cl.Now().Add(2 * time.Second))
	t2 := cl.InstantTimer(cl.Now().Add(time.Second))

	// Advance the clock by 500ms
	cl.AdvanceBy(time.Millisecond * 500)

	// No event
	select {
	case <-t1.Ch():
		t.Fatal("t1 fired early")
	case <-t2.Ch():
		t.Fatal("t2 fired early")
	default:
	}

	// Advance the clock by 500ms
	cl.AdvanceBy(time.Millisecond * 500)

	// t2 fires
	select {
	case <-t1.Ch():
		t.Fatal("t1 fired early")
	case <-t2.Ch():
	}

	// Advance the clock by 2s
	cl.AdvanceBy(time.Second * 2)

	// t1 fires
	select {
	case <-t1.Ch():
	case <-t2.Ch():
		t.Fatal("t2 fired again")
	}
}
