package blossomsub

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

func TestMapBlacklist(t *testing.T) {
	b := NewMapBlacklist()

	p := peer.ID("test")

	b.Add(p)
	if !b.Contains(p) {
		t.Fatal("peer not in the blacklist")
	}

}

func TestTimeCachedBlacklist(t *testing.T) {
	b, err := NewTimeCachedBlacklist(10 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	p := peer.ID("test")

	b.Add(p)
	if !b.Contains(p) {
		t.Fatal("peer not in the blacklist")
	}
}

func TestBlacklist(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getDefaultHosts(t, 2)
	psubs := getBlossomSubs(ctx, hosts)
	connect(t, hosts[0], hosts[1])

	bitmasks, err := psubs[0].Join([]byte{0x00, 0x80, 0x00, 0x00})
	if err != nil {
		t.Fatal(err)
	}

	sub, err := psubs[1].Subscribe([]byte{0x00, 0x80, 0x00, 0x00})
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(time.Millisecond * 100)
	psubs[1].BlacklistPeer(hosts[0].ID())
	time.Sleep(time.Millisecond * 100)

	bitmasks[0].Publish(ctx, bitmasks[0].bitmask, []byte("message"))

	wctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	_, err = sub[0].Next(wctx)

	if err == nil {
		t.Fatal("got message from blacklisted peer")
	}
}

func TestBlacklist2(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getDefaultHosts(t, 2)
	psubs := getBlossomSubs(ctx, hosts)
	connect(t, hosts[0], hosts[1])

	bitmasks, err := psubs[0].Join([]byte{0x00, 0x80, 0x00, 0x00})
	if err != nil {
		t.Fatal(err)
	}

	_, err = psubs[0].Subscribe([]byte{0x00, 0x80, 0x00, 0x00})
	if err != nil {
		t.Fatal(err)
	}

	sub1, err := psubs[1].Subscribe([]byte{0x00, 0x80, 0x00, 0x00})
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(time.Millisecond * 100)
	psubs[1].BlacklistPeer(hosts[0].ID())
	time.Sleep(time.Millisecond * 100)

	bitmasks[0].Publish(ctx, bitmasks[0].bitmask, []byte("message"))

	wctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	_, err = sub1[0].Next(wctx)

	if err == nil {
		t.Fatal("got message from blacklisted peer")
	}
}

func TestBlacklist3(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hosts := getDefaultHosts(t, 2)
	psubs := getBlossomSubs(ctx, hosts)

	psubs[1].BlacklistPeer(hosts[0].ID())
	time.Sleep(time.Millisecond * 100)
	connect(t, hosts[0], hosts[1])

	bitmasks, err := psubs[0].Join([]byte{0x00, 0x80, 0x00, 0x00})
	if err != nil {
		t.Fatal(err)
	}

	sub, err := psubs[1].Subscribe([]byte{0x00, 0x80, 0x00, 0x00})
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(time.Millisecond * 100)

	bitmasks[0].Publish(ctx, bitmasks[0].bitmask, []byte("message"))

	wctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	_, err = sub[0].Next(wctx)

	if err == nil {
		t.Fatal("got message from blacklisted peer")
	}
}
