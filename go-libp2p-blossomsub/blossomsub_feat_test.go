package blossomsub

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/protocol"
)

func TestDefaultBlossomSubFeatures(t *testing.T) {
	if BlossomSubDefaultFeatures(BlossomSubFeatureMesh, FloodSubID) {
		t.Fatal("floodsub should not support Mesh")
	}
	if !BlossomSubDefaultFeatures(BlossomSubFeatureMesh, BlossomSubID_v11) {
		t.Fatal("BlossomSub-v1.1 should support Mesh")
	}

	if BlossomSubDefaultFeatures(BlossomSubFeaturePX, FloodSubID) {
		t.Fatal("floodsub should not support PX")
	}
	if !BlossomSubDefaultFeatures(BlossomSubFeatureMesh, BlossomSubID_v11) {
		t.Fatal("BlossomSub-v1.1 should support PX")
	}
}

func TestBlossomSubCustomProtocols(t *testing.T) {
	customsub := protocol.ID("customsub/1.0.0")
	protos := []protocol.ID{customsub, FloodSubID}
	features := func(feat BlossomSubFeature, proto protocol.ID) bool {
		return proto == customsub
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getNetHosts(t, ctx, 3)

	gsubs := getBlossomSubs(ctx, hosts[:2], WithBlossomSubProtocols(protos, features))
	fsub := getPubsub(ctx, hosts[2])
	psubs := append(gsubs, fsub)

	connectAll(t, hosts)

	bitmask := []byte{0xff, 0x00, 0x00, 0x00}
	var subs []*Subscription
	for _, ps := range psubs {
		subch, err := ps.Subscribe(bitmask)
		if err != nil {
			t.Fatal(err)
		}

		subs = append(subs, subch)
	}

	// wait for heartbeats to build mesh
	time.Sleep(time.Second * 2)

	// check the meshes of the gsubs, the BlossomSub meshes should include each other but not the
	// floddsub peer
	gsubs[0].eval <- func() {
		gs := gsubs[0].rt.(*BlossomSubRouter)

		_, ok := gs.mesh[string(bitmask)][hosts[1].ID()]
		if !ok {
			t.Fatal("expected gs0 to have gs1 in its mesh")
		}

		_, ok = gs.mesh[string(bitmask)][hosts[2].ID()]
		if ok {
			t.Fatal("expected gs0 to not have fs in its mesh")
		}
	}

	gsubs[1].eval <- func() {
		gs := gsubs[1].rt.(*BlossomSubRouter)

		_, ok := gs.mesh[string(bitmask)][hosts[0].ID()]
		if !ok {
			t.Fatal("expected gs1 to have gs0 in its mesh")
		}

		_, ok = gs.mesh[string(bitmask)][hosts[2].ID()]
		if ok {
			t.Fatal("expected gs1 to not have fs in its mesh")
		}
	}

	// send some messages
	for i := 0; i < 10; i++ {
		msg := []byte(fmt.Sprintf("%d it's not quite a floooooood %d", i, i))

		owner := rand.Intn(len(psubs))

		psubs[owner].Publish(bitmask, msg)

		for _, sub := range subs {
			got, err := sub.Next(ctx)
			if err != nil {
				t.Fatal(sub.err)
			}
			if !bytes.Equal(msg, got.Data) {
				t.Fatal("got wrong message!")
			}
		}
	}
}
