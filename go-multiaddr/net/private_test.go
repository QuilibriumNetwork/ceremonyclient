package manet

import (
	"fmt"
	"testing"

	ma "github.com/multiformats/go-multiaddr"
)

func TestIsPublicAddr(t *testing.T) {
	addr1, _ := ma.StringCast("/ip4/192.168.1.1/tcp/80")
	addr2, _ := ma.StringCast("/ip4/1.1.1.1/tcp/80")
	addr3, _ := ma.StringCast("/tcp/80/ip4/1.1.1.1")
	addr4, _ := ma.StringCast("/dns/node.libp2p.io/udp/1/quic-v1")
	addr5, _ := ma.StringCast("/dnsaddr/node.libp2p.io/udp/1/quic-v1")
	addr6, _ := ma.StringCast("/dns/node.libp2p.local/udp/1/quic-v1")
	addr7, _ := ma.StringCast("/dns/localhost/udp/1/quic-v1")
	addr8, _ := ma.StringCast("/dns/a.localhost/tcp/1")
	addr9, _ := ma.StringCast("/ip6/2400::1/tcp/10")
	addr10, _ := ma.StringCast("/ip6/2001:db8::42/tcp/10")
	addr11, _ := ma.StringCast("/ip6/64:ff9b::1.1.1.1/tcp/10")
	tests := []struct {
		addr      ma.Multiaddr
		isPublic  bool
		isPrivate bool
	}{
		{
			addr:      addr1,
			isPublic:  false,
			isPrivate: true,
		},
		{
			addr:      addr2,
			isPublic:  true,
			isPrivate: false,
		},
		{
			addr:      addr3,
			isPublic:  false,
			isPrivate: false,
		},
		{
			addr:      addr4,
			isPublic:  true,
			isPrivate: false,
		},
		{
			addr:      addr5,
			isPublic:  true,
			isPrivate: false,
		},
		{
			addr:      addr6,
			isPublic:  false,
			isPrivate: false, // You can configure .local domains in local networks to return public addrs
		},
		{
			addr:      addr7,
			isPublic:  false,
			isPrivate: true,
		},
		{
			addr:      addr8,
			isPublic:  false,
			isPrivate: true,
		},
		{
			addr:      addr9,
			isPublic:  true,
			isPrivate: false,
		},
		{
			addr:      addr10,
			isPublic:  false,
			isPrivate: false,
		},
		{
			addr:      addr11,
			isPublic:  true,
			isPrivate: false,
		},
	}
	for i, tt := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			isPublic, _ := IsPublicAddr(tt.addr)
			isPrivate, _ := IsPrivateAddr(tt.addr)
			if isPublic != tt.isPublic {
				t.Errorf("IsPublicAddr check failed for %s: expected %t, got %t", tt.addr, tt.isPublic, isPublic)
			}
			if isPrivate != tt.isPrivate {
				t.Errorf("IsPrivateAddr check failed for %s: expected %t, got %t", tt.addr, tt.isPrivate, isPrivate)
			}
		})
	}
}
