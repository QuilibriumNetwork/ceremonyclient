package websocket

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	ma "github.com/multiformats/go-multiaddr"
)

func tStringCast(str string) ma.Multiaddr {
	m, _ := ma.StringCast(str)
	return m
}

func TestMultiaddrParsing(t *testing.T) {
	addr, err := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/5555/ws")
	if err != nil {
		t.Fatal(err)
	}

	wsaddr, err := parseMultiaddr(addr)
	if err != nil {
		t.Fatal(err)
	}
	if wsaddr.String() != "ws://127.0.0.1:5555" {
		t.Fatalf("expected ws://127.0.0.1:5555, got %s", wsaddr)
	}
}

type httpAddr struct {
	*url.URL
}

func (addr *httpAddr) Network() string {
	return "http"
}

func TestParseWebsocketNetAddr(t *testing.T) {
	notWs := &httpAddr{&url.URL{Host: "http://127.0.0.1:1234"}}
	_, err := ParseWebsocketNetAddr(notWs)
	if err.Error() != "not a websocket address" {
		t.Fatalf("expect \"not a websocket address\", got \"%s\"", err)
	}

	wsAddr := NewAddrWithScheme("127.0.0.1:5555", false)
	parsed, err := ParseWebsocketNetAddr(wsAddr)
	if err != nil {
		t.Fatal(err)
	}

	if parsed.String() != "/ip4/127.0.0.1/tcp/5555/ws" {
		t.Fatalf("expected \"/ip4/127.0.0.1/tcp/5555/ws\", got \"%s\"", parsed.String())
	}
}

func TestConvertWebsocketMultiaddrToNetAddr(t *testing.T) {
	addr, err := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/5555/ws")
	if err != nil {
		t.Fatal(err)
	}

	wsaddr, err := ConvertWebsocketMultiaddrToNetAddr(addr)
	if err != nil {
		t.Fatal(err)
	}
	if wsaddr.String() != "ws://127.0.0.1:5555" {
		t.Fatalf("expected ws://127.0.0.1:5555, got %s", wsaddr)
	}
	if wsaddr.Network() != "websocket" {
		t.Fatalf("expected network: \"websocket\", got \"%s\"", wsaddr.Network())
	}
}

func TestListeningOnDNSAddr(t *testing.T) {
	ln, err := newListener(tStringCast("/dns/localhost/tcp/0/ws"), nil)
	require.NoError(t, err)
	addr := ln.Multiaddr()
	first, rest, _ := ma.SplitFirst(addr)
	require.Equal(t, ma.P_DNS, first.Protocol().Code)
	require.Equal(t, "localhost", first.Value())
	next, _, _ := ma.SplitFirst(rest)
	require.Equal(t, ma.P_TCP, next.Protocol().Code)
	require.NotEqual(t, 0, next.Value())
}
