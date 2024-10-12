package websocket

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/transport"

	ws "github.com/gorilla/websocket"
)

// GracefulCloseTimeout is the time to wait trying to gracefully close a
// connection before simply cutting it.
var GracefulCloseTimeout = 100 * time.Millisecond

// Conn implements net.Conn interface for gorilla/websocket.
type Conn struct {
	*ws.Conn
	secure             bool
	DefaultMessageType int
	reader             io.Reader
	closeOnce          sync.Once

	readLock, writeLock sync.Mutex
}

var _ net.Conn = (*Conn)(nil)

// NewConn creates a Conn given a regular gorilla/websocket Conn.
func NewConn(raw *ws.Conn, secure bool) *Conn {
	return &Conn{
		Conn:               raw,
		secure:             secure,
		DefaultMessageType: ws.BinaryMessage,
	}
}

func (c *Conn) Read(b []byte) (int, error) {
	c.readLock.Lock()

	if c.reader == nil {
		if err := c.prepNextReader(); err != nil {
			c.readLock.Unlock()
			return 0, err
		}
	}

	for {
		n, err := c.reader.Read(b)
		switch err {
		case io.EOF:
			c.reader = nil

			if n > 0 {
				c.readLock.Unlock()
				return n, nil
			}

			if err := c.prepNextReader(); err != nil {
				c.readLock.Unlock()
				return 0, err
			}

			// explicitly looping
		default:
			c.readLock.Unlock()
			return n, err
		}
	}
}

func (c *Conn) prepNextReader() error {
	t, r, err := c.Conn.NextReader()
	if err != nil {
		if wserr, ok := err.(*ws.CloseError); ok {
			if wserr.Code == 1000 || wserr.Code == 1005 {
				return io.EOF
			}
		}
		return err
	}

	if t == ws.CloseMessage {
		return io.EOF
	}

	c.reader = r
	return nil
}

func (c *Conn) Write(b []byte) (n int, err error) {
	c.writeLock.Lock()

	if err := c.Conn.WriteMessage(c.DefaultMessageType, b); err != nil {
		c.writeLock.Unlock()
		return 0, err
	}

	c.writeLock.Unlock()
	return len(b), nil
}

// Close closes the connection. Only the first call to Close will receive the
// close error, subsequent and concurrent calls will return nil.
// This method is thread-safe.
func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err1 := c.Conn.WriteControl(
			ws.CloseMessage,
			ws.FormatCloseMessage(ws.CloseNormalClosure, "closed"),
			time.Now().Add(GracefulCloseTimeout),
		)
		err2 := c.Conn.Close()
		switch {
		case err1 != nil:
			err = err1
		case err2 != nil:
			err = err2
		}
	})
	return err
}

func (c *Conn) LocalAddr() net.Addr {
	return NewAddrWithScheme(c.Conn.LocalAddr().String(), c.secure)
}

func (c *Conn) RemoteAddr() net.Addr {
	return NewAddrWithScheme(c.Conn.RemoteAddr().String(), c.secure)
}

func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}

	return c.SetWriteDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	// Don't lock when setting the read deadline. That would prevent us from
	// interrupting an in-progress read.
	return c.Conn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	// Unlike the read deadline, we need to lock when setting the write
	// deadline.

	c.writeLock.Lock()
	err := c.Conn.SetWriteDeadline(t)
	c.writeLock.Unlock()
	return err
}

type capableConn struct {
	transport.CapableConn
}

func (c *capableConn) ConnState() network.ConnectionState {
	cs := c.CapableConn.ConnState()
	cs.Transport = "websocket"
	return cs
}
