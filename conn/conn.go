package conn

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"
)

const (
	maxMsgLen  = 10 * 1024 * 1024
	chunkSize  = 256
	chunkDelay = 100 * time.Millisecond
)

// Conn wraps a net.Conn with length-prefixed framing and chunked throttling
// that simulates a slow radio link.
type Conn struct {
	raw  net.Conn
	Peer string // peer name, e.g. "node1", "nodeCA"; "?" = not yet known
	Log  *slog.Logger
}

func New(c net.Conn, peer string, log *slog.Logger) *Conn {
	if peer == "" {
		peer = "?"
	}
	return &Conn{raw: c, Peer: peer, Log: log}
}

func (c *Conn) Close() error { return c.raw.Close() }

// Send writes a 4-byte big-endian length header followed by data in chunkSize-byte
// chunks with chunkDelay between them.
func (c *Conn) Send(data []byte) error {
	if uint32(len(data)) > maxMsgLen {
		return fmt.Errorf("message too large: %d bytes", len(data))
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(data)))
	frame := append(header, data...)

	total := len(frame)
	b := frame
	for chunk := 1; len(b) > 0; chunk++ {
		end := min(chunkSize, len(b))
		n, err := c.raw.Write(b[:end])
		if err != nil {
			return err
		}
		c.Log.Debug("send chunk", "to", c.Peer, "n", chunk, "bytes", n, "remaining", len(b)-n, "total", total)
		b = b[n:]
		if len(b) > 0 {
			time.Sleep(chunkDelay)
		}
	}
	return nil
}

// Receive reads a 4-byte big-endian length header and then the full body.
func (c *Conn) Receive() ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(c.raw, header); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	length := binary.BigEndian.Uint32(header)
	if length > maxMsgLen {
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(c.raw, body); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	c.Log.Debug("recv packet", "from", c.Peer, "bytes", length+4)
	return body, nil
}
