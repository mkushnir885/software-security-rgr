package msg

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const maxMsgLength = 10 * 1024 * 1024 // 10 MiB limit

type Conn struct {
	net.Conn
}

func NewConn(conn net.Conn) *Conn {
	return &Conn{Conn: conn}
}

func (c *Conn) Send(data []byte) error {
	length := uint32(len(data))
	if length > maxMsgLength {
		return fmt.Errorf("message too large: %d bytes", length)
	}

	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, length)

	if _, err := c.Write(header); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	if _, err := c.Write(data); err != nil {
		return fmt.Errorf("write body: %w", err)
	}

	return nil
}

func (c *Conn) Receive() ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(c, header); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	length := binary.BigEndian.Uint32(header)
	if length > maxMsgLength {
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(c, body); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	return body, nil
}
