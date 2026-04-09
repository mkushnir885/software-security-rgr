package conn

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// SecureConn encrypts/decrypts messages over a *Conn using AES-256-GCM.
type SecureConn struct {
	*Conn
	gcm       cipher.AEAD
	nonceSize int
}

func NewSecureConn(c *Conn, key [32]byte) (*SecureConn, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	return &SecureConn{Conn: c, gcm: gcm, nonceSize: gcm.NonceSize()}, nil
}

func (c *SecureConn) Send(data []byte) error {
	nonce := make([]byte, c.nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	buf := make([]byte, 0, c.nonceSize+len(data)+c.gcm.Overhead())
	ciphertext := c.gcm.Seal(append(buf, nonce...), nonce, data, nil)
	c.Log.Debug("send encrypted", "to", c.Peer, "plaintext", len(data), "ciphertext", len(ciphertext))
	return c.Conn.Send(ciphertext)
}

func (c *SecureConn) Receive() ([]byte, error) {
	ciphertext, err := c.Conn.Receive()
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < c.nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, enc := ciphertext[:c.nonceSize], ciphertext[c.nonceSize:]
	data, err := c.gcm.Open(nil, nonce, enc, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	c.Log.Debug("recv encrypted", "from", c.Peer, "plaintext", len(data))
	return data, nil
}
