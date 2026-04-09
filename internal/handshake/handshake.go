package handshake

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"strings"

	"github.com/mkushnir885/software-security-rgr/conn"
)

const randomLen = 16

// Initiate runs the client side of the handshake.
// verifyCert is called to validate the peer's certificate before the key exchange proceeds.
// The peer name is derived from the certificate's Common Name.
func Initiate(c *conn.Conn, nodeName string, verifyCert func([]byte) error) (string, *conn.SecureConn, error) {
	log := c.Log
	log.Debug("handshake started", "role", "client", "to", c.Peer)

	clientRandom := make([]byte, randomLen)
	if _, err := io.ReadFull(rand.Reader, clientRandom); err != nil {
		return "", nil, err
	}
	helloMsg := append([]byte("HELLO from "+nodeName+"\n"), clientRandom...)
	if err := c.Send(helloMsg); err != nil {
		return "", nil, fmt.Errorf("send HELLO: %w", err)
	}
	log.Debug("sent HELLO", "to", c.Peer, "random", fmt.Sprintf("%x", clientRandom))

	serverHello, err := c.Receive()
	if err != nil {
		return "", nil, fmt.Errorf("receive hello: %w", err)
	}
	if len(serverHello) <= randomLen {
		return "", nil, fmt.Errorf("server hello too short: %d bytes", len(serverHello))
	}
	serverRandom, peerCertDER := serverHello[:randomLen], serverHello[randomLen:]
	log.Debug("recv HELLO", "from", c.Peer, "random", fmt.Sprintf("%x", serverRandom), "cert_bytes", len(peerCertDER))

	if err := verifyCert(peerCertDER); err != nil {
		return "", nil, fmt.Errorf("cert verification: %w", err)
	}
	cert, err := x509.ParseCertificate(peerCertDER)
	if err != nil {
		return "", nil, err
	}
	peerName := cert.Subject.CommonName
	c.Peer = peerName
	log.Debug("cert verified", "peer", peerName)

	serverPubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return "", nil, fmt.Errorf("peer cert has non-RSA key")
	}

	premaster := make([]byte, randomLen)
	if _, err := io.ReadFull(rand.Reader, premaster); err != nil {
		return "", nil, err
	}
	encPremaster, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, serverPubKey, premaster, nil)
	if err != nil {
		return "", nil, err
	}
	if err := c.Send(encPremaster); err != nil {
		return "", nil, fmt.Errorf("send premaster: %w", err)
	}
	log.Debug("sent premaster", "to", peerName)

	sessionKey := sha256.Sum256(append(append(clientRandom, serverRandom...), premaster...))
	log.Debug("session key derived", "with", peerName)

	sc, err := conn.NewSecureConn(c, sessionKey)
	if err != nil {
		return "", nil, err
	}

	if err := sc.Send([]byte("READY")); err != nil {
		return "", nil, fmt.Errorf("send ready: %w", err)
	}
	log.Debug("sent READY", "to", peerName)
	serverReady, err := sc.Receive()
	if err != nil {
		return "", nil, fmt.Errorf("receive ready: %w", err)
	}
	if string(serverReady) != "READY" {
		return "", nil, fmt.Errorf("expected READY, got %q", string(serverReady))
	}
	log.Debug("recv READY", "from", peerName)

	log.Debug("handshake complete", "role", "client", "peer", peerName)
	return peerName, sc, nil
}

// Accept runs the server side of the handshake.
// The peer name is learned from the "hello from <name>" prefix sent by the client.
func Accept(c *conn.Conn, privKey *rsa.PrivateKey, certDER []byte) (string, *conn.SecureConn, error) {
	log := c.Log
	log.Debug("handshake started", "role", "server")

	helloMsg, err := c.Receive()
	if err != nil {
		return "", nil, fmt.Errorf("receive hello: %w", err)
	}
	nl := bytes.IndexByte(helloMsg, '\n')
	if nl < 0 || len(helloMsg) != nl+1+randomLen {
		return "", nil, fmt.Errorf("malformed client hello: %d bytes", len(helloMsg))
	}
	header := string(helloMsg[:nl])
	const helloPrefix = "HELLO from "
	if !strings.HasPrefix(header, helloPrefix) {
		return "", nil, fmt.Errorf("malformed client hello header")
	}
	peerName := header[len(helloPrefix):]
	clientRandom := helloMsg[nl+1:]
	c.Peer = peerName
	log.Debug("recv HELLO", "from", peerName, "random", fmt.Sprintf("%x", clientRandom))

	serverRandom := make([]byte, randomLen)
	if _, err := io.ReadFull(rand.Reader, serverRandom); err != nil {
		return "", nil, err
	}
	if err := c.Send(append(serverRandom, certDER...)); err != nil {
		return "", nil, fmt.Errorf("send HELLO: %w", err)
	}
	log.Debug("sent HELLO", "to", peerName, "random", fmt.Sprintf("%x", serverRandom), "cert_bytes", len(certDER))

	encPremaster, err := c.Receive()
	if err != nil {
		return "", nil, fmt.Errorf("receive premaster: %w", err)
	}
	log.Debug("recv premaster", "from", peerName)

	premaster, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, encPremaster, nil)
	if err != nil {
		return "", nil, fmt.Errorf("decrypt premaster: %w", err)
	}

	sessionKey := sha256.Sum256(append(append(clientRandom, serverRandom...), premaster...))
	log.Debug("session key derived", "with", peerName)

	sc, err := conn.NewSecureConn(c, sessionKey)
	if err != nil {
		return "", nil, err
	}

	clientReady, err := sc.Receive()
	if err != nil {
		return "", nil, fmt.Errorf("receive ready: %w", err)
	}
	if string(clientReady) != "READY" {
		return "", nil, fmt.Errorf("expected READY, got %q", string(clientReady))
	}
	log.Debug("recv READY", "from", peerName)
	if err := sc.Send([]byte("READY")); err != nil {
		return "", nil, fmt.Errorf("send ready: %w", err)
	}
	log.Debug("sent READY", "to", peerName)

	log.Debug("handshake complete", "role", "server", "peer", peerName)
	return peerName, sc, nil
}
