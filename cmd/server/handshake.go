package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"log/slog"

	"github.com/mkushnir885/software-security-rgr/logger"
	"github.com/mkushnir885/software-security-rgr/msg"
)

const randomLen = 16

var privKey *rsa.PrivateKey
var pubKeyBytes []byte

func init() {
	var err error
	privKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Errorf("generate keypair: %w", err))
	}
	pubKeyBytes, err = x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		panic(fmt.Errorf("marshal public key: %w", err))
	}
	fmt.Println("generated private/public keypair:")
	logger.PrintlnPubKeyPem(pubKeyBytes)
}

func doHandshake(conn *msg.Conn) (*msg.SecureConn, error) {
	fmt.Println()
	slog.Info("handshake started")

	clientRandom, err := receiveHello(conn)
	if err != nil {
		return nil, fmt.Errorf("receive hello: %w", err)
	}

	random, err := sendHello(conn)
	if err != nil {
		return nil, fmt.Errorf("send hello: %w", err)
	}

	secret, err := receivePremaster(conn)
	if err != nil {
		return nil, fmt.Errorf("receive premaster: %w", err)
	}

	sessionKey := sha256.Sum256(append(append(clientRandom, random...), secret...))
	slog.Debug("created session key", "key", fmt.Sprintf("%x", sessionKey))

	secureConn, err := msg.NewSecureConn(conn, sessionKey)
	if err != nil {
		return nil, fmt.Errorf("make conn secure: %w", err)
	}

	if message, err := secureConn.Receive(); err != nil || string(message) != "ready" {
		return nil, fmt.Errorf("receive ready: %w", err)
	}
	slog.Debug("received 'ready' message")

	if err = secureConn.Send([]byte("ready")); err != nil {
		return nil, fmt.Errorf("send ready: %w", err)
	}
	slog.Debug("sent 'ready' message")

	slog.Info("handshake finished")
	fmt.Println()
	return secureConn, nil
}

func receiveHello(conn *msg.Conn) ([]byte, error) {
	clientRandom, err := conn.Receive()
	if err != nil {
		return nil, err
	}
	slog.Debug("received 'hello' message", "random", fmt.Sprintf("%x", clientRandom))
	return clientRandom, nil
}

func sendHello(conn *msg.Conn) ([]byte, error) {
	random := make([]byte, randomLen)
	if _, err := rand.Read(random); err != nil {
		return nil, fmt.Errorf("generate random bytes: %w", err)
	}

	if err := conn.Send(append(random, pubKeyBytes...)); err != nil {
		return nil, err
	}
	slog.Debug("sent 'hello' message", "random", fmt.Sprintf("%x", random))
	return random, nil
}

func receivePremaster(conn *msg.Conn) ([]byte, error) {
	premaster, err := conn.Receive()
	if err != nil {
		return nil, err
	}
	slog.Debug("received premaster", "encryptedSecret", fmt.Sprintf("%x", premaster))

	secret, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, premaster, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt premaster: %w", err)
	}

	slog.Debug("decrypted premaster", "secret", fmt.Sprintf("%x", secret))
	return secret, nil
}
