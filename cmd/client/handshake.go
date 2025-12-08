package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"

	"github.com/mkushnir885/software-security-rgr/logger"
	"github.com/mkushnir885/software-security-rgr/msg"
)

const randomLen = 16

func doHandshake(conn *msg.Conn) error {
	fmt.Println()
	slog.Info("handshake started")

	random, err := sendHello(conn)
	if err != nil {
		return fmt.Errorf("send hello: %w", err)
	}

	serverRandom, pubKey, err := receiveHello(conn)
	if err != nil {
		return fmt.Errorf("receive hello: %w", err)
	}

	secret, err := sendPremaster(conn, pubKey)
	if err != nil {
		return fmt.Errorf("send premaster: %w", err)
	}

	sessionKey := sha256.Sum256(append(append(random, serverRandom...), secret...))
	slog.Debug("created session key", "key", fmt.Sprintf("%x", sessionKey))

	secureConn, err := msg.NewSecureConn(conn, sessionKey)
	if err != nil {
		return fmt.Errorf("make conn secure: %w", err)
	}

	if err = secureConn.Send([]byte("ready")); err != nil {
		return fmt.Errorf("send ready: %w", err)
	}
	slog.Debug("sent 'ready' message")

	if message, err := secureConn.Receive(); err != nil || string(message) != "ready" {
		return fmt.Errorf("receive ready: %w", err)
	}
	slog.Debug("received 'ready' message")

	slog.Info("handshake finished")
	fmt.Println()
	return nil
}

func sendHello(conn *msg.Conn) ([]byte, error) {
	random := make([]byte, randomLen)
	if _, err := rand.Read(random); err != nil {
		return nil, fmt.Errorf("generate random bytes: %w", err)
	}

	if err := conn.Send(random); err != nil {
		return nil, err
	}
	slog.Debug("sent 'hello' message", "random", fmt.Sprintf("%x", random))
	return random, nil
}

func receiveHello(conn *msg.Conn) ([]byte, *rsa.PublicKey, error) {
	serverHello, err := conn.Receive()
	if err != nil {
		return nil, nil, err
	}
	if len(serverHello) <= randomLen {
		return nil, nil, fmt.Errorf("hello too short: %d bytes", len(serverHello))
	}
	serverRandom, pubKeyBytes := serverHello[:randomLen], serverHello[randomLen:]

	pubKeyIface, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse public key: %w", err)
	}
	pubKey, ok := pubKeyIface.(*rsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("not RSA public key")
	}

	slog.Debug("received 'hello' message", "random", fmt.Sprintf("%x", serverRandom), "publicKey", "\\")
	logger.PrintlnPubKeyPem(pubKeyBytes)
	return serverRandom, pubKey, nil
}

func sendPremaster(conn *msg.Conn, pubKey *rsa.PublicKey) ([]byte, error) {
	secret := make([]byte, randomLen)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate random bytes: %w", err)
	}
	slog.Debug("unencrypted premaster", "secret", fmt.Sprintf("%x", secret))

	premaster, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, secret, nil)
	if err != nil {
		return nil, fmt.Errorf("encrypt premaster: %w", err)
	}

	if err := conn.Send(premaster); err != nil {
		return nil, err
	}
	slog.Debug("sent premaster", "encryptedSecret", fmt.Sprintf("%x", premaster))
	return secret, nil
}
