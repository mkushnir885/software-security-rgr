package main

import (
	"crypto/rand"
	"fmt"
	"log/slog"

	"github.com/mkushnir885/software-security-rgr/msg"
)

const randomLen = 16

func doHandshake(conn *msg.Conn) error {
	fmt.Println()
	slog.Info("handshake started")

	_, err := sendHello(conn)
	if err != nil {
		return fmt.Errorf("send hello: %w", err)
	}

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
