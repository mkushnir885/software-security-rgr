package main

import (
	"fmt"
	"log/slog"

	"github.com/mkushnir885/software-security-rgr/msg"
)

func doHandshake(conn *msg.Conn) error {
	fmt.Println()
	slog.Info("handshake started")

	_, err := receiveHello(conn)
	if err != nil {
		return fmt.Errorf("receive hello: %w", err)
	}

	slog.Info("handshake finished")
	fmt.Println()
	return nil
}

func receiveHello(conn *msg.Conn) ([]byte, error) {
	clientRandom, err := conn.Receive()
	if err != nil {
		return nil, err
	}
	slog.Debug("received 'hello' message", "random", fmt.Sprintf("%x", clientRandom))
	return clientRandom, nil
}
