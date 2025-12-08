package main

import (
	"fmt"
	"log/slog"

	"github.com/mkushnir885/software-security-rgr/msg"
)

func handleConn(conn *msg.SecureConn) error {
	fileNameBytes, err := conn.Receive()
	if err != nil {
		return fmt.Errorf("receive file name: %w", err)
	}
	data, err := conn.Receive()
	if err != nil {
		return fmt.Errorf("receive file content: %w", err)
	}
	fileName := string(fileNameBytes)
	slog.Info("received file", "name", fileName, "content", "\\")
	fmt.Print(string(data))

	response := fmt.Sprintf("received file %s (%d bytes)", fileName, len(data))
	if err := conn.Send([]byte(response)); err != nil {
		return fmt.Errorf("send response: %w", err)
	}

	return nil
}
