package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/mkushnir885/software-security-rgr/msg"
)

func handleConn(conn *msg.SecureConn) error {
	if len(os.Args) < 2 {
		return errors.New("no file provided in CLI")
	}
	filePath := os.Args[1]

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}
	fileName := filepath.Base(filePath)

	if err := conn.Send([]byte(fileName)); err != nil {
		return fmt.Errorf("send file name: %w", err)
	}
	if err := conn.Send(data); err != nil {
		return fmt.Errorf("send file content: %w", err)
	}
	slog.Info("sent file", "name", fileName, "size (bytes)", len(data))

	response, err := conn.Receive()
	if err != nil {
		return fmt.Errorf("receive response: %w", err)
	}
	slog.Info("received response", "message", string(response))

	return nil
}
