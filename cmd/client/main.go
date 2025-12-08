package main

import (
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/mkushnir885/software-security-rgr/logger"
	"github.com/mkushnir885/software-security-rgr/msg"
)

func main() {
	logger.Init()

	conn, err := net.DialTimeout("tcp", "localhost:8080", 5*time.Second)
	if err != nil {
		slog.Error("failed to connect to server", "error", err)
		os.Exit(1)
	}
	defer func() {
		conn.Close()
		slog.Info("conn closed")
	}()

	slog.Info("connected to server")

	secureConn, err := doHandshake(msg.NewConn(conn))
	if err != nil {
		slog.Error("failed to do handshake", "error", err)
		return
	}

	if err := handleConn(secureConn); err != nil {
		slog.Error("failed to handle connection", "error", err)
	}
}
