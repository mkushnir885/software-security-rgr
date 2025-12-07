package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/mkushnir885/software-security-rgr/logger"
)

func main() {
	logger.Init()

	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		slog.Error("failed to start server", "error", err)
		os.Exit(1)
	}
	slog.Info("server running")

	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				slog.Error("failed to accept conn", "error", err)
				continue
			}

			wg.Go(func() {
				defer func() {
					conn.Close()
					slog.Info("conn closed")
				}()

				slog.Info("new client connected")
			})
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down...")
	ln.Close()
	wg.Wait()
	slog.Info("server stopped")
}
