package logger

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

func newFileLogger(path string) *slog.Logger {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		panic(fmt.Errorf("create log dir: %w", err))
	}
	f, err := os.Create(path)
	if err != nil {
		panic(fmt.Errorf("open log file %s: %w", path, err))
	}
	h := slog.NewTextHandler(f, &slog.HandlerOptions{
		Level: slog.LevelDebug,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.MessageKey {
				a.Key = "event"
			}
			return a
		},
	})
	return slog.New(h)
}

func NewNodeLogger(nodeID int) *slog.Logger {
	return newFileLogger(fmt.Sprintf("log/node%d.log", nodeID))
}

func NewCALogger() *slog.Logger {
	return newFileLogger("log/nodeCA.log")
}
