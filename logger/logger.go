package logger

import (
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"

	"github.com/lmittmann/tint"
)

func Init() {
	slog.SetDefault(slog.New(
		tint.NewHandler(os.Stdout, &tint.Options{
			Level:      slog.LevelDebug,
			TimeFormat: "15:04:05.000",
		}),
	))
}

func PrintlnPubKeyPem(pubKeyBytes []byte) {
	fmt.Print(string(
		pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyBytes,
		}),
	))
}
