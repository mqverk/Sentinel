package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"sentinel/backend/internal/app"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to Sentinel config file")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	a, err := app.New(*configPath)
	if err != nil {
		slog.Error("failed to initialize app", slog.Any("error", err))
		os.Exit(1)
	}

	if err := a.Start(ctx); err != nil {
		slog.Error("application stopped with error", slog.Any("error", err))
		os.Exit(1)
	}
}
