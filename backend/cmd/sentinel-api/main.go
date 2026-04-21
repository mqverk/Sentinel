package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sentinel/backend/internal/api"
	"sentinel/backend/internal/bootstrap"
	"sentinel/backend/internal/config"
	"sentinel/backend/internal/logging"
)

func main() {
	cfg, err := config.Load("./configs/config.yaml")
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	logger := logging.NewJSONLogger("info")
	core, err := bootstrap.NewCore(cfg, logger)
	if err != nil {
		log.Fatalf("bootstrap core: %v", err)
	}
	defer core.Close()

	server, err := api.NewServer(cfg, logger, core.Store, core.Auth, core.RBAC, core.Policy, core.Audit, core.Session)
	if err != nil {
		log.Fatalf("initialize api server: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()

	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, os.Interrupt, syscall.SIGTERM)

	select {
	case stop := <-stopCh:
		logger.Info("api shutdown signal", "signal", stop.String())
	case err := <-errCh:
		if err != nil {
			logger.Error("api server failed", "error", err.Error())
			os.Exit(1)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		logger.Error("api graceful shutdown failed", "error", err.Error())
	}
}
