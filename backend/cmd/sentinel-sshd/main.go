package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"sentinel/backend/internal/bootstrap"
	"sentinel/backend/internal/config"
	"sentinel/backend/internal/logging"
	"sentinel/backend/internal/sshd"
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

	server := sshd.NewServer(cfg.SSH, logger, core.Auth, core.Policy, core.Session, core.Audit, core.Store)

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()

	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, os.Interrupt, syscall.SIGTERM)

	select {
	case stop := <-stopCh:
		logger.Info("ssh shutdown signal", "signal", stop.String())
	case err := <-errCh:
		if err != nil {
			logger.Error("ssh server failed", "error", err.Error())
			os.Exit(1)
		}
	}

	if err := server.Shutdown(); err != nil {
		logger.Error("ssh graceful shutdown failed", "error", err.Error())
	}
}
