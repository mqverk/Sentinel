package bootstrap

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"sentinel/backend/internal/audit"
	"sentinel/backend/internal/auth"
	"sentinel/backend/internal/config"
	"sentinel/backend/internal/plugin"
	"sentinel/backend/internal/policy"
	"sentinel/backend/internal/rbac"
	"sentinel/backend/internal/session"
	"sentinel/backend/internal/storage"
)

type Core struct {
	Store   storage.Store
	Auth    *auth.Service
	RBAC    *rbac.Service
	Policy  *policy.Engine
	Audit   *audit.Service
	Session *session.Service
	Plugins *plugin.Manager
}

func NewCore(cfg config.Config, logger *slog.Logger) (*Core, error) {
	store, err := storage.Open(cfg.Database)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	if err := store.RunMigrations(context.Background()); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("run migrations: %w", err)
	}
	if err := store.Seed(context.Background()); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("seed store: %w", err)
	}

	recorder := session.NewRecorder(cfg.Session.RecordingDir)
	if err := recorder.EnsureDir(); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("prepare recorder directory: %w", err)
	}

	plugins := plugin.NewManager(logger)
	for _, name := range cfg.Plugins.Enabled {
		switch strings.TrimSpace(name) {
		case "stdout-audit":
			plugins.Register(&plugin.StdoutAuditPlugin{})
		case "webhook-audit":
			plugins.Register(plugin.NewWebhookAuditPlugin(cfg.Plugins.WebhookURL))
		}
	}

	tokenManager := auth.NewTokenManager(cfg.Auth.JWTSecret, cfg.Auth.TokenTTL)
	authService := auth.NewService(store, tokenManager, cfg.Auth.PasswordMinLength)
	rbacService := rbac.NewService(store)
	policyEngine := policy.NewEngine(store)
	auditService := audit.NewService(store, logger, plugins)
	sessionService := session.NewService(store, recorder)

	return &Core{
		Store:   store,
		Auth:    authService,
		RBAC:    rbacService,
		Policy:  policyEngine,
		Audit:   auditService,
		Session: sessionService,
		Plugins: plugins,
	}, nil
}

func (c *Core) Close() error {
	if c == nil || c.Store == nil {
		return nil
	}
	return c.Store.Close()
}
