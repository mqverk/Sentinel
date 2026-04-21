package app

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"sentinel/backend/internal/api"
	"sentinel/backend/internal/audit"
	"sentinel/backend/internal/auth"
	"sentinel/backend/internal/config"
	"sentinel/backend/internal/logger"
	"sentinel/backend/internal/plugins"
	"sentinel/backend/internal/policy"
	"sentinel/backend/internal/session"
	"sentinel/backend/internal/ssh"
	"sentinel/backend/internal/store"
	"sentinel/backend/internal/store/postgres"
	"sentinel/backend/internal/store/sqlite"
)

type App struct {
	config config.Config
	log    *slog.Logger
	store  store.Store
	api    *api.Server
	ssh    *ssh.Server
}

func New(configPath string) (*App, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}

	log := logger.New(cfg.Observability.LogLevel)

	st, err := initializeStore(cfg, log)
	if err != nil {
		return nil, err
	}

	if err := st.Migrate(context.Background()); err != nil {
		return nil, err
	}

	adminHash, err := auth.HashPassword(cfg.Bootstrap.AdminPassword)
	if err != nil {
		return nil, err
	}

	if err := st.Seed(context.Background(), store.SeedData{
		AdminUsername:     cfg.Bootstrap.AdminUsername,
		AdminPasswordHash: adminHash,
		AdminDisplayName:  cfg.Bootstrap.AdminDisplayName,
	}); err != nil {
		return nil, err
	}

	pluginManager := plugins.NewManager(log)
	if strings.TrimSpace(cfg.Plugins.WebhookAuditURL) != "" {
		pluginManager.Register(plugins.NewWebhookAuditPlugin(cfg.Plugins.WebhookAuditURL, 5*time.Second))
	}

	tokenManager := auth.NewManager(cfg.Auth.JWTSecret, cfg.TokenTTLDuration())
	auditService := audit.NewService(st, pluginManager)
	policyEngine := policy.NewEngine()
	sessionService := session.NewService(st, auditService)
	authService := auth.NewService(st, tokenManager, auditService, cfg.Auth.PasswordMinLength)

	apiServer := api.NewServer(cfg, log, st, authService, tokenManager, policyEngine, sessionService, auditService)
	sshServer := ssh.NewServer(log, st, authService, policyEngine, sessionService, auditService)

	return &App{
		config: cfg,
		log:    log,
		store:  st,
		api:    apiServer,
		ssh:    sshServer,
	}, nil
}

func initializeStore(cfg config.Config, log *slog.Logger) (store.Store, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Storage.Driver)) {
	case "sqlite", "":
		return sqlite.New(cfg.Storage.DSN, log)
	case "postgres", "postgresql":
		return postgres.New(cfg.Storage.DSN)
	default:
		return nil, errors.New("unsupported storage driver")
	}
}

func (a *App) Start(ctx context.Context) error {
	defer a.store.Close()

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return a.api.Start(gctx, a.config.Server.HTTPAddress)
	})
	g.Go(func() error {
		return a.ssh.Start(gctx, a.config.Server.SSHAddress)
	})

	err := g.Wait()
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}

	return nil
}
