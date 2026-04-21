package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"

	apiMiddleware "sentinel/backend/internal/api/middleware"
	"sentinel/backend/internal/audit"
	"sentinel/backend/internal/auth"
	"sentinel/backend/internal/config"
	"sentinel/backend/internal/policy"
	"sentinel/backend/internal/rbac"
	"sentinel/backend/internal/session"
	"sentinel/backend/internal/storage"
)

type Server struct {
	cfg            config.Config
	logger         *slog.Logger
	store          storage.Store
	authService    *auth.Service
	rbacService    *rbac.Service
	policyEngine   *policy.Engine
	auditService   *audit.Service
	sessionService *session.Service
	httpServer     *http.Server
}

func NewServer(
	cfg config.Config,
	logger *slog.Logger,
	store storage.Store,
	authService *auth.Service,
	rbacService *rbac.Service,
	policyEngine *policy.Engine,
	auditService *audit.Service,
	sessionService *session.Service,
) (*Server, error) {
	r := chi.NewRouter()
	r.Use(chiMiddleware.RequestID)
	r.Use(chiMiddleware.RealIP)
	r.Use(chiMiddleware.Recoverer)
	r.Use(apiMiddleware.RequestLog(logger))
	r.Use(apiMiddleware.RateLimit(cfg.Security.RateLimit.RequestsPerSecond, cfg.Security.RateLimit.Burst))

	ipFilter, err := apiMiddleware.NewIPFilter(cfg.Security.AllowedCIDRs)
	if err != nil {
		return nil, fmt.Errorf("build ip filter middleware: %w", err)
	}
	r.Use(ipFilter.Middleware())
	r.Use(cors(cfg.API.CORSOrigins))

	s := &Server{
		cfg:            cfg,
		logger:         logger,
		store:          store,
		authService:    authService,
		rbacService:    rbacService,
		policyEngine:   policyEngine,
		auditService:   auditService,
		sessionService: sessionService,
	}

	r.Get("/health", s.handleHealth)
	r.Route("/api/v1", func(apiRouter chi.Router) {
		apiRouter.Post("/auth/login", s.handleLogin)
		apiRouter.Group(func(secure chi.Router) {
			secure.Use(apiMiddleware.Authenticate(s.authService))
			secure.Get("/auth/me", s.handleMe)

			secure.With(s.requirePermission("dashboard", "view")).Get("/dashboard/overview", s.handleDashboardOverview)

			secure.With(s.requirePermission("users", "read")).Get("/users", s.handleListUsers)
			secure.With(s.requirePermission("users", "write")).Post("/users", s.handleCreateUser)
			secure.With(s.requirePermission("users", "write")).Put("/users/{userID}/roles", s.handleReplaceUserRoles)

			secure.With(s.requirePermission("roles", "read")).Get("/roles", s.handleListRoles)
			secure.With(s.requirePermission("roles", "read")).Get("/permissions", s.handleListPermissions)
			secure.With(s.requirePermission("roles", "write")).Post("/roles", s.handleCreateRole)
			secure.With(s.requirePermission("roles", "write")).Put("/roles/{roleID}/permissions", s.handleReplaceRolePermissions)

			secure.With(s.requirePermission("sessions", "read")).Get("/sessions", s.handleListSessions)
			secure.With(s.requirePermission("sessions", "read")).Post("/sessions/start", s.handleStartSession)
			secure.With(s.requirePermission("sessions", "replay")).Get("/sessions/{sessionID}/replay", s.handleReplaySession)
			secure.With(s.requirePermission("sessions", "terminate")).Post("/sessions/{sessionID}/terminate", s.handleTerminateSession)

			secure.With(s.requirePermission("audit", "read")).Get("/audit/logs", s.handleListAuditLogs)

			secure.With(s.requirePermission("hosts", "read")).Get("/hosts", s.handleListHosts)
			secure.With(s.requirePermission("hosts", "write")).Post("/hosts", s.handleCreateHost)
			secure.With(s.requirePermission("hosts", "write")).Put("/hosts/{hostID}/policies", s.handleReplaceHostPolicies)

			secure.With(s.requirePermission("settings", "read")).Get("/settings", s.handleGetSettings)
			secure.With(s.requirePermission("settings", "write")).Put("/settings", s.handleUpsertSetting)
		})
	})

	s.httpServer = &http.Server{
		Addr:         cfg.API.ListenAddr,
		Handler:      r,
		ReadTimeout:  cfg.API.ReadTimeout,
		WriteTimeout: cfg.API.WriteTimeout,
		IdleTimeout:  cfg.API.IdleTimeout,
	}

	return s, nil
}

func (s *Server) Start() error {
	s.logger.Info("starting api server", "addr", s.cfg.API.ListenAddr)
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("listen and serve: %w", err)
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) requirePermission(resource, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, err := principalFromRequest(r)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "missing principal")
				return
			}
			if !s.rbacService.HasPermission(principal, resource, action) {
				writeError(w, http.StatusForbidden, "insufficient permissions")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func cors(allowedOrigins []string) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		allowed[strings.TrimSpace(origin)] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := strings.TrimSpace(r.Header.Get("Origin"))
			if origin != "" {
				if len(allowed) == 0 {
					w.Header().Set("Access-Control-Allow-Origin", origin)
				} else if _, ok := allowed[origin]; ok {
					w.Header().Set("Access-Control-Allow-Origin", origin)
				}
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
