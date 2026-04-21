package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/httprate"

	"sentinel/backend/internal/api/middleware"
	"sentinel/backend/internal/audit"
	"sentinel/backend/internal/auth"
	"sentinel/backend/internal/config"
	"sentinel/backend/internal/policy"
	"sentinel/backend/internal/session"
	"sentinel/backend/internal/store"
)

type Server struct {
	cfg      config.Config
	log      *slog.Logger
	store    store.Store
	auth     *auth.Service
	tokens   *auth.Manager
	policy   *policy.Engine
	sessions *session.Service
	audit    *audit.Service
	router   chi.Router
}

func NewServer(
	cfg config.Config,
	log *slog.Logger,
	st store.Store,
	authService *auth.Service,
	tokens *auth.Manager,
	policyEngine *policy.Engine,
	sessionService *session.Service,
	auditService *audit.Service,
) *Server {
	s := &Server{
		cfg:      cfg,
		log:      log,
		store:    st,
		auth:     authService,
		tokens:   tokens,
		policy:   policyEngine,
		sessions: sessionService,
		audit:    auditService,
	}

	s.router = s.routes()
	return s
}

func (s *Server) routes() chi.Router {
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)
	r.Use(middleware.RequestLogger(s.log))
	r.Use(httprate.LimitByIP(s.cfg.Security.RateLimit, s.cfg.RateWindowDuration()))
	r.Use(middleware.IPFilter(s.cfg.Security.AllowedCIDRs))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   s.cfg.API.CORSAllowedOrigins,
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodOptions},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		ExposedHeaders:   []string{"X-Request-Id"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	r.Route("/api/v1", func(v1 chi.Router) {
		v1.Post("/auth/login", s.handleLogin)

		v1.Group(func(private chi.Router) {
			private.Use(middleware.Authenticate(s.tokens))

			private.Get("/dashboard", s.withPermission(policy.PermissionDashboardRead, s.handleDashboard))

			private.Get("/users", s.withPermission(policy.PermissionUsersRead, s.handleListUsers))
			private.Post("/users", s.withPermission(policy.PermissionUsersWrite, s.handleCreateUser))
			private.Put("/users/{userID}", s.withPermission(policy.PermissionUsersWrite, s.handleUpdateUser))

			private.Get("/roles", s.withPermission(policy.PermissionRolesRead, s.handleListRoles))
			private.Post("/roles", s.withPermission(policy.PermissionRolesWrite, s.handleCreateRole))
			private.Put("/roles/{roleID}", s.withPermission(policy.PermissionRolesWrite, s.handleUpdateRole))
			private.Get("/permissions", s.withPermission(policy.PermissionRolesRead, s.handleListPermissions))

			private.Get("/hosts", s.withPermission(policy.PermissionHostsRead, s.handleListHosts))
			private.Post("/hosts", s.withPermission(policy.PermissionHostsWrite, s.handleCreateHost))
			private.Put("/hosts/{hostID}", s.withPermission(policy.PermissionHostsWrite, s.handleUpdateHost))

			private.Get("/sessions", s.withPermission(policy.PermissionSessionsRead, s.handleListSessions))
			private.Post("/sessions/start", s.withPermission(policy.PermissionSessionsWrite, s.handleStartSession))
			private.Post("/sessions/{sessionID}/end", s.withPermission(policy.PermissionSessionsWrite, s.handleEndSession))
			private.Get("/sessions/{sessionID}/replay", s.withPermission(policy.PermissionSessionsRead, s.handleSessionReplay))

			private.Get("/audit/logs", s.withPermission(policy.PermissionAuditRead, s.handleListAuditLogs))

			private.Get("/settings", s.withPermission(policy.PermissionSettingsRead, s.handleGetSettings))
			private.Put("/settings", s.withPermission(policy.PermissionSettingsWrite, s.handleUpdateSetting))
		})
	})

	return r
}

func (s *Server) Start(ctx context.Context, addr string) error {
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           s.router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	s.log.Info("http api started", slog.String("address", addr))
	err := httpServer.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}

func (s *Server) withPermission(permission string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := middleware.ClaimsFromContext(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "missing auth context")
			return
		}

		roles, err := s.store.ListUserRoles(r.Context(), claims.UserID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to resolve roles")
			return
		}

		if !s.policy.HasPermission(roles, permission) {
			writeError(w, http.StatusForbidden, "permission denied")
			return
		}

		next(w, r.WithContext(withRoles(r.Context(), roles)))
	}
}
