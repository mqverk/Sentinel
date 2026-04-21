package store

import (
	"context"
	"errors"

	"sentinel/backend/internal/domain"
)

var ErrNotFound = errors.New("store: not found")

type SeedData struct {
	AdminUsername     string
	AdminPasswordHash string
	AdminDisplayName  string
}

type SessionFilter struct {
	Status string
	UserID string
	HostID string
	Limit  int
	Offset int
}

type AuditFilter struct {
	Search string
	Action string
	Result string
	Limit  int
	Offset int
}

type Store interface {
	Close() error
	Migrate(ctx context.Context) error
	Seed(ctx context.Context, data SeedData) error

	ListUsers(ctx context.Context, search string) ([]domain.User, error)
	GetUserByUsername(ctx context.Context, username string) (domain.User, error)
	GetUserByID(ctx context.Context, id string) (domain.User, error)
	CreateUser(ctx context.Context, user domain.User) error
	UpdateUser(ctx context.Context, user domain.User) error
	ListUserRoles(ctx context.Context, userID string) ([]domain.Role, error)
	SetUserRoles(ctx context.Context, userID string, roleIDs []string) error

	ListRoles(ctx context.Context, search string) ([]domain.Role, error)
	GetRoleByID(ctx context.Context, id string) (domain.Role, error)
	CreateRole(ctx context.Context, role domain.Role) error
	UpdateRole(ctx context.Context, role domain.Role) error

	ListHosts(ctx context.Context) ([]domain.Host, error)
	GetHostByID(ctx context.Context, id string) (domain.Host, error)
	GetHostByAddress(ctx context.Context, address string, port int) (domain.Host, error)
	CreateHost(ctx context.Context, host domain.Host) error
	UpdateHost(ctx context.Context, host domain.Host) error

	CreateSession(ctx context.Context, session domain.Session) error
	UpdateSession(ctx context.Context, session domain.Session) error
	GetSessionByID(ctx context.Context, id string) (domain.Session, error)
	ListSessions(ctx context.Context, filter SessionFilter) ([]domain.Session, error)

	CreateAuditLog(ctx context.Context, log domain.AuditLog) error
	ListAuditLogs(ctx context.Context, filter AuditFilter) ([]domain.AuditLog, error)

	GetSetting(ctx context.Context, key string) (string, error)
	SetSetting(ctx context.Context, key, value string) error

	GetDashboardSummary(ctx context.Context) (domain.DashboardSummary, error)
}
