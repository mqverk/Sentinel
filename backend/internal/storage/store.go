package storage

import (
	"context"
	"errors"
	"time"

	"sentinel/backend/internal/config"
	"sentinel/backend/internal/model"
)

var ErrNotFound = errors.New("record not found")

type Store interface {
	Ping(ctx context.Context) error
	Close() error
	RunMigrations(ctx context.Context) error
	Seed(ctx context.Context) error

	AuthenticateUser(ctx context.Context, username string) (*model.User, error)
	GetUserByID(ctx context.Context, userID string) (*model.User, error)
	ListUsers(ctx context.Context) ([]model.User, error)
	CreateUser(ctx context.Context, user model.User) error
	ReplaceUserRoles(ctx context.Context, userID string, roleIDs []string) error

	ListRoles(ctx context.Context) ([]model.Role, error)
	CreateRole(ctx context.Context, role model.Role) error
	ListPermissions(ctx context.Context) ([]model.Permission, error)
	ListRolePermissions(ctx context.Context, roleID string) ([]model.Permission, error)
	ReplaceRolePermissions(ctx context.Context, roleID string, permissionIDs []string) error
	UserRoles(ctx context.Context, userID string) ([]model.Role, error)
	UserPermissions(ctx context.Context, userID string) ([]model.Permission, error)

	ListHosts(ctx context.Context) ([]model.Host, error)
	CreateHost(ctx context.Context, host model.Host) error
	ListPoliciesByHost(ctx context.Context, hostID string) ([]model.Policy, error)
	ReplaceHostPolicies(ctx context.Context, hostID string, policies []model.Policy) error
	HasHostAccess(ctx context.Context, userID, hostID string) (bool, error)

	CreateSession(ctx context.Context, session model.Session) error
	ListSessions(ctx context.Context, status string) ([]model.Session, error)
	GetSession(ctx context.Context, sessionID string) (*model.Session, error)
	UpdateSessionStatus(ctx context.Context, sessionID, status string, endedAt *time.Time) error

	CreateAuditLog(ctx context.Context, log model.AuditLog) error
	ListAuditLogs(ctx context.Context, limit int, query string) ([]model.AuditLog, error)
	CountFailedLoginsSince(ctx context.Context, since time.Time) (int, error)
	RecentLoginAudits(ctx context.Context, limit int) ([]model.AuditLog, error)

	GetSetting(ctx context.Context, key string) (string, error)
	UpsertSetting(ctx context.Context, key, value string) error

	UpdateLastLogin(ctx context.Context, userID string, loginAt time.Time) error
}

func Open(cfg config.DatabaseConfig) (Store, error) {
	return newSQLStore(cfg)
}
