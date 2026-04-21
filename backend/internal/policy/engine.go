package policy

import (
	"strings"

	"sentinel/backend/internal/domain"
)

const (
	PermissionDashboardRead = "dashboard:read"
	PermissionUsersRead     = "users:read"
	PermissionUsersWrite    = "users:write"
	PermissionRolesRead     = "roles:read"
	PermissionRolesWrite    = "roles:write"
	PermissionHostsRead     = "hosts:read"
	PermissionHostsWrite    = "hosts:write"
	PermissionHostsConnect  = "hosts:connect"
	PermissionSessionsRead  = "sessions:read"
	PermissionSessionsWrite = "sessions:write"
	PermissionAuditRead     = "audit:read"
	PermissionSettingsRead  = "settings:read"
	PermissionSettingsWrite = "settings:write"
)

var PermissionsCatalog = []string{
	PermissionDashboardRead,
	PermissionUsersRead,
	PermissionUsersWrite,
	PermissionRolesRead,
	PermissionRolesWrite,
	PermissionHostsRead,
	PermissionHostsWrite,
	PermissionHostsConnect,
	PermissionSessionsRead,
	PermissionSessionsWrite,
	PermissionAuditRead,
	PermissionSettingsRead,
	PermissionSettingsWrite,
}

type Engine struct{}

func NewEngine() *Engine {
	return &Engine{}
}

func (e *Engine) HasPermission(roles []domain.Role, permission string) bool {
	for _, role := range roles {
		for _, granted := range role.Permissions {
			if granted == "*" || granted == permission {
				return true
			}

			if strings.HasSuffix(granted, ":*") {
				prefix := strings.TrimSuffix(granted, "*")
				if strings.HasPrefix(permission, prefix) {
					return true
				}
			}
		}
	}

	return false
}

func (e *Engine) CanAccessHost(roles []domain.Role, host domain.Host) bool {
	if !host.Active {
		return false
	}

	return e.HasPermission(roles, PermissionHostsConnect)
}

func (e *Engine) FlattenPermissions(roles []domain.Role) []string {
	permissions := map[string]struct{}{}
	for _, role := range roles {
		for _, permission := range role.Permissions {
			permissions[permission] = struct{}{}
		}
	}

	result := make([]string, 0, len(permissions))
	for permission := range permissions {
		result = append(result, permission)
	}

	return result
}
