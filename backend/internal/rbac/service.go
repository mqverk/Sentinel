package rbac

import (
	"context"
	"fmt"

	"sentinel/backend/internal/auth"
	"sentinel/backend/internal/storage"
)

type Service struct {
	store storage.Store
}

func NewService(store storage.Store) *Service {
	return &Service{store: store}
}

func (s *Service) HasPermission(principal auth.Principal, resource, action string) bool {
	needle := resource + ":" + action
	for _, permission := range principal.Permissions {
		if permission == needle {
			return true
		}
	}
	return false
}

func (s *Service) RefreshPermissions(ctx context.Context, principal auth.Principal) (auth.Principal, error) {
	permissions, err := s.store.UserPermissions(ctx, principal.UserID)
	if err != nil {
		return auth.Principal{}, fmt.Errorf("refresh user permissions: %w", err)
	}
	roles, err := s.store.UserRoles(ctx, principal.UserID)
	if err != nil {
		return auth.Principal{}, fmt.Errorf("refresh user roles: %w", err)
	}

	principal.Permissions = principal.Permissions[:0]
	for _, permission := range permissions {
		principal.Permissions = append(principal.Permissions, permission.Resource+":"+permission.Action)
	}

	principal.Roles = principal.Roles[:0]
	for _, role := range roles {
		principal.Roles = append(principal.Roles, role.Name)
	}

	return principal, nil
}
