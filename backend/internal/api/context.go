package api

import (
	"context"

	"sentinel/backend/internal/domain"
)

type rolesKey struct{}

func withRoles(ctx context.Context, roles []domain.Role) context.Context {
	return context.WithValue(ctx, rolesKey{}, roles)
}

func rolesFromContext(ctx context.Context) ([]domain.Role, bool) {
	roles, ok := ctx.Value(rolesKey{}).([]domain.Role)
	if !ok {
		return nil, false
	}

	return roles, true
}
