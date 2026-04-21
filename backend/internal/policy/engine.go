package policy

import (
	"context"
	"fmt"

	"sentinel/backend/internal/auth"
	"sentinel/backend/internal/storage"
)

type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

type Engine struct {
	store storage.Store
}

func NewEngine(store storage.Store) *Engine {
	return &Engine{store: store}
}

func (e *Engine) CanConnect(ctx context.Context, principal auth.Principal, hostID string) (Decision, error) {
	if !principal.Authenticated {
		return Decision{Allowed: false, Reason: "unauthenticated principal"}, nil
	}

	allowed, err := e.store.HasHostAccess(ctx, principal.UserID, hostID)
	if err != nil {
		return Decision{}, fmt.Errorf("check host policy: %w", err)
	}
	if !allowed {
		return Decision{Allowed: false, Reason: "policy denied for host"}, nil
	}
	return Decision{Allowed: true, Reason: "policy allow"}, nil
}
