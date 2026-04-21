package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"sentinel/backend/internal/model"
	"sentinel/backend/internal/plugin"
	"sentinel/backend/internal/storage"
)

type Event struct {
	ActorID       string         `json:"actorId"`
	ActorUsername string         `json:"actorUsername"`
	Action        string         `json:"action"`
	Resource      string         `json:"resource"`
	Outcome       string         `json:"outcome"`
	SourceIP      string         `json:"sourceIp"`
	Details       map[string]any `json:"details"`
}

type Service struct {
	store   storage.Store
	logger  *slog.Logger
	plugins *plugin.Manager
}

func NewService(store storage.Store, logger *slog.Logger, plugins *plugin.Manager) *Service {
	return &Service{store: store, logger: logger, plugins: plugins}
}

func (s *Service) Log(ctx context.Context, event Event) {
	detailsJSON, err := json.Marshal(event.Details)
	if err != nil {
		s.logger.Error("marshal audit details failed", "error", err.Error())
		detailsJSON = []byte(`{"error":"marshal failed"}`)
	}

	entry := model.AuditLog{
		ID:            uuid.NewString(),
		ActorID:       event.ActorID,
		ActorUsername: event.ActorUsername,
		Action:        event.Action,
		Resource:      event.Resource,
		Outcome:       event.Outcome,
		SourceIP:      event.SourceIP,
		DetailsJSON:   string(detailsJSON),
		CreatedAt:     time.Now().UTC(),
	}

	if err := s.store.CreateAuditLog(ctx, entry); err != nil {
		s.logger.Error("persist audit log failed", "error", err.Error(), "action", event.Action, "resource", event.Resource)
		return
	}

	s.plugins.DispatchAudit(ctx, plugin.AuditEvent{
		ActorID:       event.ActorID,
		ActorUsername: event.ActorUsername,
		Action:        event.Action,
		Resource:      event.Resource,
		Outcome:       event.Outcome,
		SourceIP:      event.SourceIP,
		Details:       event.Details,
		Timestamp:     entry.CreatedAt,
	})
}

func (s *Service) List(ctx context.Context, limit int, query string) ([]model.AuditLog, error) {
	logs, err := s.store.ListAuditLogs(ctx, limit, query)
	if err != nil {
		return nil, fmt.Errorf("list audit logs: %w", err)
	}
	return logs, nil
}
