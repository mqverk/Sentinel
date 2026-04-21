package audit

import (
	"context"
	"time"

	"sentinel/backend/internal/domain"
	"sentinel/backend/internal/store"
)

type Publisher interface {
	PublishAudit(ctx context.Context, entry domain.AuditLog)
}

type Service struct {
	store     store.Store
	publisher Publisher
}

func NewService(st store.Store, publisher Publisher) *Service {
	return &Service{store: st, publisher: publisher}
}

func (s *Service) Record(ctx context.Context, entry domain.AuditLog) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	if entry.Metadata == nil {
		entry.Metadata = map[string]any{}
	}

	if err := s.store.CreateAuditLog(ctx, entry); err != nil {
		return err
	}

	if s.publisher != nil {
		s.publisher.PublishAudit(ctx, entry)
	}

	return nil
}

func (s *Service) List(ctx context.Context, filter store.AuditFilter) ([]domain.AuditLog, error) {
	return s.store.ListAuditLogs(ctx, filter)
}

func NewEntry(actorID, actorUsername, action, resource, result, sourceIP string, metadata map[string]any) domain.AuditLog {
	if metadata == nil {
		metadata = map[string]any{}
	}

	return domain.AuditLog{
		Timestamp:     time.Now().UTC(),
		ActorID:       actorID,
		ActorUsername: actorUsername,
		Action:        action,
		Resource:      resource,
		Result:        result,
		SourceIP:      sourceIP,
		Metadata:      metadata,
	}
}
