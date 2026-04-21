package session

import (
	"context"
	"time"

	"github.com/google/uuid"

	"sentinel/backend/internal/audit"
	"sentinel/backend/internal/domain"
	"sentinel/backend/internal/store"
)

type Service struct {
	store store.Store
	audit *audit.Service
}

type StartInput struct {
	UserID   string
	Username string
	HostID   string
	HostName string
	SourceIP string
	Protocol string
	Status   string
}

func NewService(st store.Store, auditSvc *audit.Service) *Service {
	return &Service{store: st, audit: auditSvc}
}

func (s *Service) Start(ctx context.Context, input StartInput) (domain.Session, error) {
	if input.Status == "" {
		input.Status = domain.SessionStatusActive
	}

	if input.Protocol == "" {
		input.Protocol = domain.SessionProtocolSSHTunnel
	}

	session := domain.Session{
		ID:        uuid.NewString(),
		UserID:    input.UserID,
		Username:  input.Username,
		HostID:    input.HostID,
		HostName:  input.HostName,
		SourceIP:  input.SourceIP,
		Protocol:  input.Protocol,
		Status:    input.Status,
		StartedAt: time.Now().UTC(),
	}

	if err := s.store.CreateSession(ctx, session); err != nil {
		return domain.Session{}, err
	}

	if s.audit != nil {
		_ = s.audit.Record(ctx, audit.NewEntry(
			input.UserID,
			input.Username,
			"session.start",
			session.HostName,
			"success",
			input.SourceIP,
			map[string]any{"sessionId": session.ID, "protocol": session.Protocol},
		))
	}

	return session, nil
}

func (s *Service) End(ctx context.Context, sessionID, status, replay string) error {
	session, err := s.store.GetSessionByID(ctx, sessionID)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	session.EndedAt = &now
	if status != "" {
		session.Status = status
	} else {
		session.Status = domain.SessionStatusClosed
	}
	session.Replay = replay

	if err := s.store.UpdateSession(ctx, session); err != nil {
		return err
	}

	if s.audit != nil {
		_ = s.audit.Record(ctx, audit.NewEntry(
			session.UserID,
			session.Username,
			"session.end",
			session.HostName,
			session.Status,
			session.SourceIP,
			map[string]any{"sessionId": session.ID},
		))
	}

	return nil
}

func (s *Service) GetByID(ctx context.Context, sessionID string) (domain.Session, error) {
	return s.store.GetSessionByID(ctx, sessionID)
}

func (s *Service) List(ctx context.Context, filter store.SessionFilter) ([]domain.Session, error) {
	return s.store.ListSessions(ctx, filter)
}
