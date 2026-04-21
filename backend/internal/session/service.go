package session

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"sentinel/backend/internal/model"
	"sentinel/backend/internal/storage"
)

type Service struct {
	store    storage.Store
	recorder *Recorder
}

func NewService(store storage.Store, recorder *Recorder) *Service {
	return &Service{store: store, recorder: recorder}
}

func (s *Service) StartSession(ctx context.Context, userID, hostID, metadataJSON string) (*model.Session, error) {
	sessionID := uuid.NewString()
	recordingPath := s.recorder.PathForSession(sessionID)
	now := time.Now().UTC()
	entry := model.Session{
		ID:            sessionID,
		UserID:        userID,
		HostID:        hostID,
		Status:        "active",
		StartedAt:     now,
		RecordingPath: recordingPath,
		MetadataJSON:  metadataJSON,
	}
	if err := s.store.CreateSession(ctx, entry); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	return &entry, nil
}

func (s *Service) EndSession(ctx context.Context, sessionID string) error {
	now := time.Now().UTC()
	if err := s.store.UpdateSessionStatus(ctx, sessionID, "ended", &now); err != nil {
		return fmt.Errorf("end session: %w", err)
	}
	return nil
}

func (s *Service) ListSessions(ctx context.Context, status string) ([]model.Session, error) {
	sessions, err := s.store.ListSessions(ctx, status)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	return sessions, nil
}

func (s *Service) Replay(ctx context.Context, sessionID string) ([]ReplayFrame, error) {
	record, err := s.store.GetSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("lookup session: %w", err)
	}
	frames, err := s.recorder.ReadFrames(record.RecordingPath)
	if err != nil {
		return nil, fmt.Errorf("read session replay: %w", err)
	}
	return frames, nil
}

func (s *Service) RecordFrame(recordingPath string, start time.Time, stream string, payload []byte) error {
	if err := s.recorder.AppendFrame(recordingPath, start, stream, payload); err != nil {
		return fmt.Errorf("append recording frame: %w", err)
	}
	return nil
}
