package plugins

import (
	"context"
	"log/slog"
	"sync"

	"sentinel/backend/internal/domain"
)

type AuditPlugin interface {
	Name() string
	OnAudit(ctx context.Context, entry domain.AuditLog) error
}

type Manager struct {
	log     *slog.Logger
	mu      sync.RWMutex
	plugins []AuditPlugin
}

func NewManager(log *slog.Logger) *Manager {
	return &Manager{log: log, plugins: []AuditPlugin{}}
}

func (m *Manager) Register(plugin AuditPlugin) {
	if plugin == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.plugins = append(m.plugins, plugin)

	m.log.Info("registered plugin", slog.String("name", plugin.Name()))
}

func (m *Manager) PublishAudit(ctx context.Context, entry domain.AuditLog) {
	m.mu.RLock()
	plugins := make([]AuditPlugin, len(m.plugins))
	copy(plugins, m.plugins)
	m.mu.RUnlock()

	for _, plugin := range plugins {
		if err := plugin.OnAudit(ctx, entry); err != nil {
			m.log.Warn("plugin audit publish failed", slog.String("plugin", plugin.Name()), slog.Any("error", err))
		}
	}
}
