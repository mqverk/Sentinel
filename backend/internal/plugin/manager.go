package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

type AuditEvent struct {
	ActorID       string         `json:"actorId"`
	ActorUsername string         `json:"actorUsername"`
	Action        string         `json:"action"`
	Resource      string         `json:"resource"`
	Outcome       string         `json:"outcome"`
	SourceIP      string         `json:"sourceIp"`
	Details       map[string]any `json:"details"`
	Timestamp     time.Time      `json:"timestamp"`
}

type Plugin interface {
	Name() string
	OnAudit(ctx context.Context, event AuditEvent) error
}

type Manager struct {
	plugins []Plugin
	logger  *slog.Logger
}

func NewManager(logger *slog.Logger) *Manager {
	return &Manager{plugins: make([]Plugin, 0), logger: logger}
}

func (m *Manager) Register(plugin Plugin) {
	m.plugins = append(m.plugins, plugin)
	m.logger.Info("plugin registered", "name", plugin.Name())
}

func (m *Manager) DispatchAudit(ctx context.Context, event AuditEvent) {
	for _, plugin := range m.plugins {
		if err := plugin.OnAudit(ctx, event); err != nil {
			m.logger.Error("plugin audit dispatch failed", "plugin", plugin.Name(), "error", err.Error())
		}
	}
}

type StdoutAuditPlugin struct{}

func (p *StdoutAuditPlugin) Name() string { return "stdout-audit" }

func (p *StdoutAuditPlugin) OnAudit(_ context.Context, event AuditEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}
	fmt.Println(string(payload))
	return nil
}

type WebhookAuditPlugin struct {
	url    string
	client *http.Client
}

func NewWebhookAuditPlugin(url string) *WebhookAuditPlugin {
	return &WebhookAuditPlugin{
		url:    url,
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

func (p *WebhookAuditPlugin) Name() string { return "webhook-audit" }

func (p *WebhookAuditPlugin) OnAudit(ctx context.Context, event AuditEvent) error {
	if p.url == "" {
		return nil
	}
	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create webhook request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := p.client.Do(request)
	if err != nil {
		return fmt.Errorf("send webhook request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", response.StatusCode)
	}
	return nil
}
