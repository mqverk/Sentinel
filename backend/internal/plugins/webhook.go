package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"sentinel/backend/internal/domain"
)

type WebhookAuditPlugin struct {
	url    string
	client *http.Client
}

func NewWebhookAuditPlugin(url string, timeout time.Duration) *WebhookAuditPlugin {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	return &WebhookAuditPlugin{
		url: url,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

func (w *WebhookAuditPlugin) Name() string {
	return "webhook-audit"
}

func (w *WebhookAuditPlugin) OnAudit(ctx context.Context, entry domain.AuditLog) error {
	body, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	return nil
}
