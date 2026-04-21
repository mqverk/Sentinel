package domain

import "time"

type AuditLog struct {
	ID            int64          `json:"id"`
	Timestamp     time.Time      `json:"timestamp"`
	ActorID       string         `json:"actorId"`
	ActorUsername string         `json:"actorUsername"`
	Action        string         `json:"action"`
	Resource      string         `json:"resource"`
	Result        string         `json:"result"`
	SourceIP      string         `json:"sourceIp"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}
