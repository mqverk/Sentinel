package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"sentinel/backend/internal/audit"
)

type upsertSettingRequest struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	keys := []string{"session.retentionDays", "security.allowedCIDRs"}
	response := make(map[string]any, len(keys))
	for _, key := range keys {
		raw, err := s.store.GetSetting(r.Context(), key)
		if err != nil {
			continue
		}
		var value map[string]any
		if err := json.Unmarshal([]byte(raw), &value); err != nil {
			continue
		}
		response[key] = value["value"]
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleUpsertSetting(w http.ResponseWriter, r *http.Request) {
	principal, err := principalFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "missing principal")
		return
	}

	var request upsertSettingRequest
	if err := decodeJSON(r, s.cfg.Security.MaxRequestBodyBytes, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(request.Key) == "" {
		writeError(w, http.StatusBadRequest, "key is required")
		return
	}

	wrapped, err := json.Marshal(map[string]any{"value": request.Value})
	if err != nil {
		writeError(w, http.StatusBadRequest, "value must be json serializable")
		return
	}
	if err := s.store.UpsertSetting(r.Context(), request.Key, string(wrapped)); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to upsert setting")
		return
	}

	s.auditService.Log(r.Context(), audit.Event{
		ActorID:       principal.UserID,
		ActorUsername: principal.Username,
		Action:        "settings.upsert",
		Resource:      "settings",
		Outcome:       "allow",
		SourceIP:      sourceIP(r),
		Details: map[string]any{
			"key": request.Key,
		},
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
