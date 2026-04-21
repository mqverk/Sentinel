package api

import (
	"net/http"
	"strconv"
	"strings"

	"sentinel/backend/internal/api/middleware"
	"sentinel/backend/internal/audit"
	"sentinel/backend/internal/store"
)

var writableSettings = map[string]struct{}{
	"security.rate_limit":     {},
	"security.rate_window":    {},
	"security.allowed_cidrs":  {},
	"observability.log_level": {},
}

type updateSettingRequest struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	values := defaultSettingsMap(s)
	for key := range writableSettings {
		stored, err := s.store.GetSetting(r.Context(), key)
		if err == nil {
			values[key] = stored
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"settings": values})
}

func (s *Server) handleUpdateSetting(w http.ResponseWriter, r *http.Request) {
	var req updateSettingRequest
	if err := decodeJSON(r, 1<<20, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request payload")
		return
	}

	req.Key = strings.TrimSpace(req.Key)
	req.Value = strings.TrimSpace(req.Value)
	if req.Key == "" || req.Value == "" {
		writeError(w, http.StatusBadRequest, "key and value are required")
		return
	}

	if _, ok := writableSettings[req.Key]; !ok {
		writeError(w, http.StatusBadRequest, "setting key is not writable")
		return
	}

	if req.Key == "security.rate_limit" {
		if _, err := strconv.Atoi(req.Value); err != nil {
			writeError(w, http.StatusBadRequest, "security.rate_limit must be an integer")
			return
		}
	}

	if err := s.store.SetSetting(r.Context(), req.Key, req.Value); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update setting")
		return
	}

	claims, _ := middleware.ClaimsFromContext(r.Context())
	_ = s.audit.Record(r.Context(), audit.NewEntry(
		claims.UserID,
		claims.Username,
		"settings.update",
		req.Key,
		"success",
		requestIP(r),
		map[string]any{"value": req.Value},
	))

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func defaultSettingsMap(s *Server) map[string]string {
	return map[string]string{
		"security.rate_limit":     strconv.Itoa(s.cfg.Security.RateLimit),
		"security.rate_window":    s.cfg.Security.RateWindow,
		"security.allowed_cidrs":  strings.Join(s.cfg.Security.AllowedCIDRs, ","),
		"observability.log_level": s.cfg.Observability.LogLevel,
	}
}

func isStoreNotFound(err error) bool {
	return err == store.ErrNotFound
}
