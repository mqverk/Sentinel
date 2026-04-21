package api

import (
	"net/http"
	"strings"

	"sentinel/backend/internal/store"
)

func (s *Server) handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	filter := store.AuditFilter{
		Search: strings.TrimSpace(r.URL.Query().Get("search")),
		Action: strings.TrimSpace(r.URL.Query().Get("action")),
		Result: strings.TrimSpace(r.URL.Query().Get("result")),
		Limit:  queryInt(r, "limit", 100),
		Offset: queryInt(r, "offset", 0),
	}

	entries, err := s.audit.List(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list audit logs")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"logs": entries})
}
