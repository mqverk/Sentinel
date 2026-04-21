package api

import (
	"net/http"
	"strconv"
	"strings"
)

func (s *Server) handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	logs, err := s.auditService.List(r.Context(), limit, query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list audit logs")
		return
	}
	writeJSON(w, http.StatusOK, logs)
}
