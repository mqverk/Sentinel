package api

import "net/http"

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	summary, err := s.store.GetDashboardSummary(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load dashboard")
		return
	}

	writeJSON(w, http.StatusOK, summary)
}
