package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"sentinel/backend/internal/audit"
	"sentinel/backend/internal/model"
)

type hostWithPolicies struct {
	model.Host
	Policies []model.Policy `json:"policies"`
}

type createHostRequest struct {
	Name        string `json:"name"`
	Address     string `json:"address"`
	Port        int    `json:"port"`
	Environment string `json:"environment"`
	Criticality string `json:"criticality"`
}

type hostPolicyInput struct {
	RoleID     string `json:"roleId"`
	CanConnect bool   `json:"canConnect"`
	RequireMFA bool   `json:"requireMfa"`
}

type replaceHostPoliciesRequest struct {
	Policies []hostPolicyInput `json:"policies"`
}

func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.store.ListHosts(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list hosts")
		return
	}

	payload := make([]hostWithPolicies, 0, len(hosts))
	for _, host := range hosts {
		policies, err := s.store.ListPoliciesByHost(r.Context(), host.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list host policies")
			return
		}
		payload = append(payload, hostWithPolicies{Host: host, Policies: policies})
	}

	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) handleCreateHost(w http.ResponseWriter, r *http.Request) {
	principal, err := principalFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "missing principal")
		return
	}

	var request createHostRequest
	if err := decodeJSON(r, s.cfg.Security.MaxRequestBodyBytes, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(request.Name) == "" || strings.TrimSpace(request.Address) == "" {
		writeError(w, http.StatusBadRequest, "name and address are required")
		return
	}
	if request.Port <= 0 {
		request.Port = 22
	}

	host := model.Host{
		ID:          "host-" + uuid.NewString(),
		Name:        strings.TrimSpace(request.Name),
		Address:     strings.TrimSpace(request.Address),
		Port:        request.Port,
		Environment: strings.TrimSpace(request.Environment),
		Criticality: strings.TrimSpace(request.Criticality),
		CreatedAt:   time.Now().UTC(),
	}
	if err := s.store.CreateHost(r.Context(), host); err != nil {
		writeError(w, http.StatusBadRequest, "failed to create host")
		return
	}

	s.auditService.Log(r.Context(), audit.Event{
		ActorID:       principal.UserID,
		ActorUsername: principal.Username,
		Action:        "hosts.create",
		Resource:      "hosts",
		Outcome:       "allow",
		SourceIP:      sourceIP(r),
		Details: map[string]any{
			"host": host.Name,
		},
	})

	writeJSON(w, http.StatusCreated, host)
}

func (s *Server) handleReplaceHostPolicies(w http.ResponseWriter, r *http.Request) {
	principal, err := principalFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "missing principal")
		return
	}

	hostID := chi.URLParam(r, "hostID")
	if strings.TrimSpace(hostID) == "" {
		writeError(w, http.StatusBadRequest, "hostID is required")
		return
	}

	var request replaceHostPoliciesRequest
	if err := decodeJSON(r, s.cfg.Security.MaxRequestBodyBytes, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	policies := make([]model.Policy, 0, len(request.Policies))
	now := time.Now().UTC()
	for _, input := range request.Policies {
		policies = append(policies, model.Policy{
			ID:         uuid.NewString(),
			RoleID:     input.RoleID,
			HostID:     hostID,
			CanConnect: input.CanConnect,
			RequireMFA: input.RequireMFA,
			CreatedAt:  now,
		})
	}

	if err := s.store.ReplaceHostPolicies(r.Context(), hostID, policies); err != nil {
		writeError(w, http.StatusBadRequest, "failed to replace host policies")
		return
	}

	s.auditService.Log(r.Context(), audit.Event{
		ActorID:       principal.UserID,
		ActorUsername: principal.Username,
		Action:        "hosts.policies.replace",
		Resource:      "hosts",
		Outcome:       "allow",
		SourceIP:      sourceIP(r),
		Details: map[string]any{
			"hostID":   hostID,
			"policies": request.Policies,
		},
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
