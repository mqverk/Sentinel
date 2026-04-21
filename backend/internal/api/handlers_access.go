package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"sentinel/backend/internal/audit"
	"sentinel/backend/internal/auth"
	"sentinel/backend/internal/model"
)

type userWithRoles struct {
	model.User
	Roles []model.Role `json:"roles"`
}

type roleWithPermissions struct {
	model.Role
	Permissions []model.Permission `json:"permissions"`
}

type createUserRequest struct {
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Password string   `json:"password"`
	RoleIDs  []string `json:"roleIds"`
}

type replaceRolesRequest struct {
	RoleIDs []string `json:"roleIds"`
}

type createRoleRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type replaceRolePermissionsRequest struct {
	PermissionIDs []string `json:"permissionIds"`
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list users")
		return
	}

	payload := make([]userWithRoles, 0, len(users))
	for _, user := range users {
		roles, err := s.store.UserRoles(r.Context(), user.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list user roles")
			return
		}
		payload = append(payload, userWithRoles{User: user, Roles: roles})
	}

	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	principal, err := principalFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "missing principal")
		return
	}

	var request createUserRequest
	if err := decodeJSON(r, s.cfg.Security.MaxRequestBodyBytes, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(request.Username) == "" || strings.TrimSpace(request.Email) == "" {
		writeError(w, http.StatusBadRequest, "username and email are required")
		return
	}
	if err := s.authService.ValidatePassword(request.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	hash, err := auth.HashPassword(request.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	user := model.User{
		ID:           uuid.NewString(),
		Username:     strings.TrimSpace(request.Username),
		Email:        strings.TrimSpace(request.Email),
		PasswordHash: hash,
		Disabled:     false,
		CreatedAt:    time.Now().UTC(),
	}
	if err := s.store.CreateUser(r.Context(), user); err != nil {
		writeError(w, http.StatusBadRequest, "failed to create user")
		return
	}
	if len(request.RoleIDs) > 0 {
		if err := s.store.ReplaceUserRoles(r.Context(), user.ID, request.RoleIDs); err != nil {
			writeError(w, http.StatusBadRequest, "failed to assign roles")
			return
		}
	}

	s.auditService.Log(r.Context(), audit.Event{
		ActorID:       principal.UserID,
		ActorUsername: principal.Username,
		Action:        "users.create",
		Resource:      "users",
		Outcome:       "allow",
		SourceIP:      sourceIP(r),
		Details: map[string]any{
			"targetUser": user.Username,
		},
	})

	roles, _ := s.store.UserRoles(r.Context(), user.ID)
	writeJSON(w, http.StatusCreated, userWithRoles{User: user, Roles: roles})
}

func (s *Server) handleReplaceUserRoles(w http.ResponseWriter, r *http.Request) {
	principal, err := principalFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "missing principal")
		return
	}

	userID := chi.URLParam(r, "userID")
	if strings.TrimSpace(userID) == "" {
		writeError(w, http.StatusBadRequest, "userID is required")
		return
	}

	var request replaceRolesRequest
	if err := decodeJSON(r, s.cfg.Security.MaxRequestBodyBytes, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := s.store.ReplaceUserRoles(r.Context(), userID, request.RoleIDs); err != nil {
		writeError(w, http.StatusBadRequest, "failed to replace user roles")
		return
	}

	s.auditService.Log(r.Context(), audit.Event{
		ActorID:       principal.UserID,
		ActorUsername: principal.Username,
		Action:        "users.roles.replace",
		Resource:      "users",
		Outcome:       "allow",
		SourceIP:      sourceIP(r),
		Details: map[string]any{
			"targetUserID": userID,
			"roleIDs":      request.RoleIDs,
		},
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := s.store.ListRoles(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list roles")
		return
	}

	payload := make([]roleWithPermissions, 0, len(roles))
	for _, role := range roles {
		permissions, err := s.store.ListRolePermissions(r.Context(), role.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load role permissions")
			return
		}
		payload = append(payload, roleWithPermissions{Role: role, Permissions: permissions})
	}
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) handleListPermissions(w http.ResponseWriter, r *http.Request) {
	permissions, err := s.store.ListPermissions(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list permissions")
		return
	}
	writeJSON(w, http.StatusOK, permissions)
}

func (s *Server) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	principal, err := principalFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "missing principal")
		return
	}

	var request createRoleRequest
	if err := decodeJSON(r, s.cfg.Security.MaxRequestBodyBytes, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(request.Name) == "" {
		writeError(w, http.StatusBadRequest, "role name is required")
		return
	}

	role := model.Role{
		ID:          "role-" + uuid.NewString(),
		Name:        strings.TrimSpace(request.Name),
		Description: strings.TrimSpace(request.Description),
		CreatedAt:   time.Now().UTC(),
	}
	if err := s.store.CreateRole(r.Context(), role); err != nil {
		writeError(w, http.StatusBadRequest, "failed to create role")
		return
	}

	s.auditService.Log(r.Context(), audit.Event{
		ActorID:       principal.UserID,
		ActorUsername: principal.Username,
		Action:        "roles.create",
		Resource:      "roles",
		Outcome:       "allow",
		SourceIP:      sourceIP(r),
		Details: map[string]any{
			"roleName": role.Name,
		},
	})

	writeJSON(w, http.StatusCreated, role)
}

func (s *Server) handleReplaceRolePermissions(w http.ResponseWriter, r *http.Request) {
	principal, err := principalFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "missing principal")
		return
	}

	roleID := chi.URLParam(r, "roleID")
	if strings.TrimSpace(roleID) == "" {
		writeError(w, http.StatusBadRequest, "roleID is required")
		return
	}

	var request replaceRolePermissionsRequest
	if err := decodeJSON(r, s.cfg.Security.MaxRequestBodyBytes, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := s.store.ReplaceRolePermissions(r.Context(), roleID, request.PermissionIDs); err != nil {
		writeError(w, http.StatusBadRequest, "failed to replace role permissions")
		return
	}

	s.auditService.Log(r.Context(), audit.Event{
		ActorID:       principal.UserID,
		ActorUsername: principal.Username,
		Action:        "roles.permissions.replace",
		Resource:      "roles",
		Outcome:       "allow",
		SourceIP:      sourceIP(r),
		Details: map[string]any{
			"roleID":        roleID,
			"permissionIDs": request.PermissionIDs,
		},
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
