package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"

	"sentinel/backend/internal/audit"
	"sentinel/backend/internal/domain"
	"sentinel/backend/internal/store"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrDisabledAccount    = errors.New("account is disabled")
)

type Service struct {
	store          store.Store
	tokens         *Manager
	audit          *audit.Service
	passwordMinLen int
}

func NewService(st store.Store, tokens *Manager, auditSvc *audit.Service, passwordMinLen int) *Service {
	if passwordMinLen <= 0 {
		passwordMinLen = 14
	}

	return &Service{
		store:          st,
		tokens:         tokens,
		audit:          auditSvc,
		passwordMinLen: passwordMinLen,
	}
}

func (s *Service) AuthenticatePassword(ctx context.Context, username, password string) (domain.User, []domain.Role, error) {
	user, err := s.store.GetUserByUsername(ctx, strings.TrimSpace(username))
	if err != nil {
		return domain.User{}, nil, ErrInvalidCredentials
	}

	if user.Disabled {
		return domain.User{}, nil, ErrDisabledAccount
	}

	if err := ComparePassword(user.PasswordHash, password); err != nil {
		return domain.User{}, nil, ErrInvalidCredentials
	}

	roles, err := s.store.ListUserRoles(ctx, user.ID)
	if err != nil {
		return domain.User{}, nil, err
	}

	return user, roles, nil
}

func (s *Service) Login(ctx context.Context, username, password, sourceIP string) (string, domain.UserSafe, error) {
	user, roles, err := s.AuthenticatePassword(ctx, username, password)
	if err != nil {
		_ = s.audit.Record(ctx, audit.NewEntry(
			"",
			username,
			"auth.login",
			"user",
			"denied",
			sourceIP,
			map[string]any{"reason": err.Error()},
		))
		return "", domain.UserSafe{}, err
	}

	roleNames := make([]string, 0, len(roles))
	for _, role := range roles {
		roleNames = append(roleNames, role.Name)
	}

	token, err := s.tokens.IssueToken(user.ID, user.Username, roleNames)
	if err != nil {
		return "", domain.UserSafe{}, err
	}

	_ = s.audit.Record(ctx, audit.NewEntry(
		user.ID,
		user.Username,
		"auth.login",
		"user",
		"success",
		sourceIP,
		nil,
	))

	safe := user.Safe()
	safe.Roles = roles
	return token, safe, nil
}

func (s *Service) ValidatePassword(password string) error {
	if utf8.RuneCountInString(password) < s.passwordMinLen {
		return fmt.Errorf("password must be at least %d characters", s.passwordMinLen)
	}

	return nil
}

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func ComparePassword(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
