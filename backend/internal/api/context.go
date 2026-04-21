package api

import (
	"errors"
	"net"
	"net/http"
	"strings"

	"sentinel/backend/internal/auth"
)

func principalFromRequest(r *http.Request) (auth.Principal, error) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		return auth.Principal{}, errors.New("missing authenticated principal")
	}
	return principal, nil
}

func sourceIP(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
