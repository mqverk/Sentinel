package middleware

import (
	"net/http"
	"strings"

	"sentinel/backend/internal/auth"
)

func Authenticate(authService *auth.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authorization := strings.TrimSpace(r.Header.Get("Authorization"))
			if authorization == "" || !strings.HasPrefix(strings.ToLower(authorization), "bearer ") {
				http.Error(w, "missing bearer token", http.StatusUnauthorized)
				return
			}
			token := strings.TrimSpace(authorization[len("Bearer "):])
			principal, err := authService.VerifyToken(token)
			if err != nil {
				http.Error(w, "invalid bearer token", http.StatusUnauthorized)
				return
			}

			ctx := auth.ContextWithPrincipal(r.Context(), principal)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
