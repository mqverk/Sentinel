package middleware

import (
	"net"
	"net/http"
	"strings"
)

type IPFilter struct {
	nets []*net.IPNet
}

func NewIPFilter(cidrs []string) (*IPFilter, error) {
	parsed := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		trimmed := strings.TrimSpace(cidr)
		if trimmed == "" {
			continue
		}
		_, network, err := net.ParseCIDR(trimmed)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, network)
	}
	return &IPFilter{nets: parsed}, nil
}

func (f *IPFilter) Middleware() func(http.Handler) http.Handler {
	if len(f.nets) == 0 {
		return func(next http.Handler) http.Handler { return next }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ipText := clientIP(r)
			ip := net.ParseIP(strings.TrimSpace(ipText))
			if ip == nil {
				http.Error(w, "invalid source ip", http.StatusForbidden)
				return
			}
			for _, network := range f.nets {
				if network.Contains(ip) {
					next.ServeHTTP(w, r)
					return
				}
			}
			http.Error(w, "source ip not allowed", http.StatusForbidden)
		})
	}
}
