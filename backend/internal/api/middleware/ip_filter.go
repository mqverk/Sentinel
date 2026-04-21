package middleware

import (
	"net"
	"net/http"
	"strings"
)

func IPFilter(allowedCIDRs []string) func(http.Handler) http.Handler {
	if len(allowedCIDRs) == 0 {
		return func(next http.Handler) http.Handler { return next }
	}

	networks := make([]*net.IPNet, 0, len(allowedCIDRs))
	for _, cidr := range allowedCIDRs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err == nil {
			networks = append(networks, network)
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(networks) == 0 {
				http.Error(w, "ip policy is misconfigured", http.StatusForbidden)
				return
			}

			remoteIP := extractIP(r.RemoteAddr)
			if remoteIP == nil {
				http.Error(w, "unable to determine client ip", http.StatusForbidden)
				return
			}

			for _, network := range networks {
				if network.Contains(remoteIP) {
					next.ServeHTTP(w, r)
					return
				}
			}

			http.Error(w, "source ip not allowed", http.StatusForbidden)
		})
	}
}

func extractIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		host = strings.TrimSpace(remoteAddr)
	}

	return net.ParseIP(host)
}
