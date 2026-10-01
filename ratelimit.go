package main

import (
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type rateWindow struct {
	started time.Time
	count   int
}
type RateLimiter struct {
	mu      sync.Mutex
	windows map[string]rateWindow
}

func NewRateLimiter() *RateLimiter { return &RateLimiter{windows: make(map[string]rateWindow)} }
func (l *RateLimiter) Allow(key string, limit int, window time.Duration) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.windows) > 10000 {
		for k, v := range l.windows {
			if now.Sub(v.started) >= window {
				delete(l.windows, k)
			}
		}
	}
	current, ok := l.windows[key]
	if !ok || now.Sub(current.started) >= window {
		l.windows[key] = rateWindow{started: now, count: 1}
		return true
	}
	if current.count >= limit {
		return false
	}
	current.count++
	l.windows[key] = current
	return true
}

// clientIP uses the network peer address unless that peer belongs to a
// TRUSTED_PROXY_CIDRS range. Only then is the X-Forwarded-For chain consulted.
// Walk from right to left and stop at the first untrusted hop, so a client
// cannot spoof the rate-limit key by prepending an arbitrary forwarded address.
func clientIP(r *http.Request) string {
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = r.RemoteAddr
	}
	remoteIP := net.ParseIP(strings.Trim(remoteHost, "[]"))
	if remoteIP == nil {
		return remoteHost
	}

	trusted := trustedProxyCIDRs()
	if !ipInNetworks(remoteIP, trusted) {
		return remoteIP.String()
	}
	forwarded := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	current := remoteIP
	for i := len(forwarded) - 1; i >= 0 && ipInNetworks(current, trusted); i-- {
		candidate := net.ParseIP(strings.TrimSpace(forwarded[i]))
		if candidate == nil {
			break
		}
		current = candidate
	}
	return current.String()
}

func trustedProxyCIDRs() []*net.IPNet {
	var networks []*net.IPNet
	for _, raw := range strings.Split(os.Getenv("TRUSTED_PROXY_CIDRS"), ",") {
		if _, network, err := net.ParseCIDR(strings.TrimSpace(raw)); err == nil {
			networks = append(networks, network)
		}
	}
	return networks
}

func ipInNetworks(ip net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func rateLimitError(w http.ResponseWriter, message string) {
	jsonError(w, message, http.StatusTooManyRequests)
}
