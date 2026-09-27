package main

import (
	"net"
	"net/http"
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
func clientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
func rateLimitError(w http.ResponseWriter, message string) {
	jsonError(w, message, http.StatusTooManyRequests)
}
