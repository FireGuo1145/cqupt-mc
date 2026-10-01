package main

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestConcurrentTokenCacheAccess(t *testing.T) {
	a := &app{tokens: make(map[string]string)}
	const workers = 32
	const iterations = 1000

	var wg sync.WaitGroup
	wg.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				token := string(rune('a' + worker))
				a.setCachedToken(token, "user")
				_ = a.cachedToken(token)
				if i%3 == 0 {
					a.deleteCachedToken(token)
				}
			}
			_ = a.cachedToken(string(rune('a' + worker)))
		}(worker)
	}
	wg.Wait()
}

func TestClientIPIgnoresForwardedHeaderFromUntrustedPeer(t *testing.T) {
	t.Setenv("TRUSTED_PROXY_CIDRS", "192.0.2.0/24")
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "198.51.100.42:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")

	if got, want := clientIP(r), "198.51.100.42"; got != want {
		t.Fatalf("clientIP() = %q, want %q", got, want)
	}
}

func TestClientIPFindsFirstUntrustedForwardedHop(t *testing.T) {
	t.Setenv("TRUSTED_PROXY_CIDRS", "10.0.0.0/8")
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.3:443"
	r.Header.Set("X-Forwarded-For", "198.51.100.42, 10.0.0.2")

	if got, want := clientIP(r), "198.51.100.42"; got != want {
		t.Fatalf("clientIP() = %q, want %q", got, want)
	}
}

func TestYggAuthenticateRateLimitUsesPeerIP(t *testing.T) {
	t.Setenv("TRUSTED_PROXY_CIDRS", "")
	a := &app{limiter: NewRateLimiter()}

	for i := 0; i < 11; i++ {
		req := httptest.NewRequest(http.MethodPost, "/authserver/authenticate", strings.NewReader("{"))
		req.RemoteAddr = "198.51.100.20:1234"
		req.Header.Set("X-Forwarded-For", "203.0.113."+strconv.Itoa(i+1))
		rec := httptest.NewRecorder()
		a.yggAuthenticate(rec, req)

		want := http.StatusBadRequest
		if i == 10 {
			want = http.StatusTooManyRequests
		}
		if rec.Code != want {
			t.Fatalf("attempt %d status = %d, want %d", i+1, rec.Code, want)
		}
	}
}

func TestRequestBodyLimitRejectsOversizedDeclaredBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(strings.Repeat("x", (1<<20)+1)))
	rec := httptest.NewRecorder()
	handlerCalled := false
	handler := withRequestBodyLimit(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		handlerCalled = true
	}))
	handler.ServeHTTP(rec, req)

	if handlerCalled {
		t.Fatal("handler should not receive a body larger than 1 MiB")
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
}
