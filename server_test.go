package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
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

func testPNG(t *testing.T, width, height int) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, width, height))); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestCapeUploadValidatesAndPubliclyServesCape(t *testing.T) {
	t.Chdir(t.TempDir())
	a := &app{tokens: make(map[string]string)}
	a.setCachedToken("test-token", "CapePlayer")

	badRequest := httptest.NewRequest(http.MethodPost, "/api/cape", bytes.NewReader(testPNG(t, 128, 64)))
	badRequest.Header.Set("Authorization", "Bearer test-token")
	badResponse := httptest.NewRecorder()
	a.cape(badResponse, badRequest)
	if badResponse.Code != http.StatusBadRequest {
		t.Fatalf("invalid dimensions status = %d, want %d", badResponse.Code, http.StatusBadRequest)
	}
	if _, err := os.Stat("data/capes/CapePlayer.png"); !os.IsNotExist(err) {
		t.Fatalf("invalid cape should not be stored, stat error = %v", err)
	}

	validRequest := httptest.NewRequest(http.MethodPost, "/api/cape", bytes.NewReader(testPNG(t, 64, 32)))
	validRequest.Header.Set("Authorization", "Bearer test-token")
	validResponse := httptest.NewRecorder()
	a.cape(validResponse, validRequest)
	if validResponse.Code != http.StatusOK {
		t.Fatalf("valid upload status = %d, body = %s", validResponse.Code, validResponse.Body.String())
	}

	publicRequest := httptest.NewRequest(http.MethodGet, "/api/cape/CapePlayer", nil)
	publicResponse := httptest.NewRecorder()
	a.publicCape(publicResponse, publicRequest)
	if publicResponse.Code != http.StatusOK {
		t.Fatalf("public cape status = %d", publicResponse.Code)
	}
	config, err := png.DecodeConfig(bytes.NewReader(publicResponse.Body.Bytes()))
	if err != nil || config.Width != 64 || config.Height != 32 {
		t.Fatalf("served cape config = %#v, error = %v", config, err)
	}
}

func TestProfileResponseIncludesCapeTexture(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.MkdirAll("data/capes", 0750); err != nil {
		t.Fatal(err)
	}
	cape := testPNG(t, 64, 32)
	if err := os.WriteFile("data/capes/CapePlayer.png", cape, 0600); err != nil {
		t.Fatal(err)
	}

	a := &app{}
	req := httptest.NewRequest(http.MethodGet, "http://mc.example/sessionserver/profile", nil)
	response := a.profileResponse(req, "CapePlayer")
	properties := response["properties"].([]any)
	texturesProperty := properties[0].(map[string]string)
	encoded, err := base64.StdEncoding.DecodeString(texturesProperty["value"])
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Textures map[string]map[string]string `json:"textures"`
	}
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatal(err)
	}
	capeTexture := payload.Textures["CAPE"]
	if capeTexture["url"] == "" {
		t.Fatal("Yggdrasil profile did not include a CAPE URL")
	}

	textureRequest := httptest.NewRequest(http.MethodGet, capeTexture["url"], nil)
	textureResponse := httptest.NewRecorder()
	a.texture(textureResponse, textureRequest)
	if textureResponse.Code != http.StatusOK {
		t.Fatalf("hashed cape texture status = %d, url = %s", textureResponse.Code, capeTexture["url"])
	}
}
