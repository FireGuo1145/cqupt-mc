package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/draw"
	"image/png"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"gorm.io/gorm"
)

const (
	joinSessionTTL   = 30 * time.Second
	maxPendingJoins  = 10_000
	maxProfileBatch  = 100
	maxTextureSide   = 1024
	maxTexturePixels = 1 << 20
)

var profileIDRE = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

func writeYggError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":        code,
		"errorMessage": message,
	})
}

func yggMethodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeYggError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "Method not allowed.")
}

func decodeYggJSON(r *http.Request, dest any) error {
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(dest); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func bearerToken(r *http.Request) string {
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

func (a *app) loadSession(accessToken string) (*Session, bool) {
	if accessToken == "" || a.gormDB == nil {
		return nil, false
	}
	var session Session
	if err := a.gormDB.First(&session, "access_token = ?", accessToken).Error; err != nil {
		return nil, false
	}
	if !time.Now().Before(session.ExpiresAt) {
		_ = a.gormDB.Delete(&Session{}, "access_token = ?", accessToken).Error
		a.deleteCachedToken(accessToken)
		return nil, false
	}
	return &session, true
}

func randomAccessToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func randomClientUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return hex.EncodeToString(b), nil
}

func (a *app) checkYggMethod(r *http.Request, method string) bool {
	return r.Method == method
}

func (a *app) handleYggAuthenticate(w http.ResponseWriter, r *http.Request) {
	if !a.checkYggMethod(r, http.MethodPost) {
		yggMethodNotAllowed(w, http.MethodPost)
		return
	}
	if a.limiter != nil && !a.limiter.Allow("ygg:authenticate:ip:"+clientIP(r), 10, time.Minute) {
		writeYggError(w, http.StatusTooManyRequests, "TooManyRequestsException", "Login requests are temporarily rate limited.")
		return
	}
	var in yggLogin
	if decodeYggJSON(r, &in) != nil || in.Username == "" || in.Password == "" {
		writeYggError(w, http.StatusBadRequest, "IllegalArgumentException", "Invalid request.")
		return
	}
	if len(in.ClientToken) > 128 {
		writeYggError(w, http.StatusBadRequest, "IllegalArgumentException", "Invalid client token.")
		return
	}
	if a.db == nil {
		writeYggError(w, http.StatusInternalServerError, "InternalServerError", "Authentication service is unavailable.")
		return
	}
	var stored string
	var banned int
	if a.db.QueryRow("SELECT password_hash,banned FROM users WHERE username=?", in.Username).Scan(&stored, &banned) != nil || banned != 0 {
		writeYggError(w, http.StatusForbidden, "ForbiddenOperationException", "Invalid credentials. Invalid username or password.")
		return
	}
	ok, _ := verifyPassword(stored, in.Password)
	if !ok {
		writeYggError(w, http.StatusForbidden, "ForbiddenOperationException", "Invalid credentials. Invalid username or password.")
		return
	}

	clientToken := in.ClientToken
	if clientToken == "" {
		var err error
		clientToken, err = randomClientUUID()
		if err != nil {
			writeYggError(w, http.StatusInternalServerError, "InternalServerError", "Could not create a token.")
			return
		}
	}
	accessToken, err := randomAccessToken()
	if err != nil {
		writeYggError(w, http.StatusInternalServerError, "InternalServerError", "Could not create a token.")
		return
	}
	if err = a.saveToken(accessToken, clientToken, in.Username); err != nil {
		writeYggError(w, http.StatusInternalServerError, "InternalServerError", "Could not save the session.")
		return
	}
	a.setCachedToken(accessToken, in.Username)

	profile := map[string]string{"id": profileID(in.Username), "name": in.Username}
	result := map[string]any{
		"accessToken":       accessToken,
		"clientToken":       clientToken,
		"selectedProfile":   profile,
		"availableProfiles": []any{profile},
	}
	if in.RequestUser {
		result["user"] = map[string]any{"id": profile["id"], "properties": []any{}}
	}
	jsonOK(w, result)
}

func (a *app) handleYggRefresh(w http.ResponseWriter, r *http.Request) {
	if !a.checkYggMethod(r, http.MethodPost) {
		yggMethodNotAllowed(w, http.MethodPost)
		return
	}
	var in struct {
		AccessToken     string            `json:"accessToken"`
		ClientToken     string            `json:"clientToken"`
		SelectedProfile map[string]string `json:"selectedProfile"`
		RequestUser     bool              `json:"requestUser"`
	}
	if decodeYggJSON(r, &in) != nil || in.AccessToken == "" {
		writeYggError(w, http.StatusBadRequest, "IllegalArgumentException", "Invalid request.")
		return
	}
	if len(in.ClientToken) > 128 {
		writeYggError(w, http.StatusBadRequest, "IllegalArgumentException", "Invalid client token.")
		return
	}

	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()
	current, ok := a.loadSession(in.AccessToken)
	if !ok || (in.ClientToken != "" && in.ClientToken != current.ClientToken) {
		writeYggError(w, http.StatusForbidden, "ForbiddenOperationException", "Invalid token.")
		return
	}
	profile := map[string]string{"id": profileID(current.Username), "name": current.Username}
	if in.SelectedProfile != nil && (!strings.EqualFold(in.SelectedProfile["id"], profile["id"]) || in.SelectedProfile["name"] != profile["name"]) {
		writeYggError(w, http.StatusForbidden, "ForbiddenOperationException", "Selected profile does not belong to this token.")
		return
	}
	newAccessToken, err := randomAccessToken()
	if err != nil {
		writeYggError(w, http.StatusInternalServerError, "InternalServerError", "Could not create a token.")
		return
	}
	newSession := Session{
		AccessToken: newAccessToken,
		ClientToken: current.ClientToken,
		Username:    current.Username,
		ExpiresAt:   time.Now().Add(a.tokenTTL),
	}
	err = a.gormDB.Transaction(func(tx *gorm.DB) error {
		var stillCurrent Session
		if err := tx.First(&stillCurrent, "access_token = ?", in.AccessToken).Error; err != nil {
			return err
		}
		if stillCurrent.ClientToken != current.ClientToken || !time.Now().Before(stillCurrent.ExpiresAt) {
			return errors.New("token is no longer valid")
		}
		if err := tx.Create(&newSession).Error; err != nil {
			return err
		}
		deleted := tx.Delete(&Session{}, "access_token = ?", in.AccessToken)
		if deleted.Error != nil {
			return deleted.Error
		}
		if deleted.RowsAffected != 1 {
			return errors.New("token has already been refreshed")
		}
		return nil
	})
	if err != nil {
		writeYggError(w, http.StatusForbidden, "ForbiddenOperationException", "Invalid token.")
		return
	}
	a.deleteCachedToken(in.AccessToken)
	a.setCachedToken(newAccessToken, current.Username)

	result := map[string]any{
		"accessToken":     newAccessToken,
		"clientToken":     current.ClientToken,
		"selectedProfile": profile,
	}
	if in.RequestUser {
		result["user"] = map[string]any{"id": profile["id"], "properties": []any{}}
	}
	jsonOK(w, result)
}

func (a *app) handleYggValidate(w http.ResponseWriter, r *http.Request) {
	if !a.checkYggMethod(r, http.MethodPost) {
		yggMethodNotAllowed(w, http.MethodPost)
		return
	}
	var in struct {
		AccessToken string `json:"accessToken"`
		ClientToken string `json:"clientToken"`
	}
	if decodeYggJSON(r, &in) != nil {
		writeYggError(w, http.StatusBadRequest, "IllegalArgumentException", "Invalid request.")
		return
	}
	session, ok := a.loadSession(in.AccessToken)
	if !ok || (in.ClientToken != "" && session.ClientToken != in.ClientToken) {
		writeYggError(w, http.StatusForbidden, "ForbiddenOperationException", "Invalid token.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *app) handleYggInvalidate(w http.ResponseWriter, r *http.Request) {
	if !a.checkYggMethod(r, http.MethodPost) {
		yggMethodNotAllowed(w, http.MethodPost)
		return
	}
	var in struct {
		AccessToken string `json:"accessToken"`
	}
	if decodeYggJSON(r, &in) == nil && in.AccessToken != "" {
		a.deleteCachedToken(in.AccessToken)
		if a.gormDB != nil {
			_ = a.gormDB.Delete(&Session{}, "access_token = ?", in.AccessToken).Error
		}
	}
	// The protocol specifies 204 regardless of whether the token existed.
	w.WriteHeader(http.StatusNoContent)
}

func (a *app) handleYggSignout(w http.ResponseWriter, r *http.Request) {
	if !a.checkYggMethod(r, http.MethodPost) {
		yggMethodNotAllowed(w, http.MethodPost)
		return
	}
	if a.limiter != nil && !a.limiter.Allow("ygg:signout:ip:"+clientIP(r), 10, time.Minute) {
		writeYggError(w, http.StatusTooManyRequests, "TooManyRequestsException", "Signout requests are temporarily rate limited.")
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if decodeYggJSON(r, &in) != nil || in.Username == "" || in.Password == "" || a.db == nil {
		writeYggError(w, http.StatusBadRequest, "IllegalArgumentException", "Invalid request.")
		return
	}
	var stored string
	if a.db.QueryRow("SELECT password_hash FROM users WHERE username=?", in.Username).Scan(&stored) != nil {
		writeYggError(w, http.StatusForbidden, "ForbiddenOperationException", "Invalid credentials. Invalid username or password.")
		return
	}
	ok, _ := verifyPassword(stored, in.Password)
	if !ok {
		writeYggError(w, http.StatusForbidden, "ForbiddenOperationException", "Invalid credentials. Invalid username or password.")
		return
	}
	if a.gormDB != nil {
		if err := a.gormDB.Delete(&Session{}, "username = ?", in.Username).Error; err != nil {
			writeYggError(w, http.StatusInternalServerError, "InternalServerError", "Could not revoke sessions.")
			return
		}
	}
	a.tokensMu.Lock()
	for token, username := range a.tokens {
		if username == in.Username {
			delete(a.tokens, token)
		}
	}
	a.tokensMu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (a *app) handleYggJoin(w http.ResponseWriter, r *http.Request) {
	if !a.checkYggMethod(r, http.MethodPost) {
		yggMethodNotAllowed(w, http.MethodPost)
		return
	}
	var in struct {
		AccessToken     string `json:"accessToken"`
		SelectedProfile string `json:"selectedProfile"`
		ServerID        string `json:"serverId"`
	}
	if decodeYggJSON(r, &in) != nil || in.ServerID == "" || len(in.ServerID) > 1024 {
		writeYggError(w, http.StatusBadRequest, "IllegalArgumentException", "Invalid join request.")
		return
	}
	session, ok := a.loadSession(in.AccessToken)
	if !ok {
		writeYggError(w, http.StatusForbidden, "ForbiddenOperationException", "Invalid token.")
		return
	}
	if !strings.EqualFold(in.SelectedProfile, profileID(session.Username)) {
		writeYggError(w, http.StatusForbidden, "ForbiddenOperationException", "Invalid token.")
		return
	}
	clientIP := normalizedIP(clientIP(r))
	now := time.Now()
	a.joinedMu.Lock()
	if a.joined == nil {
		a.joined = make(map[string]pendingJoin)
	}
	if len(a.joined) >= maxPendingJoins {
		for id, pending := range a.joined {
			if !pending.expiresAt.After(now) {
				delete(a.joined, id)
			}
		}
	}
	if len(a.joined) >= maxPendingJoins {
		a.joinedMu.Unlock()
		writeYggError(w, http.StatusServiceUnavailable, "ServiceUnavailableException", "Too many pending join sessions.")
		return
	}
	a.joined[in.ServerID] = pendingJoin{username: session.Username, clientIP: clientIP, expiresAt: now.Add(joinSessionTTL)}
	a.joinedMu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (a *app) handleYggHasJoined(w http.ResponseWriter, r *http.Request) {
	if !a.checkYggMethod(r, http.MethodGet) {
		yggMethodNotAllowed(w, http.MethodGet)
		return
	}
	username := r.URL.Query().Get("username")
	serverID := r.URL.Query().Get("serverId")
	if username == "" || serverID == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	a.joinedMu.Lock()
	pending, ok := a.joined[serverID]
	if ok && !pending.expiresAt.After(time.Now()) {
		delete(a.joined, serverID)
		ok = false
	}
	clientIPQuery := r.URL.Query().Get("ip")
	matched := ok && pending.username == username
	if matched && clientIPQuery != "" {
		matched = normalizedIP(clientIPQuery) != "" && normalizedIP(clientIPQuery) == pending.clientIP
	}
	if matched {
		delete(a.joined, serverID)
	}
	a.joinedMu.Unlock()
	if !matched {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	jsonOK(w, a.profilePayload(r, username, true))
}

func normalizedIP(value string) string {
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	if ip := net.ParseIP(strings.TrimSpace(value)); ip != nil {
		return ip.String()
	}
	return ""
}

func (a *app) handleYggProfile(w http.ResponseWriter, r *http.Request) {
	if !a.checkYggMethod(r, http.MethodGet) {
		yggMethodNotAllowed(w, http.MethodGet)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/api/yggdrasil/sessionserver/session/minecraft/profile/")
	name = strings.TrimPrefix(name, "/sessionserver/session/minecraft/profile/")
	if name == "" || strings.Contains(name, "/") {
		http.NotFound(w, r)
		return
	}
	includeSignature := false // unsigned defaults to true in the specification.
	if raw := r.URL.Query().Get("unsigned"); raw != "" {
		switch raw {
		case "true":
			includeSignature = false
		case "false":
			includeSignature = true
		default:
			writeYggError(w, http.StatusBadRequest, "IllegalArgumentException", "unsigned must be true or false.")
			return
		}
	}
	username := ""
	if usernameRE.MatchString(name) && a.db != nil {
		if a.db.QueryRow("SELECT username FROM users WHERE username=?", name).Scan(&username) != nil {
			username = ""
		}
	}
	if username == "" && profileIDRE.MatchString(name) {
		username = a.usernameForProfileID(name)
	}
	if username == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	jsonOK(w, a.profilePayload(r, username, includeSignature))
}

func (a *app) usernameForProfileID(id string) string {
	if a.db == nil {
		return ""
	}
	rows, err := a.db.Query("SELECT username FROM users")
	if err != nil {
		return ""
	}
	defer rows.Close()
	for rows.Next() {
		var candidate string
		if rows.Scan(&candidate) == nil && strings.EqualFold(profileID(candidate), id) {
			return candidate
		}
	}
	return ""
}

func (a *app) handleYggBatchProfiles(w http.ResponseWriter, r *http.Request) {
	if !a.checkYggMethod(r, http.MethodPost) {
		yggMethodNotAllowed(w, http.MethodPost)
		return
	}
	var names []string
	if decodeYggJSON(r, &names) != nil || names == nil {
		writeYggError(w, http.StatusBadRequest, "IllegalArgumentException", "Invalid profile query.")
		return
	}
	if len(names) > maxProfileBatch {
		writeYggError(w, http.StatusBadRequest, "IllegalArgumentException", "A profile query may contain at most 100 names.")
		return
	}
	if len(names) == 0 {
		jsonOK(w, []any{})
		return
	}
	if a.gormDB == nil {
		writeYggError(w, http.StatusInternalServerError, "InternalServerError", "Profile service is unavailable.")
		return
	}
	var users []User
	if err := a.gormDB.Where("username IN ?", names).Find(&users).Error; err != nil {
		writeYggError(w, http.StatusInternalServerError, "InternalServerError", "Profile lookup failed.")
		return
	}
	profiles := make([]map[string]string, 0, len(users))
	for _, user := range users {
		profiles = append(profiles, map[string]string{"id": profileID(user.Username), "name": user.Username})
	}
	jsonOK(w, profiles)
}

func (a *app) handleYggTextureUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodDelete {
		yggMethodNotAllowed(w, "PUT, DELETE")
		return
	}
	username := a.userFromToken(r)
	if username == "" {
		writeYggError(w, http.StatusUnauthorized, "Unauthorized", "Invalid token.")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/yggdrasil/api/user/profile/")
	path = strings.TrimPrefix(path, "/api/user/profile/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != 2 || !profileIDRE.MatchString(parts[0]) || !strings.EqualFold(parts[0], profileID(username)) {
		writeYggError(w, http.StatusForbidden, "ForbiddenOperationException", "The profile does not belong to this token.")
		return
	}
	textureType := strings.ToLower(parts[1])
	if textureType != "skin" && textureType != "cape" {
		writeYggError(w, http.StatusBadRequest, "IllegalArgumentException", "Texture type must be skin or cape.")
		return
	}
	filename := "data/" + textureType + "s/" + username + ".png"
	if r.Method == http.MethodDelete {
		if err := os.Remove(filename); err != nil && !os.IsNotExist(err) {
			writeYggError(w, http.StatusInternalServerError, "InternalServerError", "Could not clear texture.")
			return
		}
		if textureType == "skin" {
			_ = os.Remove("data/skins/" + username + ".model")
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err := a.uploadYggTexture(w, r, username, textureType); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeYggError(w, http.StatusRequestEntityTooLarge, "IllegalArgumentException", "Texture upload exceeds 5 MiB.")
		} else {
			writeYggError(w, http.StatusBadRequest, "IllegalArgumentException", err.Error())
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *app) uploadYggTexture(w http.ResponseWriter, r *http.Request, username, textureType string) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxTextureUploadBodyBytes)
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/form-data" {
		return errors.New("Content-Type must be multipart/form-data.")
	}
	if err := r.ParseMultipartForm(maxImageUploadBytes); err != nil {
		return err
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		return errors.New("Missing texture file part.")
	}
	defer file.Close()
	partType, _, err := mime.ParseMediaType(header.Header.Get("Content-Type"))
	if err != nil || partType != "image/png" {
		return errors.New("Texture file Content-Type must be image/png.")
	}
	body, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	if len(body) == 0 || len(body) > maxImageUploadBytes {
		return errors.New("Invalid texture file size.")
	}

	var normalized []byte
	if textureType == "skin" {
		model := strings.TrimSpace(r.FormValue("model"))
		if model != "" && model != "slim" {
			return errors.New("Skin model must be slim or empty.")
		}
		normalized, err = normalizeSkinPNG(body)
		if err != nil {
			return err
		}
		if err = storeTexturePNG("data/skins", username, normalized); err != nil {
			return fmt.Errorf("could not save skin: %w", err)
		}
		if err = storeSkinModel(username, model); err != nil {
			return fmt.Errorf("could not save skin model: %w", err)
		}
		return nil
	}
	normalized, err = normalizeCapePNG(body)
	if err != nil {
		return err
	}
	if err = storeTexturePNG("data/capes", username, normalized); err != nil {
		return fmt.Errorf("could not save cape: %w", err)
	}
	return nil
}

func (a *app) handleCustomSkin(w http.ResponseWriter, r *http.Request) {
	username := a.userFromToken(r)
	if username == "" {
		jsonError(w, "未登录", http.StatusUnauthorized)
		return
	}
	if !usernameRE.MatchString(username) {
		jsonError(w, "账号名称无效", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodGet {
		body, err := readSafeTexturePNG("data/skins", username, "skin")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(body)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxImageUploadBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeCustomUploadError(w, err, "皮肤文件不能超过 5 MiB")
		return
	}
	normalized, err := normalizeSkinPNG(body)
	if err != nil {
		jsonError(w, "皮肤图片无效："+err.Error(), http.StatusBadRequest)
		return
	}
	if err = storeTexturePNG("data/skins", username, normalized); err != nil {
		jsonError(w, "保存失败", http.StatusInternalServerError)
		return
	}
	_ = os.Remove("data/skins/" + username + ".model")
	jsonOK(w, map[string]any{"ok": true})
}

func (a *app) handleCustomCape(w http.ResponseWriter, r *http.Request) {
	username := a.userFromToken(r)
	if username == "" {
		jsonError(w, "未登录", http.StatusUnauthorized)
		return
	}
	if !usernameRE.MatchString(username) {
		jsonError(w, "账号名称无效", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxImageUploadBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeCustomUploadError(w, err, "披风文件不能超过 5 MiB")
		return
	}
	normalized, err := normalizeCapePNG(body)
	if err != nil {
		jsonError(w, "披风图片无效："+err.Error(), http.StatusBadRequest)
		return
	}
	if err = storeTexturePNG("data/capes", username, normalized); err != nil {
		jsonError(w, "保存披风失败", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{"ok": true})
}

func writeCustomUploadError(w http.ResponseWriter, err error, tooLargeMessage string) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		jsonError(w, tooLargeMessage, http.StatusRequestEntityTooLarge)
		return
	}
	jsonError(w, "图片读取失败", http.StatusBadRequest)
}

func normalizeSkinPNG(raw []byte) ([]byte, error) {
	config, err := png.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		return nil, errors.New("invalid PNG image")
	}
	if config.Width < 64 || config.Height < 32 || config.Width%64 != 0 || config.Height%32 != 0 {
		return nil, errors.New("skin dimensions must be multiples of 64x32 or 64x64")
	}
	if config.Width > maxTextureSide || config.Height > maxTextureSide || int64(config.Width)*int64(config.Height) > maxTexturePixels {
		return nil, errors.New("skin dimensions are too large")
	}
	decoded, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, errors.New("corrupted PNG image")
	}
	var normalized bytes.Buffer
	if err = png.Encode(&normalized, decoded); err != nil {
		return nil, errors.New("could not normalize PNG image")
	}
	if normalized.Len() > maxImageUploadBytes {
		return nil, errors.New("normalized image exceeds 5 MiB")
	}
	return normalized.Bytes(), nil
}

func normalizeCapePNG(raw []byte) ([]byte, error) {
	config, err := png.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		return nil, errors.New("invalid PNG image")
	}
	standardSize := config.Width >= 64 && config.Height >= 32 && config.Width%64 == 0 && config.Height%32 == 0
	legacySize := config.Width >= 22 && config.Height >= 17 && config.Width%22 == 0 && config.Height%17 == 0
	if !standardSize && !legacySize {
		return nil, errors.New("cape dimensions must be multiples of 64x32 or 22x17")
	}
	if config.Width > maxTextureSide || config.Height > maxTextureSide || int64(config.Width)*int64(config.Height) > maxTexturePixels {
		return nil, errors.New("cape dimensions are too large")
	}
	decoded, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, errors.New("corrupted PNG image")
	}
	targetWidth := ((config.Width + 63) / 64) * 64
	targetHeight := ((config.Height + 31) / 32) * 32
	if targetWidth > maxTextureSide || targetHeight > maxTextureSide || int64(targetWidth)*int64(targetHeight) > maxTexturePixels {
		return nil, errors.New("normalized cape dimensions are too large")
	}
	normalizedImage := image.NewNRGBA(image.Rect(0, 0, targetWidth, targetHeight))
	draw.Draw(normalizedImage, decoded.Bounds(), decoded, decoded.Bounds().Min, draw.Src)
	var normalized bytes.Buffer
	if err = png.Encode(&normalized, normalizedImage); err != nil {
		return nil, errors.New("could not normalize PNG image")
	}
	if normalized.Len() > maxImageUploadBytes {
		return nil, errors.New("normalized image exceeds 5 MiB")
	}
	return normalized.Bytes(), nil
}

func storeTexturePNG(directory, username string, body []byte) error {
	if !usernameRE.MatchString(username) {
		return errors.New("invalid username")
	}
	if err := os.MkdirAll(directory, 0750); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".texture-*.tmp")
	if err != nil {
		return err
	}
	tmpName := file.Name()
	defer os.Remove(tmpName)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(body)
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(tmpName, directory+"/"+username+".png")
}

func readSafeTexturePNG(directory, username, textureType string) ([]byte, error) {
	if !usernameRE.MatchString(username) {
		return nil, errors.New("invalid username")
	}
	file, err := os.Open(directory + "/" + username + ".png")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxImageUploadBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > maxImageUploadBytes {
		return nil, errors.New("invalid stored texture size")
	}
	var normalized []byte
	switch textureType {
	case "skin":
		normalized, err = normalizeSkinPNG(raw)
	case "cape":
		normalized, err = normalizeCapePNG(raw)
	default:
		return nil, errors.New("invalid texture type")
	}
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(raw, normalized) {
		if err = storeTexturePNG(directory, username, normalized); err != nil {
			return nil, err
		}
	}
	return normalized, nil
}

func storeSkinModel(username, model string) error {
	path := "data/skins/" + username + ".model"
	if model == "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if model != "slim" || !usernameRE.MatchString(username) {
		return errors.New("invalid skin model")
	}
	return os.WriteFile(path, []byte(model), 0600)
}

func (a *app) profilePayload(r *http.Request, username string, includeSignature bool) map[string]any {
	base := "http://" + r.Host
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		base = proto + "://" + r.Host
	}
	textures := map[string]any{}
	if skin, err := readSafeTexturePNG("data/skins", username, "skin"); err == nil && len(skin) > 0 {
		sum := sha256.Sum256(skin)
		skinTexture := map[string]any{"url": base + "/api/yggdrasil/textures/" + hex.EncodeToString(sum[:])}
		if model, err := os.ReadFile("data/skins/" + username + ".model"); err == nil && strings.TrimSpace(string(model)) == "slim" {
			skinTexture["metadata"] = map[string]string{"model": "slim"}
		}
		textures["SKIN"] = skinTexture
	}
	if cape, err := readSafeTexturePNG("data/capes", username, "cape"); err == nil && len(cape) > 0 {
		sum := sha256.Sum256(cape)
		textures["CAPE"] = map[string]string{"url": base + "/api/yggdrasil/textures/" + hex.EncodeToString(sum[:])}
	}
	payload := map[string]any{
		"timestamp":   time.Now().UnixMilli(),
		"profileId":   profileID(username),
		"profileName": username,
		"textures":    textures,
	}
	encodedJSON, _ := json.Marshal(payload)
	value := base64.StdEncoding.EncodeToString(encodedJSON)
	property := map[string]string{"name": "textures", "value": value}
	if includeSignature && a.signingKey != nil {
		digest := sha1.Sum([]byte(value))
		if signature, err := rsa.SignPKCS1v15(rand.Reader, a.signingKey, crypto.SHA1, digest[:]); err == nil {
			property["signature"] = base64.StdEncoding.EncodeToString(signature)
		}
	}
	return map[string]any{
		"id":   profileID(username),
		"name": username,
		"properties": []any{
			property,
			map[string]string{"name": "uploadableTextures", "value": "skin,cape"},
		},
	}
}
