package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"strings"
	"testing"
	"time"

	glebarezsqlite "github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newProtocolTestApp(t *testing.T) *app {
	t.Helper()
	dsn := "file:ygg-test-" + strings.ReplaceAll(t.Name(), "/", "_") + "?mode=memory&cache=shared"
	gdb, err := gorm.Open(glebarezsqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	db, err := gdb.DB()
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if err = gdb.AutoMigrate(&User{}, &Session{}, &ManualRegistration{}); err != nil {
		t.Fatal(err)
	}
	if err = migrateUsernameKeys(gdb); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &app{
		db:         db,
		gormDB:     gdb,
		tokens:     make(map[string]string),
		challenges: make(map[string]*captchaChallenge),
		tokenTTL:   time.Hour,
		limiter:    NewRateLimiter(),
	}
}

func addProtocolTestUser(t *testing.T, a *app, username, password string) {
	t.Helper()
	hash, err := hashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.gormDB.Create(&User{StudentID: "student-" + username, Username: username, PasswordHash: hash}).Error; err != nil {
		t.Fatal(err)
	}
}

func addProtocolTestSession(t *testing.T, a *app, accessToken, clientToken, username string) {
	t.Helper()
	session := Session{AccessToken: accessToken, ClientToken: clientToken, Username: username, ExpiresAt: time.Now().Add(time.Hour)}
	if err := a.gormDB.Create(&session).Error; err != nil {
		t.Fatal(err)
	}
	a.setCachedToken(accessToken, username)
}

func jsonRequest(t *testing.T, method, target string, value any) *http.Request {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.10:5000"
	return req
}

func TestYggAuthenticateIssuesIndependentAccessToken(t *testing.T) {
	a := newProtocolTestApp(t)
	addProtocolTestUser(t, a, "AuthPlayer", "secret")
	request := jsonRequest(t, http.MethodPost, "/authserver/authenticate", map[string]any{
		"username": "AuthPlayer", "password": "secret", "clientToken": "client-supplied-token", "requestUser": true,
	})
	response := httptest.NewRecorder()
	a.yggAuthenticate(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("authenticate status = %d, body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		AccessToken string `json:"accessToken"`
		ClientToken string `json:"clientToken"`
		User        any    `json:"user"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.AccessToken == "" || payload.AccessToken == payload.ClientToken || payload.ClientToken != "client-supplied-token" {
		t.Fatalf("tokens not correctly separated: %#v", payload)
	}
	if payload.User == nil {
		t.Fatal("requestUser=true must include user information")
	}
	if _, ok := a.loadSession(payload.AccessToken); !ok {
		t.Fatal("new access token was not persisted")
	}
}

func TestYggRefreshRotatesAndValidatesClientToken(t *testing.T) {
	a := newProtocolTestApp(t)
	addProtocolTestUser(t, a, "RefreshPlayer", "secret")
	addProtocolTestSession(t, a, "old-access", "client-id", "RefreshPlayer")

	wrong := jsonRequest(t, http.MethodPost, "/authserver/refresh", map[string]string{
		"accessToken": "old-access", "clientToken": "wrong-client",
	})
	wrongResponse := httptest.NewRecorder()
	a.yggRefresh(wrongResponse, wrong)
	if wrongResponse.Code != http.StatusForbidden {
		t.Fatalf("wrong clientToken status = %d, want 403", wrongResponse.Code)
	}
	if _, ok := a.loadSession("old-access"); !ok {
		t.Fatal("failed refresh must leave the original token valid")
	}

	request := jsonRequest(t, http.MethodPost, "/authserver/refresh", map[string]string{
		"accessToken": "old-access", "clientToken": "client-id",
	})
	response := httptest.NewRecorder()
	a.yggRefresh(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("refresh status = %d, body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		AccessToken string `json:"accessToken"`
		ClientToken string `json:"clientToken"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.AccessToken == "old-access" || payload.ClientToken != "client-id" {
		t.Fatalf("refresh did not rotate access token and preserve client token: %#v", payload)
	}
	if _, ok := a.loadSession("old-access"); ok {
		t.Fatal("old access token remained valid after refresh")
	}
	if session, ok := a.loadSession(payload.AccessToken); !ok || session.ClientToken != "client-id" {
		t.Fatal("new access token was not persisted with the original client token")
	}
}

func TestYggValidateReadsJSONAndChecksOptionalClientToken(t *testing.T) {
	a := newProtocolTestApp(t)
	addProtocolTestSession(t, a, "valid-access", "client-id", "ValidatePlayer")

	valid := jsonRequest(t, http.MethodPost, "/authserver/validate", map[string]string{"accessToken": "valid-access", "clientToken": "client-id"})
	validResponse := httptest.NewRecorder()
	a.yggValidate(validResponse, valid)
	if validResponse.Code != http.StatusNoContent {
		t.Fatalf("valid token status = %d, want 204", validResponse.Code)
	}

	invalid := jsonRequest(t, http.MethodPost, "/authserver/validate", map[string]string{"accessToken": "valid-access", "clientToken": "other"})
	invalidResponse := httptest.NewRecorder()
	a.yggValidate(invalidResponse, invalid)
	if invalidResponse.Code != http.StatusForbidden {
		t.Fatalf("invalid clientToken status = %d, want 403", invalidResponse.Code)
	}
	var errPayload map[string]string
	if err := json.Unmarshal(invalidResponse.Body.Bytes(), &errPayload); err != nil || errPayload["error"] != "ForbiddenOperationException" || errPayload["errorMessage"] == "" {
		t.Fatalf("invalid token error payload is not protocol-shaped: %s", invalidResponse.Body.String())
	}
}

func TestYggSignoutRevokesAllUserSessions(t *testing.T) {
	a := newProtocolTestApp(t)
	addProtocolTestUser(t, a, "SignoutPlayer", "secret")
	addProtocolTestSession(t, a, "access-one", "client-one", "SignoutPlayer")
	addProtocolTestSession(t, a, "access-two", "client-two", "SignoutPlayer")

	request := jsonRequest(t, http.MethodPost, "/authserver/signout", map[string]string{"username": "SignoutPlayer", "password": "secret"})
	response := httptest.NewRecorder()
	a.yggSignout(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("signout status = %d, body=%s", response.Code, response.Body.String())
	}
	var count int64
	if err := a.gormDB.Model(&Session{}).Where("username = ?", "SignoutPlayer").Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("sessions remaining after signout = %d, err=%v", count, err)
	}
	if a.tokenUser("access-one") != "" || a.tokenUser("access-two") != "" {
		t.Fatal("signout left a user token valid")
	}
}

func TestYggJoinRequiresMatchingSessionAndIP(t *testing.T) {
	a := newProtocolTestApp(t)
	addProtocolTestUser(t, a, "JoinPlayer", "secret")
	addProtocolTestSession(t, a, "join-access", "join-client", "JoinPlayer")

	join := func(serverID, selectedProfile string) *httptest.ResponseRecorder {
		request := jsonRequest(t, http.MethodPost, "/sessionserver/session/minecraft/join", map[string]string{
			"accessToken": "join-access", "selectedProfile": selectedProfile, "serverId": serverID,
		})
		response := httptest.NewRecorder()
		a.yggJoin(response, request)
		return response
	}
	if response := join("server-hash", "not-the-profile"); response.Code != http.StatusForbidden {
		t.Fatalf("mismatched profile status = %d, want 403", response.Code)
	}
	if response := join("server-hash", profileID("JoinPlayer")); response.Code != http.StatusNoContent {
		t.Fatalf("valid join status = %d, want 204", response.Code)
	}

	wrongServer := httptest.NewRequest(http.MethodGet, "/sessionserver/session/minecraft/hasJoined?username=JoinPlayer&serverId=wrong", nil)
	wrongServerResponse := httptest.NewRecorder()
	a.yggHasJoined(wrongServerResponse, wrongServer)
	if wrongServerResponse.Code != http.StatusNoContent {
		t.Fatalf("unknown serverId status = %d, want 204", wrongServerResponse.Code)
	}
	wrongIP := httptest.NewRequest(http.MethodGet, "/sessionserver/session/minecraft/hasJoined?username=JoinPlayer&serverId=server-hash&ip=198.51.100.4", nil)
	wrongIPResponse := httptest.NewRecorder()
	a.yggHasJoined(wrongIPResponse, wrongIP)
	if wrongIPResponse.Code != http.StatusNoContent {
		t.Fatalf("mismatched IP status = %d, want 204", wrongIPResponse.Code)
	}
	valid := httptest.NewRequest(http.MethodGet, "/sessionserver/session/minecraft/hasJoined?username=JoinPlayer&serverId=server-hash&ip=192.0.2.10", nil)
	validResponse := httptest.NewRecorder()
	a.yggHasJoined(validResponse, valid)
	if validResponse.Code != http.StatusOK {
		t.Fatalf("valid hasJoined status = %d, body=%s", validResponse.Code, validResponse.Body.String())
	}
	replay := httptest.NewRecorder()
	a.yggHasJoined(replay, valid)
	if replay.Code != http.StatusNoContent {
		t.Fatalf("replayed hasJoined status = %d, want 204", replay.Code)
	}
}

func TestYggProfileUnsignedAndBatchQuery(t *testing.T) {
	a := newProtocolTestApp(t)
	addProtocolTestUser(t, a, "ProfilePlayer", "secret")
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	a.signingKey = key

	profileURL := "/sessionserver/session/minecraft/profile/" + profileID("ProfilePlayer")
	unsigned := httptest.NewRequest(http.MethodGet, profileURL, nil)
	unsignedResponse := httptest.NewRecorder()
	a.yggProfile(unsignedResponse, unsigned)
	if unsignedResponse.Code != http.StatusOK {
		t.Fatalf("default unsigned profile status = %d", unsignedResponse.Code)
	}
	var unsignedPayload struct {
		Properties []map[string]string `json:"properties"`
	}
	if err := json.Unmarshal(unsignedResponse.Body.Bytes(), &unsignedPayload); err != nil {
		t.Fatal(err)
	}
	if len(unsignedPayload.Properties) == 0 || unsignedPayload.Properties[0]["signature"] != "" {
		t.Fatal("unsigned=true by default must omit the signature")
	}

	signed := httptest.NewRequest(http.MethodGet, profileURL+"?unsigned=false", nil)
	signedResponse := httptest.NewRecorder()
	a.yggProfile(signedResponse, signed)
	var signedPayload struct {
		Properties []map[string]string `json:"properties"`
	}
	if err := json.Unmarshal(signedResponse.Body.Bytes(), &signedPayload); err != nil {
		t.Fatal(err)
	}
	if len(signedPayload.Properties) == 0 || signedPayload.Properties[0]["signature"] == "" {
		t.Fatal("unsigned=false must include a texture signature")
	}

	missing := httptest.NewRequest(http.MethodGet, "/sessionserver/session/minecraft/profile/00000000000000000000000000000000", nil)
	missingResponse := httptest.NewRecorder()
	a.yggProfile(missingResponse, missing)
	if missingResponse.Code != http.StatusNoContent {
		t.Fatalf("missing profile status = %d, want 204", missingResponse.Code)
	}

	batch := jsonRequest(t, http.MethodPost, "/api/profiles/minecraft", []string{"ProfilePlayer", "MissingPlayer"})
	batchResponse := httptest.NewRecorder()
	a.handleYggBatchProfiles(batchResponse, batch)
	if batchResponse.Code != http.StatusOK {
		t.Fatalf("batch query status = %d, body=%s", batchResponse.Code, batchResponse.Body.String())
	}
	var profiles []map[string]any
	if err := json.Unmarshal(batchResponse.Body.Bytes(), &profiles); err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 || profiles[0]["name"] != "ProfilePlayer" || profiles[0]["properties"] != nil {
		t.Fatalf("unexpected batch profile response: %#v", profiles)
	}
}

func multipartPNGRequest(t *testing.T, method, target, accessToken, model string, imageBytes []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if model != "" {
		if err := writer.WriteField("model", model); err != nil {
			t.Fatal(err)
		}
	}
	header := make(textproto.MIMEHeader)
	header.Set("Content-Disposition", `form-data; name="file"; filename="texture.png"`)
	header.Set("Content-Type", "image/png")
	part, err := writer.CreatePart(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = part.Write(imageBytes); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(method, target, &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.RemoteAddr = "192.0.2.10:5000"
	return request
}

func pngWithTextChunk(t *testing.T, width, height int, text string) []byte {
	t.Helper()
	original := testPNG(t, width, height)
	data := []byte("Comment\x00" + text)
	var chunk bytes.Buffer
	if err := binary.Write(&chunk, binary.BigEndian, uint32(len(data))); err != nil {
		t.Fatal(err)
	}
	chunk.WriteString("tEXt")
	chunk.Write(data)
	crcInput := append([]byte("tEXt"), data...)
	if err := binary.Write(&chunk, binary.BigEndian, crc32.ChecksumIEEE(crcInput)); err != nil {
		t.Fatal(err)
	}
	// PNG signature (8 bytes) followed by the 25-byte IHDR chunk.
	return append(append(append([]byte{}, original[:33]...), chunk.Bytes()...), original[33:]...)
}

func TestStandardTextureAPIValidatesSanitizesStoresAndDeletes(t *testing.T) {
	t.Chdir(t.TempDir())
	a := newProtocolTestApp(t)
	addProtocolTestUser(t, a, "TexturePlayer", "secret")
	addProtocolTestSession(t, a, "texture-access", "texture-client", "TexturePlayer")
	profile := profileID("TexturePlayer")

	if err := os.MkdirAll("data/skins", 0750); err != nil {
		t.Fatal(err)
	}
	legacyPNG := pngWithTextChunk(t, 64, 64, "old-metadata-secret")
	if err := os.WriteFile("data/skins/LegacyPlayer.png", legacyPNG, 0600); err != nil {
		t.Fatal(err)
	}
	_ = a.profilePayload(httptest.NewRequest(http.MethodGet, "http://skin.example/profile", nil), "LegacyPlayer", false)
	legacyStored, err := os.ReadFile("data/skins/LegacyPlayer.png")
	if err != nil || bytes.Contains(legacyStored, []byte("old-metadata-secret")) {
		t.Fatalf("legacy stored texture was not sanitized: err=%v", err)
	}

	skinBytes := pngWithTextChunk(t, 64, 64, "metadata-secret")
	skinRequest := multipartPNGRequest(t, http.MethodPut, "/api/user/profile/"+profile+"/skin", "texture-access", "slim", skinBytes)
	skinResponse := httptest.NewRecorder()
	a.handleYggTextureUpload(skinResponse, skinRequest)
	if skinResponse.Code != http.StatusNoContent {
		t.Fatalf("skin PUT status = %d, body=%s", skinResponse.Code, skinResponse.Body.String())
	}
	storedSkin, err := os.ReadFile("data/skins/TexturePlayer.png")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(storedSkin, []byte("metadata-secret")) {
		t.Fatal("PNG ancillary text metadata was not stripped")
	}
	config, err := png.DecodeConfig(bytes.NewReader(storedSkin))
	if err != nil || config.Width != 64 || config.Height != 64 {
		t.Fatalf("stored skin config = %#v, err=%v", config, err)
	}
	if model, err := os.ReadFile("data/skins/TexturePlayer.model"); err != nil || string(model) != "slim" {
		t.Fatalf("skin model not stored: model=%q err=%v", model, err)
	}
	profilePayload := a.profilePayload(httptest.NewRequest(http.MethodGet, "http://skin.example/profile", nil), "TexturePlayer", false)
	properties := profilePayload["properties"].([]any)
	textureProperty := properties[0].(map[string]string)
	decoded, err := base64.StdEncoding.DecodeString(textureProperty["value"])
	if err != nil {
		t.Fatal(err)
	}
	var textureData struct {
		Textures map[string]struct {
			Metadata map[string]string `json:"metadata"`
		} `json:"textures"`
	}
	if err = json.Unmarshal(decoded, &textureData); err != nil {
		t.Fatal(err)
	}
	if textureData.Textures["SKIN"].Metadata["model"] != "slim" {
		t.Fatalf("slim model missing from profile texture metadata: %#v", textureData.Textures)
	}

	capeBytes := testPNG(t, 22, 17)
	capeRequest := multipartPNGRequest(t, http.MethodPut, "/api/yggdrasil/api/user/profile/"+profile+"/cape", "texture-access", "", capeBytes)
	capeResponse := httptest.NewRecorder()
	a.handleYggTextureUpload(capeResponse, capeRequest)
	if capeResponse.Code != http.StatusNoContent {
		t.Fatalf("legacy-size cape PUT status = %d, body=%s", capeResponse.Code, capeResponse.Body.String())
	}
	storedCape, err := os.ReadFile("data/capes/TexturePlayer.png")
	if err != nil {
		t.Fatal(err)
	}
	config, err = png.DecodeConfig(bytes.NewReader(storedCape))
	if err != nil || config.Width != 64 || config.Height != 32 {
		t.Fatalf("normalized legacy cape config = %#v, err=%v", config, err)
	}

	deleteRequest := httptest.NewRequest(http.MethodDelete, "/api/user/profile/"+profile+"/skin", nil)
	deleteRequest.Header.Set("Authorization", "Bearer texture-access")
	deleteResponse := httptest.NewRecorder()
	a.handleYggTextureUpload(deleteResponse, deleteRequest)
	if deleteResponse.Code != http.StatusNoContent {
		t.Fatalf("skin DELETE status = %d, body=%s", deleteResponse.Code, deleteResponse.Body.String())
	}
	if _, err := os.Stat("data/skins/TexturePlayer.png"); !os.IsNotExist(err) {
		t.Fatalf("skin still exists after DELETE: %v", err)
	}
	if _, err := os.Stat("data/skins/TexturePlayer.model"); !os.IsNotExist(err) {
		t.Fatalf("skin model still exists after DELETE: %v", err)
	}
}

func TestTextureAPIRejectsWrongProfileAndMalformedImages(t *testing.T) {
	t.Chdir(t.TempDir())
	a := newProtocolTestApp(t)
	addProtocolTestUser(t, a, "TextureOwner", "secret")
	addProtocolTestSession(t, a, "owner-access", "owner-client", "TextureOwner")

	wrongProfile := multipartPNGRequest(t, http.MethodPut, "/api/user/profile/00000000000000000000000000000000/skin", "owner-access", "", testPNG(t, 64, 64))
	wrongProfileResponse := httptest.NewRecorder()
	a.handleYggTextureUpload(wrongProfileResponse, wrongProfile)
	if wrongProfileResponse.Code != http.StatusForbidden {
		t.Fatalf("another profile upload status = %d, want 403", wrongProfileResponse.Code)
	}

	badSkin := multipartPNGRequest(t, http.MethodPut, "/api/user/profile/"+profileID("TextureOwner")+"/skin", "owner-access", "", testPNG(t, 65, 31))
	badSkinResponse := httptest.NewRecorder()
	a.handleYggTextureUpload(badSkinResponse, badSkin)
	if badSkinResponse.Code != http.StatusBadRequest {
		t.Fatalf("invalid skin dimensions status = %d, want 400", badSkinResponse.Code)
	}
}
