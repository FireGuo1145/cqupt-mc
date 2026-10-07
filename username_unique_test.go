package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	glebarezsqlite "github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestRegisterRejectsCaseInsensitiveDuplicateBeforeCAS(t *testing.T) {
	a := newProtocolTestApp(t)
	addProtocolTestUser(t, a, "ExistingPlayer", "old-password")
	calls := 0
	a.casProbe = func(string, string, string, *captchaChallenge) (string, *captchaChallenge, error) {
		calls++
		return "credentials-correct", nil, nil
	}
	request := jsonRequest(t, http.MethodPost, "/api/register", map[string]string{
		"studentId": "2026100701", "studentPassword": "cas-password",
		"username": "existingplayer", "password": "new-site-password",
	})
	response := httptest.NewRecorder()
	a.register(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("case-insensitive duplicate registration status=%d, want 409: %s", response.Code, response.Body.String())
	}
	if calls != 0 {
		t.Fatalf("CAS was called %d times for a duplicate username; duplicate must be rejected first", calls)
	}
	if !strings.Contains(response.Body.String(), "大小写") {
		t.Fatalf("duplicate error should explain case-insensitive matching: %s", response.Body.String())
	}
	manual := jsonRequest(t, http.MethodPost, "/api/manual-registration", map[string]string{
		"studentId": "2026100708", "username": "PendingName", "password": "site-password", "confirmPassword": "site-password",
	})
	manualResponse := httptest.NewRecorder()
	a.manualRegister(manualResponse, manual)
	if manualResponse.Code != http.StatusAccepted {
		t.Fatalf("manual application setup status=%d body=%s", manualResponse.Code, manualResponse.Body.String())
	}
	pendingDuplicate := jsonRequest(t, http.MethodPost, "/api/register", map[string]string{
		"studentId": "2026100709", "studentPassword": "cas-password",
		"username": "pendingname", "password": "new-site-password",
	})
	pendingResponse := httptest.NewRecorder()
	a.register(pendingResponse, pendingDuplicate)
	if pendingResponse.Code != http.StatusConflict || calls != 0 {
		t.Fatalf("pending case-insensitive duplicate should be rejected before CAS: status=%d calls=%d body=%s", pendingResponse.Code, calls, pendingResponse.Body.String())
	}
}

func TestDatabaseUsernameKeyUniqueIndexRejectsCaseVariants(t *testing.T) {
	a := newProtocolTestApp(t)
	addProtocolTestUser(t, a, "UniqueName", "one-password")
	hash, err := hashPassword("two-password")
	if err != nil {
		t.Fatal(err)
	}
	second := User{StudentID: "another-student", Username: "UNIQUENAME", PasswordHash: hash, CreatedAt: time.Now()}
	if err := a.gormDB.Create(&second).Error; err == nil {
		t.Fatal("database accepted a username differing only by letter case")
	}
}

func TestManualApplicationsRejectCaseInsensitiveUsernameDuplicate(t *testing.T) {
	a := newProtocolTestApp(t)
	request := func(studentID, username string) *httptest.ResponseRecorder {
		t.Helper()
		req := jsonRequest(t, http.MethodPost, "/api/manual-registration", map[string]string{
			"studentId": studentID, "username": username, "password": "site-password", "confirmPassword": "site-password",
		})
		response := httptest.NewRecorder()
		a.manualRegister(response, req)
		return response
	}
	if response := request("2026100702", "AlumniName"); response.Code != http.StatusAccepted {
		t.Fatalf("first application status=%d body=%s", response.Code, response.Body.String())
	}
	duplicate := request("2026100703", "alumniname")
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("case-insensitive pending application duplicate status=%d, want 409 body=%s", duplicate.Code, duplicate.Body.String())
	}
	if !strings.Contains(duplicate.Body.String(), "不区分大小写") {
		t.Fatalf("duplicate message should explain case-insensitive matching: %s", duplicate.Body.String())
	}
}

func TestAdminCannotCreateOrRenameToCaseInsensitiveDuplicate(t *testing.T) {
	a := newProtocolTestApp(t)
	adminHash, _ := hashPassword("admin-password")
	admin := User{StudentID: "9000000000", Username: "SiteAdmin", PasswordHash: adminHash}
	if err := a.gormDB.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}
	a.adminStudent = admin.StudentID
	addProtocolTestSession(t, a, "admin-case-token", "client", admin.Username)
	addProtocolTestUser(t, a, "PlayerOne", "player-password")
	targetHash, _ := hashPassword("target-password")
	target := User{StudentID: "2026100707", Username: "RenameTarget", PasswordHash: targetHash}
	if err := a.gormDB.Create(&target).Error; err != nil {
		t.Fatal(err)
	}

	save := func(payload any) *httptest.ResponseRecorder {
		t.Helper()
		req := jsonRequest(t, http.MethodPost, "/api/admin/users/save", payload)
		req.Header.Set("Authorization", "Bearer admin-case-token")
		response := httptest.NewRecorder()
		a.adminSaveUser(response, req)
		return response
	}
	create := save(map[string]any{"studentId": "2026100704", "username": "playerone", "password": "created-password", "confirmPassword": "created-password"})
	if create.Code != http.StatusConflict {
		t.Fatalf("admin case-insensitive duplicate create status=%d body=%s", create.Code, create.Body.String())
	}
	rename := save(map[string]any{"id": target.ID, "studentId": target.StudentID, "username": "PLAYERONE", "password": "", "confirmPassword": "", "banned": false})
	if rename.Code != http.StatusConflict {
		t.Fatalf("admin case-insensitive duplicate rename status=%d body=%s", rename.Code, rename.Body.String())
	}
	addProtocolTestSession(t, a, "rename-session-token", "client", target.Username)
	caseOnlyRename := save(map[string]any{"id": target.ID, "studentId": target.StudentID, "username": "renametarget", "password": "", "confirmPassword": "", "banned": false})
	if caseOnlyRename.Code != http.StatusOK {
		t.Fatalf("same-account case-only rename status=%d body=%s", caseOnlyRename.Code, caseOnlyRename.Body.String())
	}
	var session Session
	if err := a.gormDB.First(&session, "access_token = ?", "rename-session-token").Error; err != nil {
		t.Fatal(err)
	}
	if session.Username != "renametarget" || a.cachedToken("rename-session-token") != "renametarget" {
		t.Fatalf("case-only rename did not preserve/update the user's session: db=%q cache=%q", session.Username, a.cachedToken("rename-session-token"))
	}
}

func TestUsernameMigrationBackfillsAndDetectsLegacyCaseCollisions(t *testing.T) {
	dsn := "file:username-legacy-" + strings.ReplaceAll(t.Name(), "/", "_") + "?mode=memory&cache=shared"
	db, err := gorm.Open(glebarezsqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.AutoMigrate(&User{}); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC()
	for i, name := range []string{"CaseLegacy", "caselegacy"} {
		student := "legacy-student-" + string(rune('1'+i))
		if err := db.Exec("INSERT INTO users (student_id, username, password_hash, banned, created_at, username_key) VALUES (?, ?, ?, ?, ?, NULL)", student, name, "hash", false, stamp).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := migrateUsernameKeys(db); err == nil || !strings.Contains(err.Error(), "collide ignoring case") {
		t.Fatalf("migration should clearly reject existing case-insensitive collisions, got %v", err)
	}
	var keys []string
	if err := db.Model(&User{}).Order("student_id").Pluck("username_key", &keys).Error; err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0] != "caselegacy" || keys[1] != "caselegacy" {
		t.Fatalf("migration did not backfill canonical keys: %#v", keys)
	}

	var rows int64
	if err := db.Model(&User{}).Count(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Fatalf("migration should not rename or delete existing accounts; rows=%d", rows)
	}
}
