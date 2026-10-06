package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRecoverAccountResetsPasswordOncePerShanghaiDay(t *testing.T) {
	a := newProtocolTestApp(t)
	oldHash, err := hashPassword("old-site-password")
	if err != nil {
		t.Fatal(err)
	}
	user := User{StudentID: "2020123456", Username: "RecoverPlayer", PasswordHash: oldHash}
	if err := a.gormDB.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	addProtocolTestSession(t, a, "recover-token", "client", user.Username)
	casCalls := 0
	a.casProbe = func(studentID, password, _ string, _ *captchaChallenge) (string, *captchaChallenge, error) {
		casCalls++
		if studentID != user.StudentID || password != "cas-secret-not-stored" {
			t.Fatalf("CAS received unexpected credentials: studentId=%q", studentID)
		}
		return "credentials-correct", nil, nil
	}

	payload := map[string]string{
		"studentId": user.StudentID, "studentPassword": "cas-secret-not-stored",
		"newPassword": "new-site-password", "confirmPassword": "new-site-password",
	}
	request := jsonRequest(t, http.MethodPost, "/api/account/recover", payload)
	response := httptest.NewRecorder()
	a.recoverAccount(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("recovery status = %d, body=%s", response.Code, response.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["username"] != user.Username || !strings.Contains(result["message"].(string), "请牢记") {
		t.Fatalf("recovery response does not reveal account and reminder: %#v", result)
	}
	var saved User
	if err := a.gormDB.First(&saved, user.ID).Error; err != nil {
		t.Fatal(err)
	}
	if ok, _ := verifyPassword(saved.PasswordHash, "new-site-password"); !ok {
		t.Fatal("new site password was not stored as a working hash")
	}
	if saved.LastPasswordResetAt == nil || shanghaiDayStart(*saved.LastPasswordResetAt) != shanghaiDayStart(time.Now()) {
		t.Fatalf("reset timestamp is missing or not on today's Shanghai date: %v", saved.LastPasswordResetAt)
	}
	var remainingSessions int64
	if err := a.gormDB.Model(&Session{}).Where("access_token = ?", "recover-token").Count(&remainingSessions).Error; err != nil {
		t.Fatal(err)
	}
	if remainingSessions != 0 || a.cachedToken("recover-token") != "" {
		t.Fatal("password recovery should revoke existing persisted and cached sessions")
	}

	payload["newPassword"] = "another-site-password"
	payload["confirmPassword"] = "another-site-password"
	second := jsonRequest(t, http.MethodPost, "/api/account/recover", payload)
	secondResponse := httptest.NewRecorder()
	a.recoverAccount(secondResponse, second)
	if secondResponse.Code != http.StatusConflict {
		t.Fatalf("same-day second recovery status = %d, want 409; body=%s", secondResponse.Code, secondResponse.Body.String())
	}
	if casCalls != 2 {
		t.Fatalf("CAS probe calls = %d, want 2", casCalls)
	}
	if err := a.gormDB.First(&saved, user.ID).Error; err != nil {
		t.Fatal(err)
	}
	if ok, _ := verifyPassword(saved.PasswordHash, "new-site-password"); !ok {
		t.Fatal("a rejected same-day request changed the password")
	}
}

func TestRecoverAccountRequiresTwoMatchingNewPasswordsAndSharedGlobalLimit(t *testing.T) {
	a := newProtocolTestApp(t)
	userHash, _ := hashPassword("old")
	if err := a.gormDB.Create(&User{StudentID: "2020555000", Username: "RateRecover", PasswordHash: userHash}).Error; err != nil {
		t.Fatal(err)
	}
	casCalls := 0
	a.casProbe = func(string, string, string, *captchaChallenge) (string, *captchaChallenge, error) {
		casCalls++
		return "credentials-correct", nil, nil
	}
	mismatch := jsonRequest(t, http.MethodPost, "/api/account/recover", map[string]string{
		"studentId": "2020555000", "studentPassword": "cas", "newPassword": "new-password", "confirmPassword": "different-password",
	})
	mismatchResponse := httptest.NewRecorder()
	a.recoverAccount(mismatchResponse, mismatch)
	if mismatchResponse.Code != http.StatusBadRequest || casCalls != 0 {
		t.Fatalf("mismatched confirmation should be rejected before CAS: status=%d calls=%d", mismatchResponse.Code, casCalls)
	}
	for i := 0; i < 5; i++ {
		if !a.limiter.Allow("probe:global", 5, time.Minute) {
			t.Fatal("failed to prefill shared global test budget")
		}
	}
	limited := jsonRequest(t, http.MethodPost, "/api/account/recover", map[string]string{
		"studentId": "2020555000", "studentPassword": "cas", "newPassword": "new-password", "confirmPassword": "new-password",
	})
	limitedResponse := httptest.NewRecorder()
	a.recoverAccount(limitedResponse, limited)
	if limitedResponse.Code != http.StatusTooManyRequests || casCalls != 0 {
		t.Fatalf("global CAS budget was not enforced: status=%d calls=%d", limitedResponse.Code, casCalls)
	}
}

func TestRecoverAccountCompletesCAPTCHAChallengeWithoutSavingCASPassword(t *testing.T) {
	a := newProtocolTestApp(t)
	passwordHash, _ := hashPassword("before")
	user := User{StudentID: "2020999001", Username: "CaptchaRecover", PasswordHash: passwordHash}
	if err := a.gormDB.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	calls := 0
	a.casProbe = func(studentID, password, captcha string, challenge *captchaChallenge) (string, *captchaChallenge, error) {
		calls++
		if studentID != user.StudentID || password != "only-in-memory" {
			t.Fatalf("unexpected CAS inputs studentId=%q", studentID)
		}
		if challenge == nil {
			return "captcha-required", &captchaChallenge{image: "data:image/png;base64,AA==", expires: time.Now().Add(time.Minute)}, nil
		}
		if challenge.username != user.StudentID || captcha != "7319" {
			t.Fatalf("CAPTCHA retry was not bound to the challenge: challenge=%#v captcha=%q", challenge, captcha)
		}
		return "authenticated", nil, nil
	}
	payload := map[string]string{
		"studentId": user.StudentID, "studentPassword": "only-in-memory",
		"newPassword": "captcha-new-password", "confirmPassword": "captcha-new-password",
	}
	first := jsonRequest(t, http.MethodPost, "/api/account/recover", payload)
	firstResponse := httptest.NewRecorder()
	a.recoverAccount(firstResponse, first)
	if firstResponse.Code != http.StatusPreconditionRequired {
		t.Fatalf("initial CAPTCHA status=%d body=%s", firstResponse.Code, firstResponse.Body.String())
	}
	var challengeResponse struct {
		CaptchaToken string `json:"captchaToken"`
		Code         string `json:"code"`
	}
	if err := json.Unmarshal(firstResponse.Body.Bytes(), &challengeResponse); err != nil || challengeResponse.CaptchaToken == "" || challengeResponse.Code != "captcha-required" {
		t.Fatalf("CAPTCHA challenge payload=%s err=%v", firstResponse.Body.String(), err)
	}
	payload["captchaToken"] = challengeResponse.CaptchaToken
	payload["captcha"] = "7319"
	second := jsonRequest(t, http.MethodPost, "/api/account/recover", payload)
	secondResponse := httptest.NewRecorder()
	a.recoverAccount(secondResponse, second)
	if secondResponse.Code != http.StatusOK {
		t.Fatalf("CAPTCHA recovery status=%d body=%s", secondResponse.Code, secondResponse.Body.String())
	}
	if calls != 2 {
		t.Fatalf("CAS calls=%d want 2", calls)
	}
	var saved User
	if err := a.gormDB.First(&saved, user.ID).Error; err != nil {
		t.Fatal(err)
	}
	if ok, _ := verifyPassword(saved.PasswordHash, "captcha-new-password"); !ok {
		t.Fatal("CAPTCHA recovery did not update the site password")
	}
	if len(a.challenges) != 0 {
		t.Fatalf("one-time CAPTCHA challenge was not consumed: %d remain", len(a.challenges))
	}
}

func TestManualRegistrationApprovalAndRejection(t *testing.T) {
	a := newProtocolTestApp(t)
	adminHash, _ := hashPassword("admin-password")
	admin := User{StudentID: "9000000000", Username: "SiteAdmin", PasswordHash: adminHash}
	if err := a.gormDB.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}
	a.adminStudent = admin.StudentID
	addProtocolTestSession(t, a, "admin-token", "admin-client", admin.Username)

	apply := func(studentID, username, password string) *httptest.ResponseRecorder {
		t.Helper()
		request := jsonRequest(t, http.MethodPost, "/api/manual-registration", map[string]string{
			"studentId": studentID, "username": username, "password": password, "confirmPassword": password,
		})
		response := httptest.NewRecorder()
		a.manualRegister(response, request)
		return response
	}
	if protected := apply(a.adminStudent, "ImpersonatedAdmin", "alumni-password"); protected.Code != http.StatusConflict {
		t.Fatalf("manual application for configured admin status=%d, want 409", protected.Code)
	}
	response := apply("2020999002", "AlumniOne", "alumni-password")
	if response.Code != http.StatusAccepted {
		t.Fatalf("manual application status=%d body=%s", response.Code, response.Body.String())
	}
	var application ManualRegistration
	if err := a.gormDB.Where("student_id = ?", "2020999002").First(&application).Error; err != nil {
		t.Fatal(err)
	}
	if application.Status != "pending" || application.PasswordHash == "alumni-password" {
		t.Fatalf("application did not store a pending password hash: %#v", application)
	}
	if ok, _ := verifyPassword(application.PasswordHash, "alumni-password"); !ok {
		t.Fatal("pending registration password hash is invalid")
	}
	if duplicate := apply("2020999002", "AlumniOther", "another-password"); duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate pending student ID status=%d, want 409", duplicate.Code)
	}

	adminRequest := httptest.NewRequest(http.MethodPost, "/api/admin/applications/review", strings.NewReader(`{"id":`+uintString(application.ID)+`,"action":"approve"}`))
	adminRequest.Header.Set("Authorization", "Bearer admin-token")
	adminResponse := httptest.NewRecorder()
	a.adminReviewApplication(adminResponse, adminRequest)
	if adminResponse.Code != http.StatusOK {
		t.Fatalf("approval status=%d body=%s", adminResponse.Code, adminResponse.Body.String())
	}
	var approved User
	if err := a.gormDB.Where("student_id = ?", "2020999002").First(&approved).Error; err != nil {
		t.Fatal(err)
	}
	if ok, _ := verifyPassword(approved.PasswordHash, "alumni-password"); !ok {
		t.Fatal("approval did not transfer the pending site-password hash")
	}
	if err := a.gormDB.First(&application, application.ID).Error; err != nil {
		t.Fatal(err)
	}
	if application.Status != "approved" || application.PasswordHash != "" || application.ActiveStudentKey != nil || application.ActiveUsernameKey != nil {
		t.Fatalf("approved application retained active keys or a redundant password hash: %#v", application)
	}
	if duplicate := apply("2020999002", "AlumniThree", "another-password"); duplicate.Code != http.StatusConflict {
		t.Fatalf("already registered student ID status=%d, want 409", duplicate.Code)
	}

	rejected := apply("2020999003", "AlumniReject", "reject-password")
	if rejected.Code != http.StatusAccepted {
		t.Fatalf("second application status=%d body=%s", rejected.Code, rejected.Body.String())
	}
	var rejectedApplication ManualRegistration
	if err := a.gormDB.Where("student_id = ?", "2020999003").First(&rejectedApplication).Error; err != nil {
		t.Fatal(err)
	}
	rejectRequest := httptest.NewRequest(http.MethodPost, "/api/admin/applications/review", strings.NewReader(`{"id":`+uintString(rejectedApplication.ID)+`,"action":"reject","note":"请联系管理员"}`))
	rejectRequest.Header.Set("Authorization", "Bearer admin-token")
	rejectResponse := httptest.NewRecorder()
	a.adminReviewApplication(rejectResponse, rejectRequest)
	if rejectResponse.Code != http.StatusOK {
		t.Fatalf("rejection status=%d body=%s", rejectResponse.Code, rejectResponse.Body.String())
	}
	if err := a.gormDB.First(&rejectedApplication, rejectedApplication.ID).Error; err != nil {
		t.Fatal(err)
	}
	if rejectedApplication.Status != "rejected" || rejectedApplication.PasswordHash != "" {
		t.Fatalf("rejected application retained credentials or wrong status: %#v", rejectedApplication)
	}
	if retry := apply("2020999003", "AlumniRetry", "retry-password"); retry.Code != http.StatusAccepted {
		t.Fatalf("rejected student should be able to resubmit: status=%d body=%s", retry.Code, retry.Body.String())
	}
}

func TestAdminCanAddAndEditUsersButCannotAlterConfiguredAdminIdentity(t *testing.T) {
	a := newProtocolTestApp(t)
	adminHash, _ := hashPassword("admin-password")
	admin := User{StudentID: "9000000000", Username: "SiteAdmin", PasswordHash: adminHash}
	if err := a.gormDB.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}
	a.adminStudent = admin.StudentID
	addProtocolTestSession(t, a, "admin-token", "admin-client", admin.Username)
	request := func(value any) *httptest.ResponseRecorder {
		t.Helper()
		req := jsonRequest(t, http.MethodPost, "/api/admin/users/save", value)
		req.Header.Set("Authorization", "Bearer admin-token")
		resp := httptest.NewRecorder()
		a.adminSaveUser(resp, req)
		return resp
	}
	created := request(map[string]any{
		"studentId": "2020888001", "username": "AddedPlayer", "password": "first-password", "confirmPassword": "first-password",
	})
	if created.Code != http.StatusOK {
		t.Fatalf("admin create status=%d body=%s", created.Code, created.Body.String())
	}
	var createdPayload struct {
		ID uint `json:"id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &createdPayload); err != nil || createdPayload.ID == 0 {
		t.Fatalf("admin create response=%s err=%v", created.Body.String(), err)
	}
	var before User
	if err := a.gormDB.First(&before, createdPayload.ID).Error; err != nil {
		t.Fatal(err)
	}
	originalHash := before.PasswordHash
	updated := request(map[string]any{
		"id": createdPayload.ID, "studentId": before.StudentID, "username": "EditedPlayer", "password": "", "confirmPassword": "", "banned": true,
	})
	if updated.Code != http.StatusOK {
		t.Fatalf("admin edit status=%d body=%s", updated.Code, updated.Body.String())
	}
	var after User
	if err := a.gormDB.First(&after, createdPayload.ID).Error; err != nil {
		t.Fatal(err)
	}
	if after.Username != "EditedPlayer" || !after.Banned || after.PasswordHash != originalHash {
		t.Fatalf("admin edit changed unexpected fields: %#v", after)
	}
	protected := request(map[string]any{
		"id": admin.ID, "studentId": "999", "username": admin.Username, "password": "", "confirmPassword": "", "banned": true,
	})
	if protected.Code != http.StatusBadRequest {
		t.Fatalf("configured administrator should be protected, status=%d body=%s", protected.Code, protected.Body.String())
	}
	nonAdmin := jsonRequest(t, http.MethodPost, "/api/admin/users/save", map[string]any{
		"studentId": "2020888002", "username": "Unauthorized", "password": "secret123", "confirmPassword": "secret123",
	})
	nonAdmin.Header.Set("Authorization", "Bearer no-such-token")
	nonAdminResponse := httptest.NewRecorder()
	a.adminSaveUser(nonAdminResponse, nonAdmin)
	if nonAdminResponse.Code != http.StatusForbidden {
		t.Fatalf("non-admin access status=%d, want 403", nonAdminResponse.Code)
	}
}

func uintString(value uint) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}
