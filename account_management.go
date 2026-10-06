package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"gorm.io/gorm"
)

// ManualRegistration stores a site-password hash while an alumni registration
// is pending. Active keys are NULL after a decision, allowing later resubmission.
type ManualRegistration struct {
	ID                uint      `gorm:"primaryKey"`
	StudentID         string    `gorm:"size:64;not null;index"`
	Username          string    `gorm:"size:64;not null;index"`
	PasswordHash      string    `gorm:"not null"`
	Status            string    `gorm:"size:16;not null;index"`
	ActiveStudentKey  *string   `gorm:"size:64;uniqueIndex"`
	ActiveUsernameKey *string   `gorm:"size:64;uniqueIndex"`
	SubmittedAt       time.Time `gorm:"not null;index"`
	ReviewedAt        *time.Time
	ReviewedBy        string `gorm:"size:64"`
	ReviewNote        string `gorm:"size:500"`
}

type recoverRequest struct {
	StudentID       string `json:"studentId"`
	StudentPassword string `json:"studentPassword"`
	NewPassword     string `json:"newPassword"`
	ConfirmPassword string `json:"confirmPassword"`
	Captcha         string `json:"captcha"`
	CaptchaToken    string `json:"captchaToken"`
}

func (a *app) probeCAS(studentID, studentPassword, captcha string, challenge *captchaChallenge) (string, *captchaChallenge, error) {
	if a.casProbe != nil {
		return a.casProbe(studentID, studentPassword, captcha, challenge)
	}
	return probe(studentID, studentPassword, captcha, challenge)
}

func (a *app) takeCASChallenge(studentID, captchaToken, captcha string) (*captchaChallenge, error) {
	if captchaToken == "" {
		if strings.TrimSpace(captcha) != "" {
			return nil, errors.New("验证码状态已失效，请重新验证")
		}
		return nil, nil
	}
	a.challengeMu.Lock()
	challenge := a.challenges[captchaToken]
	delete(a.challenges, captchaToken)
	a.challengeMu.Unlock()
	if challenge == nil || time.Now().After(challenge.expires) || challenge.username != studentID || strings.TrimSpace(captcha) == "" {
		return nil, errors.New("验证码已过期，请重新验证")
	}
	return challenge, nil
}

func (a *app) saveCASChallenge(studentID string, pending *captchaChallenge) string {
	token := randomToken()
	pending.username = studentID
	pending.expires = time.Now().Add(3 * time.Minute)
	a.challengeMu.Lock()
	if a.challenges == nil {
		a.challenges = make(map[string]*captchaChallenge)
	}
	for key, old := range a.challenges {
		if time.Now().After(old.expires) {
			delete(a.challenges, key)
		}
	}
	a.challenges[token] = pending
	a.challengeMu.Unlock()
	return token
}

func (a *app) recoverAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		jsonError(w, "请求方法不允许", http.StatusMethodNotAllowed)
		return
	}
	var in recoverRequest
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		jsonError(w, "请求格式错误", http.StatusBadRequest)
		return
	}
	in.StudentID = strings.TrimSpace(in.StudentID)
	if !studentRE.MatchString(in.StudentID) || len(in.StudentID) > 64 || in.StudentPassword == "" || len(in.StudentPassword) > 256 {
		jsonError(w, "请输入有效的统一认证账号和密码", http.StatusBadRequest)
		return
	}
	if len(in.NewPassword) < 6 || len(in.NewPassword) > 256 || in.NewPassword != in.ConfirmPassword {
		jsonError(w, "新密码至少 6 位，且两次输入必须一致", http.StatusBadRequest)
		return
	}
	if a.limiter != nil {
		// Check the shared budget first so rejected cross-IP traffic does not
		// create unbounded per-IP or per-account limiter keys.
		if !a.limiter.Allow("probe:global", 5, time.Minute) {
			rateLimitError(w, "统一认证验证次数已达到全局上限，请一分钟后再试")
			return
		}
		if !a.limiter.Allow("recover:ip:"+clientIP(r), 5, time.Minute) {
			rateLimitError(w, "密码找回请求过于频繁，请稍后再试")
			return
		}
		if !a.limiter.Allow("recover:student:"+in.StudentID, 3, time.Minute) {
			rateLimitError(w, "该统一账号验证过于频繁，请稍后再试")
			return
		}
	}
	challenge, err := a.takeCASChallenge(in.StudentID, in.CaptchaToken, in.Captcha)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	status, pending, err := a.probeCAS(in.StudentID, in.StudentPassword, in.Captcha, challenge)
	if err != nil {
		log.Printf("CAS password recovery probe failed")
		jsonError(w, "统一认证服务暂时不可用", http.StatusBadGateway)
		return
	}
	if status == "captcha-required" && pending != nil {
		token := a.saveCASChallenge(in.StudentID, pending)
		w.WriteHeader(http.StatusPreconditionRequired)
		jsonOK(w, map[string]any{"error": "统一认证需要验证码", "code": "captcha-required", "captchaToken": token, "captchaImage": pending.image})
		return
	}
	if status != "credentials-correct" && status != "authenticated" {
		jsonError(w, "统一认证账号或密码验证失败", http.StatusUnauthorized)
		return
	}
	hash, err := hashPassword(in.NewPassword)
	if err != nil {
		jsonError(w, "密码生成失败", http.StatusInternalServerError)
		return
	}
	location := time.FixedZone("Asia/Shanghai", 8*60*60)
	now := time.Now().UTC()
	localNow := now.In(location)
	dayStart := time.Date(localNow.Year(), localNow.Month(), localNow.Day(), 0, 0, 0, 0, location).UTC()
	var username string
	failureStatus := 0
	failureMessage := ""
	err = a.gormDB.Transaction(func(tx *gorm.DB) error {
		var user User
		if err := tx.Where("student_id = ?", in.StudentID).First(&user).Error; err != nil {
			failureStatus = http.StatusNotFound
			failureMessage = "统一认证验证成功，但本站未找到该账号；如为离校生，请提交人工注册申请。"
			return err
		}
		if user.Banned {
			failureStatus = http.StatusForbidden
			failureMessage = "账号当前不可找回，请联系管理员。"
			return errors.New("account is disabled")
		}
		result := tx.Model(&User{}).
			Where("id = ? AND (last_password_reset_at IS NULL OR last_password_reset_at < ?)", user.ID, dayStart).
			Updates(map[string]any{"password_hash": hash, "last_password_reset_at": now})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			failureStatus = http.StatusConflict
			failureMessage = "每个统一认证账号每天只能找回一次密码，请明天再试。"
			return errors.New("daily password recovery quota reached")
		}
		if err := tx.Delete(&Session{}, "username = ?", user.Username).Error; err != nil {
			return err
		}
		username = user.Username
		return nil
	})
	if err != nil {
		if failureStatus != 0 {
			jsonError(w, failureMessage, failureStatus)
			return
		}
		jsonError(w, "密码重设失败，请稍后再试", http.StatusInternalServerError)
		return
	}
	a.revokeCachedUserTokens(username)
	jsonOK(w, map[string]any{
		"ok":       true,
		"username": username,
		"message":  "本站密码已重设。本站用户名为 " + username + "，请牢记新密码。",
	})
}

func (a *app) revokeCachedUserTokens(username string) {
	a.tokensMu.Lock()
	defer a.tokensMu.Unlock()
	for token, cachedUsername := range a.tokens {
		if cachedUsername == username {
			delete(a.tokens, token)
		}
	}
}

func (a *app) manualRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		jsonError(w, "请求方法不允许", http.StatusMethodNotAllowed)
		return
	}
	if a.limiter != nil {
		if !a.limiter.Allow("manual:global", 20, time.Hour) {
			rateLimitError(w, "人工注册申请已达到全局数量上限，请稍后再试")
			return
		}
		if !a.limiter.Allow("manual:ip:"+clientIP(r), 10, time.Hour) {
			rateLimitError(w, "人工注册申请过于频繁，请稍后再试")
			return
		}
	}
	var in struct {
		StudentID       string `json:"studentId"`
		Username        string `json:"username"`
		Password        string `json:"password"`
		ConfirmPassword string `json:"confirmPassword"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		jsonError(w, "请求格式错误", http.StatusBadRequest)
		return
	}
	in.StudentID = strings.TrimSpace(in.StudentID)
	in.Username = strings.TrimSpace(in.Username)
	if !studentRE.MatchString(in.StudentID) || len(in.StudentID) > 64 || !usernameRE.MatchString(in.Username) || len(in.Username) < 3 || len(in.Username) > 64 {
		jsonError(w, "请输入有效的统一账号和本站用户名（用户名至少 3 位，仅限英文和数字）", http.StatusBadRequest)
		return
	}
	if a.adminStudent != "" && in.StudentID == a.adminStudent {
		jsonError(w, "管理员账号不能通过人工注册申请创建", http.StatusConflict)
		return
	}
	if len(in.Password) < 6 || len(in.Password) > 256 || in.Password != in.ConfirmPassword {
		jsonError(w, "本站密码至少 6 位，且两次输入必须一致", http.StatusBadRequest)
		return
	}
	var existing int64
	if err := a.gormDB.Model(&User{}).Where("student_id = ? OR username = ?", in.StudentID, in.Username).Count(&existing).Error; err != nil {
		jsonError(w, "数据库错误", http.StatusInternalServerError)
		return
	}
	if existing > 0 {
		jsonError(w, "统一账号或本站用户名已注册", http.StatusConflict)
		return
	}
	hash, err := hashPassword(in.Password)
	if err != nil {
		jsonError(w, "密码生成失败", http.StatusInternalServerError)
		return
	}
	studentKey, usernameKey := in.StudentID, in.Username
	application := ManualRegistration{
		StudentID: in.StudentID, Username: in.Username, PasswordHash: hash, Status: "pending",
		ActiveStudentKey: &studentKey, ActiveUsernameKey: &usernameKey, SubmittedAt: time.Now().UTC(),
	}
	if err = a.gormDB.Create(&application).Error; err != nil {
		jsonError(w, "该统一账号或用户名已有待审核申请", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusAccepted)
	jsonOK(w, map[string]any{"ok": true, "message": "人工注册申请已提交，审核通过后即可登录。"})
}

func (a *app) adminSaveUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		jsonError(w, "请求方法不允许", http.StatusMethodNotAllowed)
		return
	}
	adminUsername := a.userFromToken(r)
	if !a.isAdmin(adminUsername) {
		jsonError(w, "管理员权限不足", http.StatusForbidden)
		return
	}
	var in struct {
		ID              uint   `json:"id"`
		StudentID       string `json:"studentId"`
		Username        string `json:"username"`
		Password        string `json:"password"`
		ConfirmPassword string `json:"confirmPassword"`
		Banned          bool   `json:"banned"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		jsonError(w, "请求格式错误", http.StatusBadRequest)
		return
	}
	in.StudentID = strings.TrimSpace(in.StudentID)
	in.Username = strings.TrimSpace(in.Username)
	if !studentRE.MatchString(in.StudentID) || len(in.StudentID) > 64 || !usernameRE.MatchString(in.Username) || len(in.Username) < 3 || len(in.Username) > 64 {
		jsonError(w, "请输入有效的统一账号和本站用户名", http.StatusBadRequest)
		return
	}
	if in.ID == 0 && len(in.Password) < 6 {
		jsonError(w, "新用户本站密码至少 6 位", http.StatusBadRequest)
		return
	}
	if in.Password != "" && (len(in.Password) < 6 || len(in.Password) > 256 || in.Password != in.ConfirmPassword) {
		jsonError(w, "密码至少 6 位，且两次输入必须一致", http.StatusBadRequest)
		return
	}
	if in.Password == "" && in.ConfirmPassword != "" {
		jsonError(w, "请填写新密码，或清空两处密码以保持原密码", http.StatusBadRequest)
		return
	}
	var passwordHash string
	if in.Password != "" {
		var err error
		passwordHash, err = hashPassword(in.Password)
		if err != nil {
			jsonError(w, "密码生成失败", http.StatusInternalServerError)
			return
		}
	}

	var saved User
	cachedUsernameToRevoke := ""
	failureStatus := 0
	failureMessage := ""
	err := a.gormDB.Transaction(func(tx *gorm.DB) error {
		var current User
		if in.ID != 0 {
			if err := tx.First(&current, in.ID).Error; err != nil {
				failureStatus, failureMessage = http.StatusNotFound, "用户不存在"
				return err
			}
			cachedUsernameToRevoke = current.Username
			if current.StudentID == a.adminStudent && (in.StudentID != current.StudentID || in.Banned) {
				failureStatus, failureMessage = http.StatusBadRequest, "不能修改或封禁环境变量指定的管理员身份"
				return errors.New("protected administrator account")
			}
		}
		query := tx.Model(&User{}).Where("student_id = ? OR username = ?", in.StudentID, in.Username)
		if in.ID != 0 {
			query = query.Where("id <> ?", in.ID)
		}
		var count int64
		if err := query.Count(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			failureStatus, failureMessage = http.StatusConflict, "统一账号或本站用户名已被使用"
			return errors.New("duplicate user identity")
		}
		if in.ID == 0 {
			saved = User{StudentID: in.StudentID, Username: in.Username, PasswordHash: passwordHash, Banned: in.Banned, CreatedAt: time.Now().UTC()}
			return tx.Create(&saved).Error
		}
		updates := map[string]any{"student_id": in.StudentID, "username": in.Username, "banned": in.Banned}
		if passwordHash != "" {
			updates["password_hash"] = passwordHash
		}
		if err := tx.Model(&current).Updates(updates).Error; err != nil {
			return err
		}
		saved = current
		saved.StudentID, saved.Username, saved.Banned = in.StudentID, in.Username, in.Banned
		if passwordHash != "" {
			saved.PasswordHash = passwordHash
			if err := tx.Delete(&Session{}, "username = ?", current.Username).Error; err != nil {
				return err
			}
		} else if current.Username != in.Username {
			if err := tx.Model(&Session{}).Where("username = ?", current.Username).Update("username", in.Username).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		if failureStatus != 0 {
			jsonError(w, failureMessage, failureStatus)
		} else {
			jsonError(w, "用户保存失败", http.StatusInternalServerError)
		}
		return
	}
	if in.ID != 0 && passwordHash != "" {
		a.revokeCachedUserTokens(cachedUsernameToRevoke)
	}
	jsonOK(w, map[string]any{"ok": true, "id": saved.ID, "username": saved.Username})
}

func (a *app) adminApplications(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		jsonError(w, "请求方法不允许", http.StatusMethodNotAllowed)
		return
	}
	if !a.isAdmin(a.userFromToken(r)) {
		jsonError(w, "管理员权限不足", http.StatusForbidden)
		return
	}
	var applications []ManualRegistration
	if err := a.gormDB.Where("status = ?", "pending").Order("submitted_at ASC").Find(&applications).Error; err != nil {
		jsonError(w, "数据库错误", http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(applications))
	for _, application := range applications {
		out = append(out, map[string]any{
			"id": application.ID, "studentId": application.StudentID,
			"username": application.Username, "submittedAt": application.SubmittedAt,
		})
	}
	jsonOK(w, out)
}

func (a *app) adminReviewApplication(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		jsonError(w, "请求方法不允许", http.StatusMethodNotAllowed)
		return
	}
	adminUsername := a.userFromToken(r)
	if !a.isAdmin(adminUsername) {
		jsonError(w, "管理员权限不足", http.StatusForbidden)
		return
	}
	var in struct {
		ID     uint   `json:"id"`
		Action string `json:"action"`
		Note   string `json:"note"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.ID == 0 || (in.Action != "approve" && in.Action != "reject") || len(in.Note) > 500 {
		jsonError(w, "审核请求无效", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	failureStatus := 0
	failureMessage := ""
	err := a.gormDB.Transaction(func(tx *gorm.DB) error {
		var application ManualRegistration
		if err := tx.First(&application, in.ID).Error; err != nil {
			failureStatus, failureMessage = http.StatusNotFound, "申请不存在"
			return err
		}
		if application.Status != "pending" {
			failureStatus, failureMessage = http.StatusConflict, "该申请已处理"
			return errors.New("application already reviewed")
		}
		if in.Action == "approve" {
			if a.adminStudent != "" && application.StudentID == a.adminStudent {
				failureStatus, failureMessage = http.StatusConflict, "管理员账号不能通过人工注册申请创建"
				return errors.New("manual application targets configured administrator")
			}
			user := User{StudentID: application.StudentID, Username: application.Username, PasswordHash: application.PasswordHash, CreatedAt: now}
			if err := tx.Create(&user).Error; err != nil {
				failureStatus, failureMessage = http.StatusConflict, "统一账号或本站用户名已注册，申请无法通过"
				return err
			}
		}
		reviewStatus := "approved"
		if in.Action == "reject" {
			reviewStatus = "rejected"
		}
		updates := map[string]any{
			"status": reviewStatus, "password_hash": "", "active_student_key": nil,
			"active_username_key": nil, "reviewed_at": now, "reviewed_by": adminUsername, "review_note": strings.TrimSpace(in.Note),
		}
		return tx.Model(&application).Updates(updates).Error
	})
	if err != nil {
		if failureStatus != 0 {
			jsonError(w, failureMessage, failureStatus)
		} else {
			jsonError(w, "申请审核失败", http.StatusInternalServerError)
		}
		return
	}
	reviewStatus := "approved"
	if in.Action == "reject" {
		reviewStatus = "rejected"
	}
	jsonOK(w, map[string]any{"ok": true, "status": reviewStatus})
}

func shanghaiDayStart(now time.Time) time.Time {
	location := time.FixedZone("Asia/Shanghai", 8*60*60)
	local := now.In(location)
	return time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, location).UTC()
}
