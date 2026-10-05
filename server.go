package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	glebarezsqlite "github.com/glebarez/sqlite"
	_ "github.com/go-sql-driver/mysql"
	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
)

//go:embed web/mc-skin/dist/*
var frontend embed.FS

var usernameRE = regexp.MustCompile(`^[A-Za-z0-9]+$`)
var studentRE = regexp.MustCompile(`^[0-9]+$`)

const (
	maxImageUploadBytes              = 5 << 20
	maxTextureUploadBodyBytes        = maxImageUploadBytes + (64 << 10)
	yggdrasilAPIRootPath             = "/api/yggdrasil/"
	authlibInjectorAPILocationHeader = "X-Authlib-Injector-API-Location"
)

type app struct {
	db           *sql.DB
	gormDB       *gorm.DB
	driver, site string
	adminStudent string
	tokens       map[string]string
	tokensMu     sync.RWMutex
	refreshMu    sync.Mutex
	signatureKey string
	signingKey   *rsa.PrivateKey
	tokenTTL     time.Duration
	limiter      *RateLimiter
	challengeMu  sync.Mutex
	challenges   map[string]*captchaChallenge
	joinedMu     sync.Mutex
	joined       map[string]pendingJoin
}
type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// StudentPassword is used only for the upstream CAS check and is not part of User.
type registration struct {
	StudentID       string `json:"studentId"`
	StudentPassword string `json:"studentPassword"`
	Captcha         string `json:"captcha"`
	CaptchaToken    string `json:"captchaToken"`
	Username        string `json:"username"`
	Password        string `json:"password"`
}
type captchaChallenge struct {
	username string
	client   *http.Client
	fields   map[string]string
	image    string
	expires  time.Time
}
type yggLogin struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	ClientToken string `json:"clientToken"`
	RequestUser bool   `json:"requestUser"`
}
type User struct {
	ID           uint   `gorm:"primaryKey"`
	StudentID    string `gorm:"uniqueIndex;size:64;not null"`
	Username     string `gorm:"uniqueIndex;size:64;not null"`
	PasswordHash string `gorm:"not null"`
	Banned       bool
	CreatedAt    time.Time
}
type Session struct {
	AccessToken string    `gorm:"primaryKey;size:128"`
	ClientToken string    `gorm:"size:128;not null"`
	Username    string    `gorm:"size:64;not null;index"`
	ExpiresAt   time.Time `gorm:"index"`
}

type pendingJoin struct {
	username  string
	clientIP  string
	expiresAt time.Time
}

func main() {
	loadDotEnv(".env")
	driver := os.Getenv("DB_DRIVER")
	if driver == "" {
		driver = "sqlite"
	}
	dsn := os.Getenv("DB_DSN")
	if dsn == "" && driver == "sqlite" {
		dsn = "auth.db"
	}
	if driver == "mysql" && dsn == "" {
		log.Fatal("DB_DSN is required for mysql")
	}
	if driver != "sqlite" && driver != "mysql" {
		log.Fatal("DB_DRIVER must be sqlite or mysql")
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	var gdb *gorm.DB
	if driver == "mysql" {
		gdb, err = gorm.Open(gormmysql.Open(dsn), &gorm.Config{})
	} else {
		gdb, err = gorm.Open(glebarezsqlite.Open(dsn), &gorm.Config{})
	}
	if err != nil {
		log.Fatal(err)
	}
	if err = gdb.AutoMigrate(&User{}, &Session{}); err != nil {
		log.Fatal(err)
	}
	schema := `CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, student_id VARCHAR(64) UNIQUE NOT NULL, username VARCHAR(64) UNIQUE NOT NULL, password_hash TEXT NOT NULL, banned INTEGER NOT NULL DEFAULT 0, created_at TIMESTAMP NOT NULL)`
	if driver == "mysql" {
		schema = `CREATE TABLE IF NOT EXISTS users (id BIGINT PRIMARY KEY AUTO_INCREMENT, student_id VARCHAR(64) UNIQUE NOT NULL, username VARCHAR(64) UNIQUE NOT NULL, password_hash TEXT NOT NULL, banned BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMP NOT NULL)`
	}
	_ = schema
	ttl := 30 * 24 * time.Hour
	if raw := os.Getenv("TOKEN_TTL_HOURS"); raw != "" {
		if hours, parseErr := strconv.Atoi(raw); parseErr == nil && hours > 0 {
			ttl = time.Duration(hours) * time.Hour
		}
	}
	signingKey, keyErr := loadSigningKey("data/signing-key.pem")
	if keyErr != nil {
		log.Fatal(keyErr)
	}
	publicKey, keyErr := x509.MarshalPKIXPublicKey(&signingKey.PublicKey)
	if keyErr != nil {
		log.Fatal(keyErr)
	}
	a := &app{db: db, gormDB: gdb, driver: driver, site: getenv("SITE_NAME", "CQUPT Minecraft"), adminStudent: os.Getenv("ADMIN_STUDENT_ID"), tokens: map[string]string{}, challenges: map[string]*captchaChallenge{}, tokenTTL: ttl, limiter: NewRateLimiter(), signingKey: signingKey, signatureKey: "-----BEGIN PUBLIC KEY-----\n" + base64.StdEncoding.EncodeToString(publicKey) + "\n-----END PUBLIC KEY-----\n"}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, _ *http.Request) {
		jsonOK(w, map[string]any{"ok": true, "siteName": a.site})
	})
	mux.HandleFunc("/api/register", a.register)
	mux.HandleFunc("/api/login", a.login)
	mux.HandleFunc("/api/password", a.changePassword)
	mux.HandleFunc("/api/legal", legalStatus)
	mux.HandleFunc("/tos.html", legalPage("tos.html"))
	mux.HandleFunc("/privacy.html", legalPage("privacy.html"))
	mux.HandleFunc("/api/launcher/login", a.login)
	mux.HandleFunc("/api/admin/users", a.adminUsers)
	mux.HandleFunc("/api/admin/ban", a.adminBan)
	mux.HandleFunc("/api/admin/delete", a.adminDelete)
	mux.HandleFunc("/api/skin", a.skin)
	mux.HandleFunc("/api/skin/", a.publicSkin)
	mux.HandleFunc("/api/cape", a.cape)
	mux.HandleFunc("/api/cape/", a.publicCape)
	mux.HandleFunc("/textures/", a.texture)
	mux.HandleFunc("/api/yggdrasil/textures/", a.texture)
	mux.HandleFunc("/skins/MinecraftSkins/", a.legacySkin)
	mux.HandleFunc("/authserver/authenticate", a.yggAuthenticate)
	mux.HandleFunc("/authserver/authenticate/", a.yggAuthenticate)
	mux.HandleFunc("/authserver/refresh", a.yggRefresh)
	mux.HandleFunc("/authserver/refresh/", a.yggRefresh)
	mux.HandleFunc("/authserver/validate", a.yggValidate)
	mux.HandleFunc("/authserver/validate/", a.yggValidate)
	mux.HandleFunc("/authserver/invalidate", a.yggInvalidate)
	mux.HandleFunc("/authserver/invalidate/", a.yggInvalidate)
	mux.HandleFunc("/authserver/signout", a.yggSignout)
	mux.HandleFunc("/authserver/signout/", a.yggSignout)
	mux.HandleFunc("/sessionserver/session/minecraft/join", a.yggJoin)
	mux.HandleFunc("/sessionserver/session/minecraft/hasJoined", a.yggHasJoined)
	mux.HandleFunc("/sessionserver/session/minecraft/profile/", a.yggProfile)
	mux.HandleFunc("/authlib-injector", a.yggMetadata)
	mux.HandleFunc("/authlib-injector/", a.yggMetadata)
	mux.HandleFunc("/api/yggdrasil", a.yggMetadata)
	mux.HandleFunc("/api/yggdrasil/", a.yggMetadata)
	mux.HandleFunc("/api/yggdrasil/authserver/authenticate", a.yggAuthenticate)
	mux.HandleFunc("/api/yggdrasil/authserver/authenticate/", a.yggAuthenticate)
	mux.HandleFunc("/api/yggdrasil/authserver/refresh", a.yggRefresh)
	mux.HandleFunc("/api/yggdrasil/authserver/validate", a.yggValidate)
	mux.HandleFunc("/api/yggdrasil/authserver/invalidate", a.yggInvalidate)
	mux.HandleFunc("/api/yggdrasil/authserver/signout", a.yggSignout)
	mux.HandleFunc("/api/yggdrasil/sessionserver/session/minecraft/join", a.yggJoin)
	mux.HandleFunc("/api/yggdrasil/sessionserver/session/minecraft/hasJoined", a.yggHasJoined)
	mux.HandleFunc("/api/yggdrasil/sessionserver/session/minecraft/profile/", a.yggProfile)
	mux.HandleFunc("/api/profiles/minecraft", a.handleYggBatchProfiles)
	mux.HandleFunc("/api/yggdrasil/api/profiles/minecraft", a.handleYggBatchProfiles)
	mux.HandleFunc("/api/user/profile/", a.handleYggTextureUpload)
	mux.HandleFunc("/api/yggdrasil/api/user/profile/", a.handleYggTextureUpload)
	static, _ := fs.Sub(frontend, "web/mc-skin/dist")
	fileServer := http.FileServer(http.FS(static))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// React Router owns application routes. Return the embedded shell for
		// routes without a physical asset so /login and /dashboard do not 404.
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" || !strings.Contains(path, ".") {
			if _, err := fs.Stat(static, path); err != nil {
				data, readErr := fs.ReadFile(static, "index.html")
				if readErr != nil {
					http.Error(w, "frontend unavailable", 500)
					return
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write(data)
				return
			}
		}
		fileServer.ServeHTTP(w, r)
	})
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	server := &http.Server{
		Addr:              addr,
		Handler:           withCORS(withRequestBodyLimit(mux)),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	log.Printf("listening on %s", addr)
	log.Fatal(server.ListenAndServe())
}

// loadDotEnv provides a small dependency-free .env loader. Existing process
// environment variables always take precedence over values from the file.
func loadDotEnv(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if key == "" || os.Getenv(key) != "" {
			continue
		}
		value = strings.Trim(value, "\"'")
		_ = os.Setenv(key, value)
	}
}

func (a *app) register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	if !a.limiter.Allow("register:ip:"+clientIP(r), 10, time.Minute) {
		rateLimitError(w, "注册请求过于频繁，请稍后再试")
		return
	}
	var in registration
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		jsonError(w, "请求格式错误", 400)
		return
	}
	if !studentRE.MatchString(in.StudentID) {
		jsonError(w, "统一账号必须为纯数字", 400)
		return
	}
	if !usernameRE.MatchString(in.Username) {
		jsonError(w, "用户名只能包含英文和数字", 400)
		return
	}
	if len(in.Username) < 3 || len(in.Password) < 6 {
		jsonError(w, "用户名至少3位，密码至少6位", 400)
		return
	}
	var exists int64
	if a.gormDB.Model(&User{}).Where("student_id = ? OR username = ?", in.StudentID, in.Username).Count(&exists).Error != nil {
		jsonError(w, "数据库错误", 500)
		return
	}
	if exists > 0 {
		jsonError(w, "统一账号或本站用户名已注册", 409)
		return
	}
	if !a.limiter.Allow("probe:global", 5, time.Minute) {
		rateLimitError(w, "统一认证验证次数已达到全局上限，请一分钟后再试")
		return
	}
	var challenge *captchaChallenge
	if in.CaptchaToken != "" {
		a.challengeMu.Lock()
		challenge = a.challenges[in.CaptchaToken]
		delete(a.challenges, in.CaptchaToken)
		a.challengeMu.Unlock()
		if challenge == nil || time.Now().After(challenge.expires) || challenge.username != in.StudentID || strings.TrimSpace(in.Captcha) == "" {
			jsonError(w, "验证码已过期，请重新验证", 400)
			return
		}
	}
	status, pending, err := probe(in.StudentID, in.StudentPassword, in.Captcha, challenge)
	if err != nil {
		log.Printf("CQUPT probe failed")
		jsonError(w, "统一认证服务暂时不可用", 502)
		return
	}
	if status == "captcha-required" && pending != nil {
		token := randomToken()
		a.challengeMu.Lock()
		for key, old := range a.challenges {
			if time.Now().After(old.expires) {
				delete(a.challenges, key)
			}
		}
		a.challenges[token] = pending
		a.challengeMu.Unlock()
		w.WriteHeader(http.StatusPreconditionRequired)
		jsonOK(w, map[string]any{"error": "统一认证需要验证码", "code": "captcha-required", "captchaToken": token, "captchaImage": pending.image})
		return
	}
	if status != "credentials-correct" && status != "authenticated" {
		jsonError(w, "统一账号或密码验证失败: "+status, 401)
		return
	}
	hash, _ := hashPassword(in.Password)
	if err = a.gormDB.Create(&User{StudentID: in.StudentID, Username: in.Username, PasswordHash: hash, CreatedAt: time.Now()}).Error; err != nil {
		jsonError(w, "用户名已存在", 409)
		return
	}
	jsonOK(w, map[string]any{"ok": true, "username": in.Username, "site": a.site})
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	if !a.limiter.Allow("login:ip:"+clientIP(r), 20, time.Minute) {
		rateLimitError(w, "登录请求过于频繁，请稍后再试")
		return
	}
	var in credentials
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		jsonError(w, "请求格式错误", 400)
		return
	}
	var account User
	if a.gormDB.Where("username = ?", in.Username).First(&account).Error != nil || account.Banned {
		jsonError(w, "用户名或密码错误", 401)
		return
	}
	ok, _ := verifyPassword(account.PasswordHash, in.Password)
	if !ok {
		jsonError(w, "用户名或密码错误", 401)
		return
	}
	token := randomToken()
	a.setCachedToken(token, in.Username)
	_ = a.saveToken(token, token, in.Username)
	jsonOK(w, map[string]any{"ok": true, "username": in.Username, "accessToken": token, "clientToken": token, "launcher": r.URL.Path == "/api/launcher/login"})
}

func (a *app) changePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	username := a.userFromToken(r)
	if username == "" {
		jsonError(w, "登录已失效", 401)
		return
	}
	var in struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || len(in.NewPassword) < 6 {
		jsonError(w, "新密码至少6位", 400)
		return
	}
	var user User
	if a.gormDB.Where("username = ?", username).First(&user).Error != nil {
		jsonError(w, "用户不存在", 404)
		return
	}
	ok, _ := verifyPassword(user.PasswordHash, in.CurrentPassword)
	if !ok {
		jsonError(w, "当前密码错误", 403)
		return
	}
	hash, err := hashPassword(in.NewPassword)
	if err != nil {
		jsonError(w, "密码生成失败", 500)
		return
	}
	if err = a.gormDB.Model(&user).Update("password_hash", hash).Error; err != nil {
		jsonError(w, "保存失败", 500)
		return
	}
	jsonOK(w, map[string]any{"ok": true})
}

func legalStatus(w http.ResponseWriter, _ *http.Request) {
	_, tos := os.Stat("tos.html")
	_, privacy := os.Stat("privacy.html")
	jsonOK(w, map[string]bool{"tos": tos == nil, "privacy": privacy == nil})
}
func legalPage(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := os.ReadFile(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(b)
	}
}

func probe(user, pass, captcha string, challenge *captchaChallenge) (string, *captchaChallenge, error) {
	const origin = "https://ids.cqupt.edu.cn"
	var client *http.Client
	var fields map[string]string
	if challenge != nil {
		client, fields = challenge.client, challenge.fields
	} else {
		jar, _ := cookiejar.New(nil)
		client = &http.Client{Jar: jar, Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	}
	loginURL := origin + "/authserver/login"
	if challenge == nil {
		resp, err := client.Get(loginURL)
		if err != nil {
			return "", nil, err
		}
		page, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		resp.Body.Close()
		if err != nil {
			return "", nil, err
		}
		fields = parseCASForm(string(page))
	}
	salt := fields["pwdEncryptSalt"]
	execution := fields["execution"]
	eventID := fields["_eventId"]
	cllt := fields["cllt"]
	dllt := fields["dllt"]
	if salt == "" || execution == "" || eventID == "" {
		return "", nil, fmt.Errorf("CAS login form fields missing")
	}
	if challenge == nil {
		check, err := client.Get(origin + "/authserver/checkNeedCaptcha.htl?username=" + url.QueryEscape(user))
		if err != nil {
			return "", nil, err
		}
		var need struct {
			IsNeed bool `json:"isNeed"`
		}
		err = json.NewDecoder(check.Body).Decode(&need)
		check.Body.Close()
		if err != nil {
			return "", nil, err
		}
		if need.IsNeed {
			imageResp, err := client.Get(origin + "/authserver/getCaptcha.htl?_=" + strconv.FormatInt(time.Now().UnixMilli(), 10))
			if err != nil {
				return "", nil, err
			}
			imageType := strings.ToLower(strings.TrimSpace(strings.Split(imageResp.Header.Get("Content-Type"), ";")[0]))
			image, readErr := io.ReadAll(io.LimitReader(imageResp.Body, 1<<20+1))
			imageResp.Body.Close()
			if readErr != nil {
				return "", nil, readErr
			}
			if imageResp.StatusCode != http.StatusOK || len(image) == 0 || len(image) > 1<<20 || (imageType != "image/png" && imageType != "image/jpeg" && imageType != "image/gif" && imageType != "image/webp") {
				return "", nil, fmt.Errorf("CAS captcha image unavailable")
			}
			pending := &captchaChallenge{username: user, client: client, fields: fields, image: "data:" + imageType + ";base64," + base64.StdEncoding.EncodeToString(image), expires: time.Now().Add(3 * time.Minute)}
			return "captcha-required", pending, nil
		}
	}
	encrypted, err := encryptCASPassword(pass, salt)
	if err != nil {
		return "", nil, err
	}
	if cllt == "" {
		cllt = "userNameLogin"
	}
	if dllt == "" {
		dllt = "generalLogin"
	}
	form := url.Values{}
	for key, value := range fields {
		if key != "pwdEncryptSalt" {
			form.Set(key, value)
		}
	}
	form.Set("username", user)
	form.Set("password", encrypted)
	form.Set("_eventId", eventID)
	form.Set("execution", execution)
	form.Set("cllt", cllt)
	form.Set("dllt", dllt)
	if captcha != "" {
		form.Set("captcha", captcha)
	}
	req, _ := http.NewRequest(http.MethodPost, loginURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	req.Header.Set("Referer", loginURL)
	req.Header.Set("Origin", origin)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	for hop := 0; hop < 8; hop++ {
		location := resp.Header.Get("Location")
		if resp.StatusCode < 300 || resp.StatusCode >= 400 || location == "" {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
			resp.Body.Close()
			finalPath := resp.Request.URL.Path
			loginPage := strings.Contains(string(body), `id="pwdFromId"`) || strings.Contains(string(body), `name="passwordText"`)
			log.Printf("CQUPT probe final response: status=%d loginPage=%t", resp.StatusCode, loginPage)
			if resp.StatusCode == http.StatusUnauthorized || loginPage {
				return "credentials-incorrect", nil, nil
			}
			if finalPath == "/personalInfo/personCenter/index.html" || (resp.StatusCode >= 200 && resp.StatusCode < 300) {
				return "credentials-correct", nil, nil
			}
			return "login-unconfirmed", nil, nil
		}
		log.Printf("CQUPT probe redirect: status=%d", resp.StatusCode)
		resp.Body.Close()
		next, parseErr := url.Parse(location)
		if parseErr != nil {
			return "", nil, parseErr
		}
		if !next.IsAbs() {
			next = resp.Request.URL.ResolveReference(next)
		}
		if next.Scheme != "https" || next.Hostname() != "ids.cqupt.edu.cn" || (next.Port() != "" && next.Port() != "443") {
			return "login-unconfirmed", nil, nil
		}
		redirectReq, reqErr := http.NewRequest(http.MethodGet, next.String(), nil)
		if reqErr != nil {
			return "", nil, reqErr
		}
		redirectReq.Header.Set("Referer", resp.Request.URL.String())
		redirectReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36")
		resp, err = client.Do(redirectReq)
		if err != nil {
			return "", nil, err
		}
	}
	resp.Body.Close()
	return "login-unconfirmed", nil, nil
}

func matchInput(html, id string) string {
	re := regexp.MustCompile(`(?is)<input[^>]+(?:id|name)=["']` + regexp.QuoteMeta(id) + `["'][^>]*>`)
	tag := re.FindString(html)
	v := regexp.MustCompile(`(?i)value=["']([^"']*)["']`).FindStringSubmatch(tag)
	if len(v) > 1 {
		return v[1]
	}
	return ""
}

func parseCASForm(html string) map[string]string {
	result := map[string]string{}
	form := ""
	for _, candidate := range regexp.MustCompile(`(?is)<form\b[^>]*>[\s\S]*?</form>`).FindAllString(html, -1) {
		if regexp.MustCompile(`(?i)\bid\s*=\s*["']pwdFromId["']`).MatchString(candidate) {
			form = candidate
			break
		}
	}
	if form == "" {
		// Some deployments omit the form id while keeping the same named inputs.
		form = html
	}
	inputRE := regexp.MustCompile(`(?is)<input\b[^>]*>`)
	attrRE := regexp.MustCompile(`(?i)([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	for _, tag := range inputRE.FindAllString(form, -1) {
		attrs := map[string]string{}
		for _, m := range attrRE.FindAllStringSubmatch(tag, -1) {
			value := m[2]
			if value == "" {
				value = m[3]
			}
			if value == "" {
				value = m[4]
			}
			attrs[strings.ToLower(m[1])] = value
		}
		name := attrs["name"]
		if name == "" {
			if attrs["id"] == "pwdEncryptSalt" {
				result["pwdEncryptSalt"] = attrs["value"]
			}
			continue
		}
		if strings.EqualFold(attrs["type"], "checkbox") && !regexp.MustCompile(`(?i)\schecked(?:\s|=|/?>)`).MatchString(tag) {
			continue
		}
		result[name] = attrs["value"]
	}
	if result["cllt"] == "" {
		result["cllt"] = "userNameLogin"
	}
	if result["dllt"] == "" {
		result["dllt"] = "generalLogin"
	}
	return result
}

func matchCheckedInput(html, name string) string {
	re := regexp.MustCompile(`(?is)<input[^>]+name=["']` + regexp.QuoteMeta(name) + `["'][^>]*checked[^>]*>`)
	tag := re.FindString(html)
	if tag == "" {
		return ""
	}
	v := regexp.MustCompile(`(?i)value=["']([^"']*)["']`).FindStringSubmatch(tag)
	if len(v) > 1 {
		return v[1]
	}
	return "on"
}
func encryptCASPassword(password, key string) (string, error) {
	key = strings.TrimSpace(key)
	if len([]byte(key)) != 16 {
		return "", fmt.Errorf("invalid CAS encryption key")
	}
	random := make([]byte, 80)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	chars := "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"
	iv := make([]byte, 16)
	prefix := make([]byte, 64)
	for i := range random {
		random[i] = chars[int(random[i])%len(chars)]
	}
	// probe.mjs consumes the random stream in this order: IV first, prefix second.
	copy(iv, random[:16])
	copy(prefix, random[16:])
	padded := []byte(string(prefix) + password)
	pad := aes.BlockSize - len(padded)%aes.BlockSize
	padded = append(padded, bytes.Repeat([]byte{byte(pad)}, pad)...)
	cipherBlock, _ := aes.NewCipher([]byte(key))
	out := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(cipherBlock, iv)
	mode.CryptBlocks(out, padded)
	return base64.StdEncoding.EncodeToString(out), nil
}

func hashPassword(password string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	h := sha256.Sum256(append(b, []byte(password)...))
	return hex.EncodeToString(b) + ":" + hex.EncodeToString(h[:]), nil
}
func verifyPassword(stored, password string) (bool, error) {
	p := strings.SplitN(stored, ":", 2)
	if len(p) != 2 {
		return false, nil
	}
	salt, err := hex.DecodeString(p[0])
	if err != nil {
		return false, nil
	}
	h := sha256.Sum256(append(salt, []byte(password)...))
	return subtle.ConstantTimeCompare([]byte(p[1]), []byte(hex.EncodeToString(h[:]))) == 1, nil
}
func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	jsonOK(w, map[string]any{"error": msg})
}
func withRequestBodyLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			limit := int64(1 << 20)
			if (r.URL.Path == "/api/skin" || r.URL.Path == "/api/cape") && r.Method == http.MethodPost {
				limit = maxImageUploadBytes
			}
			if (strings.HasPrefix(r.URL.Path, "/api/user/profile/") || strings.HasPrefix(r.URL.Path, "/api/yggdrasil/api/user/profile/")) && r.Method == http.MethodPut {
				limit = maxTextureUploadBodyBytes
			}
			if r.ContentLength > limit {
				jsonError(w, "请求体过大", http.StatusRequestEntityTooLarge)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Expose-Headers", authlibInjectorAPILocationHeader)
		w.Header().Set(authlibInjectorAPILocationHeader, yggdrasilAPIRootPath)
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func getenv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
func randomToken() string { b := make([]byte, 24); _, _ = rand.Read(b); return hex.EncodeToString(b) }
func (a *app) setCachedToken(token, username string) {
	a.tokensMu.Lock()
	defer a.tokensMu.Unlock()
	a.tokens[token] = username
}
func (a *app) cachedToken(token string) string {
	a.tokensMu.RLock()
	defer a.tokensMu.RUnlock()
	return a.tokens[token]
}
func (a *app) deleteCachedToken(token string) {
	a.tokensMu.Lock()
	defer a.tokensMu.Unlock()
	delete(a.tokens, token)
}
func (a *app) userFromToken(r *http.Request) string {
	p := bearerToken(r)
	return a.tokenUser(p)
}
func (a *app) saveToken(access, client, username string) error {
	return a.gormDB.Save(&Session{AccessToken: access, ClientToken: client, Username: username, ExpiresAt: time.Now().Add(a.tokenTTL)}).Error
}
func (a *app) tokenUser(access string) string {
	session, ok := a.loadSession(access)
	if !ok {
		return ""
	}
	return session.Username
}
func (a *app) isAdmin(username string) bool {
	if username == "" {
		return false
	}
	var id string
	return a.db.QueryRow("SELECT student_id FROM users WHERE username=?", username).Scan(&id) == nil && id == a.adminStudent && a.adminStudent != ""
}
func (a *app) adminUsers(w http.ResponseWriter, r *http.Request) {
	if !a.isAdmin(a.userFromToken(r)) {
		jsonError(w, "管理员权限不足", 403)
		return
	}
	rows, err := a.db.Query("SELECT id,student_id,username,banned,created_at FROM users ORDER BY id DESC")
	if err != nil {
		jsonError(w, "数据库错误", 500)
		return
	}
	defer rows.Close()
	out := []any{}
	for rows.Next() {
		var id int64
		var sid, name string
		var ban int
		var created any
		_ = rows.Scan(&id, &sid, &name, &ban, &created)
		out = append(out, map[string]any{"id": id, "studentId": sid, "username": name, "banned": ban != 0, "createdAt": created})
	}
	jsonOK(w, out)
}
func (a *app) adminBan(w http.ResponseWriter, r *http.Request) {
	a.adminMutation(w, r, "UPDATE users SET banned=1 WHERE username=?")
}
func (a *app) adminDelete(w http.ResponseWriter, r *http.Request) {
	a.adminMutation(w, r, "DELETE FROM users WHERE username=?")
}
func (a *app) adminMutation(w http.ResponseWriter, r *http.Request, q string) {
	if !a.isAdmin(a.userFromToken(r)) {
		jsonError(w, "管理员权限不足", 403)
		return
	}
	var in struct {
		Username string `json:"username"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	if _, e := a.db.Exec(q, in.Username); e != nil {
		jsonError(w, "数据库错误", 500)
		return
	}
	jsonOK(w, map[string]any{"ok": true})
}
func (a *app) skin(w http.ResponseWriter, r *http.Request) {
	a.handleCustomSkin(w, r)
}

func (a *app) cape(w http.ResponseWriter, r *http.Request) {
	a.handleCustomCape(w, r)
}

func (a *app) publicSkin(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimPrefix(r.URL.Path, "/api/skin/")
	if username == "" || !usernameRE.MatchString(username) {
		http.NotFound(w, r)
		return
	}
	body, err := readSafeTexturePNG("data/skins", username, "skin")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(body)
}
func (a *app) publicCape(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimPrefix(r.URL.Path, "/api/cape/")
	if username == "" || !usernameRE.MatchString(username) {
		http.NotFound(w, r)
		return
	}
	b, err := readSafeTexturePNG("data/capes", username, "cape")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "public, max-age=60")
	_, _ = w.Write(b)
}
func (a *app) legacySkin(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/skins/MinecraftSkins/"), ".png")
	a.serveSkinByUser(w, username)
}
func (a *app) texture(w http.ResponseWriter, r *http.Request) {
	hash := strings.TrimPrefix(r.URL.Path, "/textures/")
	hash = strings.TrimPrefix(hash, "/api/yggdrasil/textures/")
	if !regexp.MustCompile(`^[a-fA-F0-9]{64}$`).MatchString(hash) {
		http.NotFound(w, r)
		return
	}
	for _, directory := range []string{"skins", "capes"} {
		entries, _ := os.ReadDir("data/" + directory)
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".png") {
				continue
			}
			username := strings.TrimSuffix(entry.Name(), ".png")
			kind := strings.TrimSuffix(directory, "s")
			b, err := readSafeTexturePNG("data/"+directory, username, kind)
			if err == nil {
				sum := sha256.Sum256(b)
				if hex.EncodeToString(sum[:]) == strings.ToLower(hash) {
					w.Header().Set("Content-Type", "image/png")
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
					w.Header().Set("X-Content-Type-Options", "nosniff")
					_, _ = w.Write(b)
					return
				}
			}
		}
	}
	http.NotFound(w, r)
}
func (a *app) serveSkinByUser(w http.ResponseWriter, username string) {
	if username == "" || !usernameRE.MatchString(username) {
		http.NotFound(w, nil)
		return
	}
	b, err := readSafeTexturePNG("data/skins", username, "skin")
	if err != nil {
		http.NotFound(w, nil)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	_, _ = w.Write(b)
}

func (a *app) yggAuthenticate(w http.ResponseWriter, r *http.Request) {
	a.handleYggAuthenticate(w, r)
}
func (a *app) yggMetadata(w http.ResponseWriter, r *http.Request) {
	base := "http://" + r.Host
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		base = proto + "://" + r.Host
	}
	host := strings.Split(r.Host, ":")[0]
	jsonOK(w, map[string]any{"meta": map[string]any{"serverName": a.site, "implementationName": a.site, "implementationVersion": "1.0.0", "feature.non_email_login": true, "feature.legacy_skin_api": true, "links": map[string]string{"homepage": base + "/", "register": base + "/login"}}, "skinDomains": []string{host}, "signaturePublickey": a.signatureKey})
}
func (a *app) yggRefresh(w http.ResponseWriter, r *http.Request) {
	a.handleYggRefresh(w, r)
}
func (a *app) yggValidate(w http.ResponseWriter, r *http.Request) {
	a.handleYggValidate(w, r)
}
func (a *app) yggInvalidate(w http.ResponseWriter, r *http.Request) {
	a.handleYggInvalidate(w, r)
}
func (a *app) yggSignout(w http.ResponseWriter, r *http.Request) {
	a.handleYggSignout(w, r)
}
func (a *app) yggJoin(w http.ResponseWriter, r *http.Request) {
	a.handleYggJoin(w, r)
}
func (a *app) yggHasJoined(w http.ResponseWriter, r *http.Request) {
	a.handleYggHasJoined(w, r)
}
func (a *app) yggProfile(w http.ResponseWriter, r *http.Request) {
	a.handleYggProfile(w, r)
}
func profileID(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:])[:32] }
func (a *app) profileResponse(r *http.Request, username string) map[string]any {
	return a.profilePayload(r, username, true)
}

func loadSigningKey(path string) (*rsa.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(b)
		if block != nil {
			if key, parseErr := x509.ParsePKCS1PrivateKey(block.Bytes); parseErr == nil {
				return key, nil
			}
			if parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes); parseErr == nil {
				if key, ok := parsed.(*rsa.PrivateKey); ok {
					return key, nil
				}
			}
		}
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll("data", 0700); err != nil {
		return nil, err
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}), 0600); err != nil {
		return nil, err
	}
	return key, nil
}
