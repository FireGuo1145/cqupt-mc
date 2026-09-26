package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "modernc.org/sqlite"
)

//go:embed web/mc-skin/dist/*
var frontend embed.FS

var usernameRE = regexp.MustCompile(`^[A-Za-z0-9]+$`)
var studentRE = regexp.MustCompile(`^[0-9]+$`)

type app struct {
	db           *sql.DB
	driver, site string
	adminStudent string
	tokens       map[string]string
}
type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type registration struct{ StudentID, StudentPassword, Captcha, Username, Password string }
type yggLogin struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	ClientToken string `json:"clientToken"`
	RequestUser bool   `json:"requestUser"`
}

func main() {
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
	schema := `CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, student_id VARCHAR(64) UNIQUE NOT NULL, username VARCHAR(64) UNIQUE NOT NULL, password_hash TEXT NOT NULL, banned INTEGER NOT NULL DEFAULT 0, created_at TIMESTAMP NOT NULL)`
	if driver == "mysql" {
		schema = `CREATE TABLE IF NOT EXISTS users (id BIGINT PRIMARY KEY AUTO_INCREMENT, student_id VARCHAR(64) UNIQUE NOT NULL, username VARCHAR(64) UNIQUE NOT NULL, password_hash TEXT NOT NULL, banned BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMP NOT NULL)`
	}
	if _, err = db.Exec(schema); err != nil {
		log.Fatal(err)
	}
	a := &app{db: db, driver: driver, site: getenv("SITE_NAME", "CQUPT Minecraft"), adminStudent: os.Getenv("ADMIN_STUDENT_ID"), tokens: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, _ *http.Request) { jsonOK(w, map[string]any{"ok": true}) })
	mux.HandleFunc("/api/register", a.register)
	mux.HandleFunc("/api/login", a.login)
	mux.HandleFunc("/api/launcher/login", a.login)
	mux.HandleFunc("/api/admin/users", a.adminUsers)
	mux.HandleFunc("/api/admin/ban", a.adminBan)
	mux.HandleFunc("/api/admin/delete", a.adminDelete)
	mux.HandleFunc("/api/skin", a.skin)
	mux.HandleFunc("/authserver/authenticate", a.yggAuthenticate)
	mux.HandleFunc("/authserver/refresh", a.yggRefresh)
	mux.HandleFunc("/authserver/validate", a.yggValidate)
	mux.HandleFunc("/authserver/invalidate", a.yggInvalidate)
	mux.HandleFunc("/sessionserver/session/minecraft/join", a.yggJoin)
	mux.HandleFunc("/sessionserver/session/minecraft/hasJoined", a.yggHasJoined)
	mux.HandleFunc("/sessionserver/session/minecraft/profile/", a.yggProfile)
	static, _ := fs.Sub(frontend, "web/mc-skin/dist")
	mux.Handle("/", http.FileServer(http.FS(static)))
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, withCORS(mux)))
}

func (a *app) register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
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
	var exists int
	if a.db.QueryRow("SELECT COUNT(*) FROM users WHERE student_id = ? OR username = ?", in.StudentID, in.Username).Scan(&exists) != nil {
		jsonError(w, "数据库错误", 500)
		return
	}
	if exists > 0 {
		jsonError(w, "统一账号或本站用户名已注册", 409)
		return
	}
	status, err := probe(in.StudentID, in.StudentPassword, in.Captcha)
	if err != nil {
		jsonError(w, "统一认证服务暂时不可用", 502)
		return
	}
	if status != "credentials-correct" && status != "authenticated" {
		jsonError(w, "统一账号或密码验证失败: "+status, 401)
		return
	}
	hash, _ := hashPassword(in.Password)
	if _, err = a.db.Exec("INSERT INTO users(student_id,username,password_hash,created_at) VALUES(?,?,?,?)", in.StudentID, in.Username, hash, time.Now()); err != nil {
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
	var in credentials
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		jsonError(w, "请求格式错误", 400)
		return
	}
	var stored string
	var banned int
	if a.db.QueryRow("SELECT password_hash,banned FROM users WHERE username = ?", in.Username).Scan(&stored, &banned) != nil || banned != 0 {
		jsonError(w, "用户名或密码错误", 401)
		return
	}
	ok, _ := verifyPassword(stored, in.Password)
	if !ok {
		jsonError(w, "用户名或密码错误", 401)
		return
	}
	token := randomToken()
	a.tokens[token] = in.Username
	jsonOK(w, map[string]any{"ok": true, "username": in.Username, "accessToken": token, "clientToken": token, "launcher": r.URL.Path == "/api/launcher/login"})
}

func probe(user, pass, captcha string) (string, error) {
	// probe.mjs is the source of truth for the university CAS flow. The optional
	// CAPTCHA value is passed through for future probe implementations.
	_ = captcha
	cmd := exec.Command("node", "-e", `import('./probe.mjs').then(async m=>{let r=await m.runProbe({username:process.env.PUSER,password:process.env.PPASS,captchaCode:process.env.PCAPTCHA}); console.log(JSON.stringify(r))}).catch(e=>{console.error(e.message);process.exit(1)})`)
	cmd.Env = append(os.Environ(), "PUSER="+user, "PPASS="+pass, "PCAPTCHA="+captcha)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	var result struct {
		Status string `json:"status"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(string(out))), &result) != nil {
		return "", errors.New("invalid probe output")
	}
	return result.Status, nil
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
	w.WriteHeader(code)
	jsonOK(w, map[string]any{"error": msg})
}
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
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
func (a *app) userFromToken(r *http.Request) string {
	p := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return a.tokens[p]
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
	user := a.userFromToken(r)
	if user == "" {
		jsonError(w, "未登录", 401)
		return
	}
	os.MkdirAll("data/skins", 0750)
	if r.Method == http.MethodGet {
		f, e := os.Open("data/skins/" + user + ".png")
		if e != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "image/png")
		io.Copy(w, f)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 5<<20)
	b, e := io.ReadAll(r.Body)
	if e != nil || len(b) == 0 {
		jsonError(w, "皮肤文件无效", 400)
		return
	}
	if len(b) < 8 || string(b[:8]) != "\x89PNG\r\n\x1a\n" {
		jsonError(w, "仅支持 PNG 皮肤", 400)
		return
	}
	if e = os.WriteFile("data/skins/"+user+".png", b, 0600); e != nil {
		jsonError(w, "保存失败", 500)
		return
	}
	jsonOK(w, map[string]any{"ok": true})
}

func (a *app) yggAuthenticate(w http.ResponseWriter, r *http.Request) {
	var in yggLogin
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		jsonError(w, "无效请求", 400)
		return
	}
	var stored string
	var banned int
	if a.db.QueryRow("SELECT password_hash,banned FROM users WHERE username=?", in.Username).Scan(&stored, &banned) != nil || banned != 0 {
		jsonError(w, "Forbidden", 403)
		return
	}
	ok, _ := verifyPassword(stored, in.Password)
	if !ok {
		jsonError(w, "Forbidden", 403)
		return
	}
	tok := in.ClientToken
	if tok == "" {
		tok = randomToken()
	}
	a.tokens[tok] = in.Username
	jsonOK(w, map[string]any{"accessToken": tok, "clientToken": tok, "selectedProfile": map[string]string{"id": profileID(in.Username), "name": in.Username}})
}
func (a *app) yggRefresh(w http.ResponseWriter, r *http.Request) { a.yggAuthenticate(w, r) }
func (a *app) yggValidate(w http.ResponseWriter, r *http.Request) {
	if a.userFromToken(r) != "" {
		w.WriteHeader(204)
	} else {
		w.WriteHeader(403)
	}
}
func (a *app) yggInvalidate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AccessToken string `json:"accessToken"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	delete(a.tokens, in.AccessToken)
	w.WriteHeader(204)
}
func (a *app) yggJoin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AccessToken, SelectedProfile string `json:"accessToken"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	if a.tokens[in.AccessToken] == "" {
		jsonError(w, "Forbidden", 403)
		return
	}
	w.WriteHeader(204)
}
func (a *app) yggHasJoined(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("username") == "" {
		http.NotFound(w, r)
		return
	}
	var sid string
	if a.db.QueryRow("SELECT username FROM users WHERE username=?", r.URL.Query().Get("username")).Scan(&sid) != nil {
		http.NotFound(w, r)
		return
	}
	jsonOK(w, map[string]any{"id": profileID(sid), "name": sid, "properties": []any{}})
}
func (a *app) yggProfile(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/sessionserver/session/minecraft/profile/")
	if name == "" {
		http.NotFound(w, r)
		return
	}
	var u string
	if a.db.QueryRow("SELECT username FROM users WHERE username=?", name).Scan(&u) != nil {
		http.NotFound(w, r)
		return
	}
	jsonOK(w, map[string]any{"id": profileID(u), "name": u, "properties": []any{}})
}
func profileID(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:])[:32] }
