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
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed web/mc-skin/dist/*
var frontend embed.FS

var usernameRE = regexp.MustCompile(`^[A-Za-z0-9]+$`)
var studentRE = regexp.MustCompile(`^[0-9]+$`)

type app struct{ db *sql.DB }
type credentials struct { Username string `json:"username"`; Password string `json:"password"` }
type registration struct { StudentID, StudentPassword, Captcha, Username, Password string }

func main() {
	db, err := sql.Open("sqlite", "auth.db"); if err != nil { log.Fatal(err) }
	defer db.Close()
	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, student_id TEXT UNIQUE NOT NULL, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at DATETIME NOT NULL)`); err != nil { log.Fatal(err) }
	a := &app{db: db}; mux := http.NewServeMux()
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, _ *http.Request) { jsonOK(w, map[string]any{"ok": true}) })
	mux.HandleFunc("/api/register", a.register)
	mux.HandleFunc("/api/login", a.login)
	mux.HandleFunc("/api/launcher/login", a.login)
	static, _ := fs.Sub(frontend, "web/mc-skin/dist")
	mux.Handle("/", http.FileServer(http.FS(static)))
	addr := os.Getenv("ADDR"); if addr == "" { addr = ":8080" }
	log.Printf("listening on %s", addr); log.Fatal(http.ListenAndServe(addr, withCORS(mux)))
}

func (a *app) register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "method not allowed", 405); return }
	var in registration; if json.NewDecoder(r.Body).Decode(&in) != nil { jsonError(w, "请求格式错误", 400); return }
	if !studentRE.MatchString(in.StudentID) { jsonError(w, "统一账号必须为纯数字", 400); return }
	if !usernameRE.MatchString(in.Username) { jsonError(w, "用户名只能包含英文和数字", 400); return }
	if len(in.Username) < 3 || len(in.Password) < 6 { jsonError(w, "用户名至少3位，密码至少6位", 400); return }
	var exists int; if a.db.QueryRow("SELECT COUNT(*) FROM users WHERE student_id = ? OR username = ?", in.StudentID, in.Username).Scan(&exists) != nil { jsonError(w, "数据库错误", 500); return }
	if exists > 0 { jsonError(w, "统一账号或本站用户名已注册", 409); return }
	status, err := probe(in.StudentID, in.StudentPassword, in.Captcha); if err != nil { jsonError(w, "统一认证服务暂时不可用", 502); return }
	if status != "credentials-correct" && status != "authenticated" { jsonError(w, "统一账号或密码验证失败: "+status, 401); return }
	hash, _ := hashPassword(in.Password); if _, err = a.db.Exec("INSERT INTO users(student_id,username,password_hash,created_at) VALUES(?,?,?,?)", in.StudentID, in.Username, hash, time.Now()); err != nil { jsonError(w, "用户名已存在", 409); return }
	jsonOK(w, map[string]any{"ok": true, "username": in.Username})
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "method not allowed", 405); return }
	var in credentials; if json.NewDecoder(r.Body).Decode(&in) != nil { jsonError(w, "请求格式错误", 400); return }
	var stored string; if a.db.QueryRow("SELECT password_hash FROM users WHERE username = ?", in.Username).Scan(&stored) != nil { jsonError(w, "用户名或密码错误", 401); return }
	ok, _ := verifyPassword(stored, in.Password); if !ok { jsonError(w, "用户名或密码错误", 401); return }
	jsonOK(w, map[string]any{"ok": true, "username": in.Username, "launcher": r.URL.Path == "/api/launcher/login"})
}

func probe(user, pass, captcha string) (string, error) {
	// probe.mjs is the source of truth for the university CAS flow. The optional
	// CAPTCHA value is passed through for future probe implementations.
	_ = captcha
	cmd := exec.Command("node", "-e", `import('./probe.mjs').then(async m=>{let r=await m.runProbe({username:process.env.PUSER,password:process.env.PPASS}); console.log(JSON.stringify(r))}).catch(e=>{console.error(e.message);process.exit(1)})`)
	cmd.Env = append(os.Environ(), "PUSER="+user, "PPASS="+pass)
	out, err := cmd.Output(); if err != nil { return "", err }
	var result struct{ Status string `json:"status"` }; if json.Unmarshal([]byte(strings.TrimSpace(string(out))), &result) != nil { return "", errors.New("invalid probe output") }; return result.Status, nil
}

func hashPassword(password string) (string, error) { b := make([]byte, 16); if _, err := rand.Read(b); err != nil { return "", err }; h := sha256.Sum256(append(b, []byte(password)...)); return hex.EncodeToString(b)+":"+hex.EncodeToString(h[:]), nil }
func verifyPassword(stored, password string) (bool, error) { p := strings.SplitN(stored, ":", 2); if len(p) != 2 { return false, nil }; salt, err := hex.DecodeString(p[0]); if err != nil { return false, nil }; h := sha256.Sum256(append(salt, []byte(password)...)); return subtle.ConstantTimeCompare([]byte(p[1]), []byte(hex.EncodeToString(h[:]))) == 1, nil }
func jsonOK(w http.ResponseWriter, v any) { w.Header().Set("Content-Type", "application/json"); json.NewEncoder(w).Encode(v) }
func jsonError(w http.ResponseWriter, msg string, code int) { w.WriteHeader(code); jsonOK(w, map[string]any{"error": msg}) }
func withCORS(next http.Handler) http.Handler { return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Access-Control-Allow-Origin", "*"); w.Header().Set("Access-Control-Allow-Headers", "Content-Type"); if r.Method == "OPTIONS" { w.WriteHeader(204); return }; next.ServeHTTP(w,r) }) }
