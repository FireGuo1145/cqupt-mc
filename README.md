# CQUPT Minecraft Auth

## Run

```powershell
cd web/mc-skin
yarn install
yarn build
cd ../..
go run .
```

Open `http://localhost:8080`. The SQLite database is created as `auth.db`.

Copy `.env.example` to `.env` and set `ADMIN_STUDENT_ID` to the administrator's Chongqing University of Posts and Telecommunications unified-account number. The server loads `.env` automatically; process environment variables take precedence.

Environment variables:

- `DB_DRIVER=sqlite|mysql` and `DB_DSN` (for MySQL, for example `user:pass@tcp(127.0.0.1:3306)/mc?parseTime=true`)
- `ADDR` (default `:8080`), `SITE_NAME`, `ADMIN_STUDENT_ID`
- `TRUSTED_PROXY_CIDRS` (optional, comma-separated proxy IPs/CIDRs; forwarded client IPs are ignored unless the direct peer matches one of these ranges)

Registration validates the numeric CQUPT unified account through the Go native CAS probe, then stores a separate site username and password. Site usernames are unique without regard to ASCII letter case (`Player1` and `player1` conflict); registration checks this before contacting unified authentication. A normalized unique database index protects account creation and administrator edits, while pending manual applications use a separate normalized unique key. At startup, legacy usernames are backfilled; if existing accounts already collide case-insensitively, the server stops with a clear migration error so the accounts can be renamed deliberately rather than changing player identities automatically. Launcher clients should POST the site credentials to `/api/launcher/login`.

The unified-account password is used transiently for CAS verification; it is not a field in the application's persisted user record and the service does not intentionally write it to files or logs. It remains in process/browser memory while verification is in progress, and browser-to-server transport protection depends on serving the site over HTTPS. No application can guarantee that OS swap, crash dumps, browser software, or separately configured infrastructure never persist sensitive input.

### Account recovery and alumni applications

The login page provides account recovery through `POST /api/account/recover`. The user proves control of their numeric unified account using the upstream CAS password, then sets a new site password twice; the CAS password is never stored. A successfully verified recovery returns the site username, displays a reminder to remember the new password, and revokes the account's active sessions. Each unified account can complete one recovery per China Standard Time calendar day. Recovery also shares the server-wide CAS probe budget with standard registration (5 probes/minute), and is additionally limited to 5 requests/minute per source IP and 3/minute per unified account. CAS CAPTCHA challenges use the same short-lived verification flow as registration.

Former students can use the “离校生人工注册” channel and submit their unified-account number, site username, and site password plus confirmation; this form does not send a unified-account password. Applications remain pending until an administrator approves or rejects them. The pending site password is stored as a hash and is cleared from the application record when reviewed. Application submissions are limited to 10/hour per source IP and 20/hour server-wide. The administrator signs in with the normal site account whose unified-account number matches `ADMIN_STUDENT_ID`; the “管理员后台” page uses shadcn dialogs to add/edit users and to review applications. Admin APIs are `/api/admin/users`, `/api/admin/users/save`, `/api/admin/applications`, and `/api/admin/applications/review` (the existing ban/delete endpoints remain available).

Yggdrasil endpoints are available under `/authserver/*` and `/sessionserver/*`, with matching routes under `/api/yggdrasil/`. Authentication supports `authenticate`, `refresh`, `validate`, `invalidate`, and `signout`; refresh rotates the access token while preserving the client token. `join` records a short-lived server session, and `hasJoined` only succeeds for the matching username, server ID, and (when supplied) client IP. `GET /sessionserver/session/minecraft/profile/{uuid}` supports the `unsigned` parameter, and `POST /api/profiles/minecraft` batch-looks up profile names.

Texture uploads use the standard `PUT` and `DELETE /api/user/profile/{uuid}/{skin|cape}` routes (also available below `/api/yggdrasil/`). Uploads require `Authorization: Bearer {accessToken}` and `multipart/form-data` with an `image/png` `file` part; skin uploads may include `model=slim`. Images are size- and dimension-checked, decoded and re-encoded to remove ancillary PNG data. Legacy 22×17-multiple capes are padded with transparent pixels to 64×32 multiples. The existing website endpoints remain available: `POST /api/skin` and `POST /api/cape` replace the signed-in user's images, and public images remain available at `/api/skin/{username}` and `/api/cape/{username}`. Uploaded textures are included in signed Yggdrasil profile properties. Admins can manage user records through the dashboard; the existing `/api/admin/ban` and `/api/admin/delete` endpoints remain available.

### authlib-injector address discovery and drag-and-drop

All HTTP responses include `X-Authlib-Injector-API-Location: /api/yggdrasil/`; CORS exposes the header to browser clients. The login and dashboard footers, as well as the dashboard overview, provide a draggable control. It transfers `text/plain` data in the form `authlib-injector:yggdrasil-server:{URL-encoded absolute API Root}` with copy semantics. The launcher is expected to confirm before adding the server.

This follows the [Yggdrasil server specification (API Location Indication)](https://github.com/yushijinhun/authlib-injector/wiki/Yggdrasil-%E6%9C%8D%E5%8A%A1%E7%AB%AF%E6%8A%80%E6%9C%AF%E8%A7%84%E8%8C%83/569333647362bad5c7cea5ec40185bd4faff6439) and [launcher DnD specification](https://github.com/yushijinhun/authlib-injector/wiki/%E5%90%AF%E5%8A%A8%E5%99%A8%E6%8A%80%E6%9C%AF%E8%A7%84%E8%8C%83/27b8ece7cdd4fa70ece4b24292c65c9182c820a7).

To build the embedded web UI and a Linux x64 executable, build the frontend first, then run `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o cqupt-mc-linux-amd64 .` from the repository root.
