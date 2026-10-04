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

Registration validates the numeric CQUPT unified account through the Go native CAS probe, then stores a separate site username and password. Launcher clients should POST the site credentials to `/api/launcher/login`.

The unified-account password is used transiently for CAS verification; it is not a field in the application's persisted user record and the service does not intentionally write it to files or logs. It remains in process/browser memory while verification is in progress, and browser-to-server transport protection depends on serving the site over HTTPS. No application can guarantee that OS swap, crash dumps, browser software, or separately configured infrastructure never persist sensitive input.

Yggdrasil compatible endpoints are available under `/authserver/*` and `/sessionserver/*`. Authenticated users can upload one PNG skin to `/api/skin` and one 64×32 PNG cape to `/api/cape`; uploading again replaces the current image. Uploaded capes are served at `/api/cape/{username}` and included as `CAPE` in signed Yggdrasil profile textures. Admins use the bearer token returned by login with `/api/admin/users`, `/api/admin/ban`, and `/api/admin/delete`.

### authlib-injector address discovery and drag-and-drop

All HTTP responses include `X-Authlib-Injector-API-Location: /api/yggdrasil/`; CORS exposes the header to browser clients. The login and dashboard footers, as well as the dashboard overview, provide a draggable control. It transfers `text/plain` data in the form `authlib-injector:yggdrasil-server:{URL-encoded absolute API Root}` with copy semantics. The launcher is expected to confirm before adding the server.

This follows the [Yggdrasil server specification (API Location Indication)](https://github.com/yushijinhun/authlib-injector/wiki/Yggdrasil-%E6%9C%8D%E5%8A%A1%E7%AB%AF%E6%8A%80%E6%9C%AF%E8%A7%84%E8%8C%83/569333647362bad5c7cea5ec40185bd4faff6439) and [launcher DnD specification](https://github.com/yushijinhun/authlib-injector/wiki/%E5%90%AF%E5%8A%A8%E5%99%A8%E6%8A%80%E6%9C%AF%E8%A7%84%E8%8C%83/27b8ece7cdd4fa70ece4b24292c65c9182c820a7).

To build the embedded web UI and a Linux x64 executable, build the frontend first, then run `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o cqupt-mc-linux-amd64 .` from the repository root.
