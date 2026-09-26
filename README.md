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

Environment variables:

- `DB_DRIVER=sqlite|mysql` and `DB_DSN` (for MySQL, for example `user:pass@tcp(127.0.0.1:3306)/mc?parseTime=true`)
- `ADDR` (default `:8080`), `SITE_NAME`, `ADMIN_STUDENT_ID`

Registration first validates the numeric CQUPT unified account through `probe.mjs`, then stores a separate site username and password. Launcher clients should POST the site credentials to `/api/launcher/login`.

Yggdrasil compatible endpoints are available under `/authserver/*` and `/sessionserver/*`. Authenticated users can upload one PNG skin to `/api/skin`; uploading again replaces the existing file. Admins use the bearer token returned by login with `/api/admin/users`, `/api/admin/ban`, and `/api/admin/delete`.
