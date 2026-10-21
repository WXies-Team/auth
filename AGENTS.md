# AGENTS.md — 统一账号服务 (auth.horatio.cn)

> Project-level rules only. Global standards (commit format, versioning, security) live in
> `~/.config/opencode/AGENTS.md` — **this file wins on conflict**.

## At a glance

Generic account service (register / login / 2FA / passkey / sessions) that any project joins
**by registry** — auth exists for accounts, not for any particular app; app names appear only
as registry entries (allowedApps / brand / hooks) and session labels. Go + MySQL, package root
`github.com/WXies-Team/auth` (module at **repo root**, no server/ subdir). UIDs are 7-digit
random ints (1,000,000–9,999,999, `crypto/rand` + PK-collision retry, `internal/auth/uid.go`);
the snowflake node (id 1, never change) issues internal row ids only. Repo `WXies-Team/auth`,
push straight to main; deploy = self-hosted CI → `ci/deploy-server.sh` (atomic `current/`
symlink switch under `/www/project/auth`, supervisord `auth:*` on `127.0.0.1:8868`, `/health`
fail ⇒ auto-rollback), nginx (BT-panel vhost) terminates TLS.

### Read first, by area

| You want to change | Read |
|---|---|
| Any auth DTO / JSON tag | `internal/protocol/protocol.go` **and** calorie-diary's `shared/.../dto/AuthDtos.kt` — diary-side snapshot pinned by `internal/protocol/protocol_test.go`; new contract ⇒ sync the snapshot same-PR |
| Business logic reference | expense-diary `server/internal/auth/auth.go` + `otp.go` (this repo was照抄自 that family); divergences commented in place |
| OTP / 2FA factors | `internal/auth/otp.go`, `loginflow.go`, `totp.go` + `otp_codes`/`login_states` comments in `internal/db/schema.sql` |
| Sessions / devices | `internal/auth/session.go` (sid 63-bit snowflake ⇒ **JSON string**, JS-safe; kick = session layer only) |
| User profile (nickname/avatarColor/avatarImage) | `internal/auth/profile.go` + `GET/PUT /api/profile` — sole source of truth; diaries' `profiles` 三列已迁入并清理 |
| AI rate limits / usage (per-uid) | `internal/ai/quota.go` (three gates, 口径 pinned in package comment) + `cmd/server/ai.go` |
| User-visible email copy | `internal/auth/email.go` brand registry keyed by app (热量日记 / 开支日记 / neutral **Auth**), one shared shell |
| Web console / admin pages | logic `internal/auth/{websession,loginflow,totp,passkey,audit,admin}.go`, HTTP `cmd/server/{web,admin,ui}.go`, pages `internal/ui/` |

## Commands

```bash
go build ./...        # compile gate
go test ./...         # DB cases need TEST_MYSQL_DSN (dedicated schema, never prod) else Skip
go vet ./...          # must stay clean
ci/build-server.sh    # test + package dist/server.tar (same entry CI uses)
```

DB cases are accepted to Skip locally and in CI (no dedicated test DB by decision); the
delivery gate is CI build/test + deploy-time `/health` with auto-rollback — verify on prod
with the test account instead of standing up a test database.

## Boundaries

| Tier | Rule |
|---|---|
| Always | run build+vet+test after every change; keep protocol fields identical to calorie's auth block; `git add` per file, never `git add -A` |
| Ask first | new dependencies; schema changes (`internal/db/schema.sql`); adding an app to the `allowedApps` JWT aud whitelist; touching `ci/` or `.github/`; deleting rows from prod `app_config` |
| Never | secrets or real DSNs in the repo (`.env.example` placeholders only); commit `vendor/`; change snowflake `nodeID`; push without reading the diff |

## Onboarding a new app (接入 auth 流程)

Each step has a done-criterion; finish all six, then `go build ./... && go vet ./... && go test ./...` must pass.

1. **Protocol** — define the app-facing DTOs in `internal/protocol/protocol.go` (fields
   stay一字不差 with the diary family's `AuthDtos.kt` convention; our only extra field is
   `app`). Done when `TestProtocolMatchesDiaryAuthDtos` covers the new block.
2. **Registry** — add the slug to `allowedApps` (`internal/auth/scope.go`, also the JWT `aud`
   whitelist) and `knownApps` (`internal/ui/ui.go`, display name); add an email brand row in
   `internal/auth/email.go`. Done when `TestBrandForSelection` passes (brand ↔ whitelist drift
   fails it).
3. **Config** — nothing generic to store: FCM/push credentials belong in the **app's own
   database** (`app_config` there; never in auth — auth can only hold shared keys:
   `llm_*`, `push_admin_token`). Set `hook_<app>` in prod `app_config` before the app ships
   (a missing key silently orphans that app's rows on account deletion). Done when `/health`
   reports and a test delete skips/succeeds for the new app.
4. **Client** — point the app at `https://auth.horatio.cn` + send `app` on every call; set a
   parseable User-Agent `<slug>/<version> (Android; <model>)` (auth shows it as the device
   name; unknown UA degrades to 未知设备); register WebAuthn origins in
   `webauthn_opaque_origins` with **all 4 encoding variants per cert hash** (see pitfalls);
   decode `/internal/verify` `uid` as int64, never float64. Done when login → 2FA → session
   appears correctly in the web console.
5. **Session scope** — bearer (JWT `aud`) callers only ever see/revoke their own app's
   sessions; the web cookie sees all. The app ships a session page against
   `GET /api/sessions` (`{sessions:[...]}`, id = string) + `DELETE /api/sessions/{id}` +
   `POST /api/sessions/revoke-others`. Done when the app lists only its own rows.
6. **2FA parity** — three factors are supported: TOTP (`code`), email OTP (`emailCode`,
   purpose `login_2fa`), recovery code (`recoveryCode`); `POST /auth/send-code` purpose must
   be in the server whitelist and in the diary-side enum test
   (`TestDiaryCodePurposeMatchesServerWhitelist`). Done when a login succeeds via each factor
   the app offers.

## Work conventions

1. **JWT**: HS256, `iss="auth"`, `aud` = the `app` the login declared (whitelist
   `calorie-diary` / `expense-diary`), TTL 90 days, claims `uid/email/ver`; single secret is
   enough (signature + validation both live here).
2. **`uid`/`sid` precision**: parse claims with `jwt.WithJSONNumber()` (float64 eats snowflake
   low bits); `/internal/verify` consumers decode `uid` into int64; session ids cross JSON as
   **strings** (63-bit > 2^53, browsers round them).
3. **Revocation**: `token_version` in `users`, compared on **every** token validation;
   logout / password-change do +1; **never cached** (10s app_config cache must not spread here).
4. **OTP**: 6-digit, 5-min expiry, 60s cooldown, 10/day per (email,purpose), 5 wrong tries
   invalidate, cross-purpose recipient cap 15/day; "burn" sets `used=1`, never deletes rows
   mid-day (deletion loses daily counts). Purposes: `register` / `login` / `reset` /
   `change` / `email_change` / `login_2fa` (the 2FA email code, keyed separately from `login`).
5. **2FA login step**: `POST /web/login/totp` takes `code` | `recoveryCode` | `emailCode`
   (priority recovery > email > code). Disabling 2FA deletes only the 2FA config (factors +
   recovery codes) — it **never** logs out other devices (GitHub parity).
6. **Rate limits** (in-process sliding window, single-instance assumption): unauthed 15/min/IP,
   send-code 5/min/IP, authed 10/min/uid + 120/min/IP outer, verify 600/min **per app** (keyed
   by body `app` — both diary callers are loopback); session endpoints own uid scopes —
   list 30/min, kick / revoke-others / revoke-many 10/min each.
7. **Copy tone**: error = what went wrong + next step, Chinese; terms are fixed:
   两步验证 / 恢复码 / 邮箱验证码 / 两步验证码 / 会话 / 设备 / 项目 / 控制台 / 管理后台.
   Email brand via `brandFor(app)`; subjects `<prefix><场景>验证码` (e.g. `【Auth】注册验证码`).
   auth is generic copy — never phrase it as existing to serve particular apps.
8. **Web console session = cookie, apps = Bearer, same `sessions` row.** `__Host-auth_web`
   (HttpOnly+Secure+SameSite=Strict) stores only sha256 in `sessions.web_token_hash`; every
   non-GET request carrying it must send `X-CSRF-Token` — including legacy `/auth/*`,
   `/api/sessions*` (cookie support there is what makes the web pages work). Bearer callers
   skip CSRF. `/admin/*` is cookie-only, re-checks `users.role` per request, and requires MFA
   bound + `reauth_at` within 2 h (`ReauthWindow`; the window **slides** — successful
   `reauthThen` / `reauthed` / admin-gate ops refresh via `slideReauth`, failures never do;
   `POST /web/reauth` also refreshes). UI auto-retries on the fixed 401
   `需要重新验证身份，请输入密码或验证码`.
9. **Roles**: `user | admin | super`. Effective app-admin = role `admin` + ≥1 `admin_scopes`
   row (grant implicit-promotes to admin; revoke-to-zero demotes to `user`). Only the root su
   (constant `RootSuperEmail = horatioxs@outlook.com`) may grant/revoke `super`; other sus
   manage user|admin only. Sole role endpoint: `POST /admin/users/{uid}/role`; scope grants:
   `POST /admin/roles/{uid}/scope`. Never re-introduce an email allow-list in `app_config`
   (spec A1.3 rejected it).

## Known pitfalls

- `JWT_SECRET` < 32 bytes and `TOTP_ENC_KEY` < 32 bytes → process refuses to start (by
  design). `TOTP_ENC_KEY` in prod backs up next to `JWT_SECRET`: losing it invalidates every
  enrolled TOTP (recovery codes only). Local runs/real-DB tests set it via `t.Setenv`.
- `MYSQL_DSN` is the **only** env name accepted (`db.FromEnv`); calorie uses `DB_DSN` — don't mix.
- `app_config` reads are cached 10s in-process: after inserting mail keys, wait ≤10s (or
  restart) before `/health` `mailConfigured:true`. Quote `` `key` `` in every app_config SQL.
- self-hosted runner: the step process has **no HOME** — workflows set it per-step
  (`HOME: ${{ github.workspace }}/../go-home`); don't hoist to job level.
- `.github/**` and `*.md` pushes don't trigger build.yml; verify workflow edits with
  `gh workflow run` (concurrency group cancels queued runs on rerun of old commits).
- Never reintroduce a `vendor/` dir — Go auto-enables `-mod=vendor` and breaks the build.
- Email brands live in one registry (`email.go`) pinned by `TestBrandEmailStrings`; a new
  brand = registry row + test row, key kept in sync with `allowedApps`
  (`TestBrandForSelection` fails on drift).
- The three delete-hook keys (`hook_token` / `hook_calorie_diary` / `hook_expense_diary`)
  must all be set in prod: a missing key is the legitimate "skip this App" state (real-DB
  tests rely on it to avoid network calls); lose one and that App's rows orphan silently.
- **Declared non-rollbackable residual of the delete hooks**: cross-service, non-transactional
  — if App A's hook succeeds and App B's fails, the delete aborts but A's data is already
  gone. Remedy = retry (idempotent); troubleshoot via `注销钩子调用失败，注销中止` slog lines
  (uid/app/status). Two-phase remediation across three repos is deliberately out of scope.
- `__Host-` cookies require `Secure`: real browsers drop them on plain http. Smoke-test with
  curl (`-b` jar) or behind TLS; route tests attach cookies by hand for the same reason.
- The `token` from `/web/login/*` and `/webauthn/login/finish` depends on the request's `app`:
  **blank = web session token** (dual-credential routes, delivered with two cookies),
  **whitelisted app = business JWT** (same aud/ver/sid/90 days, no cookie). `/internal/verify`
  and diary APIs accept only the JWT. The 2FA second step reads `app` from `login_states.app`.
- An invalid `webauthn_opaque_origins` value logs an Error and degrades to web-only origins
  instead of refusing to start; read the startup log after touching that key.
- **App origins are matched as exact strings — list every encoding variant of each cert
  hash**: Android's clientDataJSON origin is base64**url**, hex-computed hashes are usually
  standard base64, padding varies by Play-services build ⇒ std/url-safe × padded/unpadded
  (4 per cert). A missing variant surfaces only at `register/login/finish` as
  `Error validating origin` (looks app-side). Key is startup-loaded: update, then restart.
- Don't mass-run `gofmt`: Go 1.27's gofmt wants a space after `//` before a full-width
  parenthesis and this repo's comments don't — a blanket run drowns the diff (CI never runs gofmt).
- `ai_usage_merged_at` in `app_config` is the **only** guard against double-counting
  `scripts/migrate-ai-usage-to-auth.sh` — never delete it; re-running `--execute` doubles counts.
- `otpStore.issue` holds a per-email `GET_LOCK` on a pinned conn (`issueLocked`): never call a
  `s.pool` statement while that lock is held — with the 8-conn pool saturated by concurrent
  issuers the holder waits forever for a connection (self-deadlock, `TestOTPStoreConcurrency`);
  cleanups run after `issueLocked` returns.
- UI elements whose CSS sets `display` (`.btn`, `.badge`, `.row`) ignore the HTML `hidden`
  **attribute** (author display wins over UA `[hidden]`) — toggle them with the `.hidden`
  class (`!important`) instead.
