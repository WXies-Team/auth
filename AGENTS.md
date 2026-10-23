# AGENTS.md — 统一账号服务 (auth.horatio.cn)

> Project-level rules only. Global standards (commit format, versioning, security) live in
> `~/.config/opencode/AGENTS.md` — **this file wins on conflict**.

## At a glance

Generic account service (register / login / 2FA / passkey / sessions + account lifecycle:
invites, bans, 7-day delete grace, web-app OAuth) that any project joins
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
| Account lifecycle (ban / grace-delete / invites / bulk) | `internal/auth/{gate,adminctl,pendingdelete,invite,bulk}.go` — gate order & sweeper semantics commented in place |
| Web-app OAuth (BFF) | `internal/auth/oauth.go` + `cmd/server/oauth.go`; authorize tx & codes are **in-memory single-instance** state |
| User profile (nickname/avatarColor/avatarImage) | `internal/auth/profile.go` + `GET/PUT /api/profile` — sole source of truth; diaries' `profiles` 三列已迁入并清理 |
| AI rate limits / usage (per-uid) | `internal/ai/quota.go` (three gates, 口径 pinned in package comment) + `cmd/server/ai.go` |
| User-visible email copy | `internal/auth/email.go` brand registry keyed by app (热量日记 / 开支日记 / neutral **Auth**), one shared shell |
| Web console / admin pages (Kotlin/Wasm SPA) | logic `internal/auth/{websession,loginflow,totp,passkey,audit,admin}.go`, HTTP `cmd/server/{web,admin,ui}.go`, SPA `web/`（Gradle 子工程，产物经 `ci/build-server.sh` 拷入 `internal/ui/wasm/` 由 go:embed 伺服） |

## Commands

```bash
go build ./...        # compile gate
go test ./...         # DB cases need TEST_MYSQL_DSN (dedicated schema, never prod) else Skip
go vet ./...          # must stay clean
go run ./scripts/genicons        # regenerate favicon/brand assets; -check = disk==generator
ci/build-server.sh    # test + package dist/server.tar (same entry CI uses; builds web/ first)
# Frontend (web/, Kotlin/Wasm + miuix 0.9.4):
cd web && ./gradlew compileKotlinWasmJs --console=plain      # compile gate (needs JDK 21)
cd web && ./gradlew wasmJsBrowserDistribution --console=plain  # produce dist -> copied into internal/ui/wasm by ci
# Optional real-DB run (isolated mysqld only, NEVER prod; -p 1 — the two test packages
# share one schema):
TEST_MYSQL_DSN='root@tcp(127.0.0.1:<port>)/<schema>?charset=utf8mb4&parseTime=true&loc=Local' \
  go test -count=1 -p 1 ./internal/... ./cmd/...
```

DB cases still Skip by default (no dedicated test DB by decision), but the whole suite was
verified green against a real DB (2026-10-21, isolated mysqld) — use the DSN recipe before
touching lifecycle/OTP code instead of trusting Skip-silence. The delivery gate remains CI
build/test + deploy-time `/health` with auto-rollback.

## Boundaries

| Tier | Rule |
|---|---|
| Always | run build+vet+test after every change; keep protocol fields identical to calorie's auth block; `git add` per file, never `git add -A` |
| Ask first | new dependencies; schema changes (`internal/db/schema.sql`); adding an app to the `allowedApps` JWT aud whitelist; touching `ci/` or `.github/`; deleting rows from prod `app_config` |
| Never | secrets or real DSNs in the repo (`.env.example` placeholders only); commit `vendor/`; change snowflake `nodeID`; push without reading the diff |

## Onboarding a new app (接入 auth 流程)

The full eight-step guide lives in `~/.config/opencode/AUTH-ONBOARDING.md` (global, shared
by every project that joins auth)—read it before onboarding any app or changing the flow.
It is the single source of truth; do not inline the steps here. **If this repo changes the
onboarding flow (endpoint, registry, session/2FA/OAuth step), update that global guide in
the same PR**—a stale guide ships wrong integrations.

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
   `change` / `email_change` / `login_2fa` / `delete` (deletion confirm).
   `otp_codes` carries `uid` (0 = anonymous issuance): authed flows record the account;
   admin email change burns **by uid** (keying by email can't reach an in-flight code whose
   email is the user's *requested* target), and `email_change` verification checks uid
   ownership.
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
   bound + `reauth_at` within 2 h (`ReauthWindow`; the window **slides only on non-GET
    success** — GET/HEAD/OPTIONS never slide, else a hijacked cookie keeps sudo alive by
    polling; successful
   `reauthThen` / `reauthed` / admin-gate ops refresh via `slideReauth`, failures never do;
   `POST /web/reauth` also refreshes; Passkey 路为 `POST /web/reauth/webauthn/options|finish`
   （BeginLogin 非 discoverable，仪式行绑 uid、单次消费、method=passkey 审计）). UI auto-retries
   on the fixed 401 `需要重新验证身份`; SPA 弹框按账号能力出方案（Passkey/两步验证码，无 MFA
   才出密码兜底），并发 401 共享单例 in-flight promise。
9. **Roles**: `user | admin | super`. Effective app-admin = role `admin` + ≥1 `admin_scopes`
   row (grant implicit-promotes to admin; revoke-to-zero demotes to `user`). Only the root su
   (constant `RootSuperEmail = horatioxs@outlook.com`, resolved to a **uid** at startup so
   root can rebind their email without losing root) may grant/revoke `super`; other sus
   manage user|admin only. Sole role endpoint: `POST /admin/users/{uid}/role`; scope grants:
   `POST /admin/roles/{uid}/scope`. Never re-introduce an email allow-list in `app_config`
   (spec A1.3 rejected it).
10. **Account lifecycle & login gate**: the gate order is credentials → ban (`user_bans`,
    `app='*'` = global, 限时到期惰性判+删行) → project allow-list (`project_policy` /
    `project_access`; 放行 = su ∨ 名单 ∨ 该项目 admin_scopes) → 注销 pending → mustChange.
    Bans / membership removal revoke the affected app's sessions immediately. Admin matrix:
    su → anyone; app-admin → only targets with an active session in one of their scoped
    apps; the root-super target is actionable by root alone (root matched by **uid**).
11. **Deletion is a 7-day grace**: `users.pending_delete_at`; the request only sets the
    column + revokes all sessions + mails a signed cancel link — **hooks run only when the
    sweeper fires** (`RunPendingDeleteSweeper`, 1 h ticker + startup pass, `purgeAccount`
    reuses the original pipeline). Logging in inside the window cancels it and the receipt
    carries `deletePendingCancelled`.
12. **Login receipts & verify**: every token-issuing login receipt carries
    `mustChangePassword` / `deletePendingCancelled`; `Verify` reads **email from DB, never
    the claim** (admin email change doesn't bump `token_version`, so claims go stale);
    `/auth/change-password` re-issues the caller's credential (Bearer → `token`, web →
    Set-Cookie) and accepts an empty `oldPassword` when `password_must_change=1` and the
    session is inside the reauth window. **A new login path MUST call
    `notifyNewLoginDevice`** — the three 收口 points are `completeLogin`, `/auth/login`,
    the OAuth exchange.
13. **Emails**: `internal/mail` sends multipart/alternative (text/plain + html); the brand
    registry owns prefix/name/primaryHex/logoPath; logos are hosted `/brand/<slug>-v1.png`
    (swap = new versioned filename via genicons + logoPath in the same PR, never overwrite
    a live URL). The auth brand glyph is Lucide `shield`, single-sourced in genicons for
    favicon trio + email logo. Every `Audit*` constant must have a same-value `<option>` in
    `admin-audit.html` (`TestAuditFilterOptionsMatchAuditConstants` pins both directions).
14. **UA Client Hints**: `sessions.user_agent` may carry a CH suffix
    `原UA + " | CH:<platform>;<model>"` (collected on web login paths only when a device
    model is reported); `shortDevice` prefers the suffix → `平台 · 机型`, suffix-less /
    malformed fall back to UA parsing (legacy rows unaffected). The opt-in lives in
    `internal/ui.Render`'s `Accept-CH` header.

## Known pitfalls

- **前端是 Kotlin/Wasm SPA（web/，miuix 0.9.4）**：旧模板前端（templates/style.css/app.js）
  已于 M4 切流整体删除，别按旧文档找回。`go build` 前必须先有 wasm 产物（本地跑
  `cd web && ./gradlew wasmJsBrowserDistribution` 一次即可；`internal/ui/wasm/.keep` 占位
  保证缺产物时也能编译，页面壳会 404 到底）。页面壳（`ui.SPAIndex`）由 `spaHandler` 下发，
  带 no-store + Accept-CH（丢 header 设备名回退 UA 解析）。审计筛选下拉的值域在
  `web/.../screens/admin/AdminAuditScreen.kt` 的 `AUDIT_ACTIONS`——`TestAuditFilterOptionsMatchAuditConstants`
  从那里双向对拍。`?app=` 页面层 403 门已随模板移除：授权收口在数据端点，页面壳不含数据。
- **Wasm E2E 配方**（真浏览器全旅程验证）：隔离 mysqld 起服（`TOTP_ENC_KEY` 用测试口径
  32×`k`，播种测试用同 key 加密 TOTP 秘钥否则登录 500「密文解开失败」）+ Playwright
  `executablePath` 指系统 Chrome。两个坑：Compose 画布语义框的 `fill()` 是**追加不是替换**
  （要 click→Ctrl+A→type）；点击要 `force:true`（canvas 拦截 actionability 检查）。

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
- Schema batch 2026-10 adds tables `user_bans` `project_policy` `project_access`
  `user_invites` `oauth_clients`, columns `users.{password_must_change,pending_delete_at,
  login_notify}` and `otp_codes.uid` — **every new table must join both test cleanup
  lists** (`internal/auth/auth_test.go`, `cmd/server/routes_test.go`) or real-DB cases leak
  rows across each other.
- OAuth authorize transactions and codes live in **process memory** (single-instance, same
  assumption as the rate limiter): a restart voids them — integrators restart the flow,
  never replay a code.
- New-device login notify is best-effort (failure = slog only, never blocks login);
  `users.login_notify` defaults ON and `PUT /api/profile` only writes it when the field is
  explicitly present (`*bool`) — the Apps' full-profile saves can't clobber the web toggle.
- Recovery codes are Crockford alphanumeric `XXXX-XXXX-XXXX-XXXX`: any input that accepts
  them (web or Apps) must NOT use a numeric-only keyboard — letters can't be typed and
  some IMEs disable paste under numeric/password keyboards.
- `sessions.device` is an **insert-time snapshot**; every display path re-derives
  `shortDevice(user_agent)` at read time (legacy rows hold raw library UAs like
  `ktor-client/2.0`) — never render the stored column directly.
- The browser password-manager badge anchors to the **containing block**: field wrappers
  (`.field`/`.code-line`) must stay `position:relative` (plus `padding-right:44px` on
  credential/OTP fields) or the badge flies hundreds of px off the input (measured 554px).
- `.content` is a grid — children need `min-width:0` or the sessions table's min-width
  pushes the **whole page** into horizontal scroll; overflow belongs inside `.table-wrap`.
- `.bar-fill` (AI usage bars) is an inline span: without `display:block` its `height:100%`
  is ignored and the bar never renders.
- Admin avatar endpoint `GET /admin/users/{uid}/avatar`: admin gate, 300/min/uid, 404 =
  no image (frontend onerror falls back to colored initial). OAuth admin UI (Web 接入
  block) was removed from 项目访问 — backend `/admin/projects/{app}/oauth` + `clientId`
  stay dormant; restore the UI when the first real web project lands.
- `Sec-CH-UA-Model` is a **high-entropy** hint: the opt-in `Accept-CH` header lives in
  `internal/ui.Render` — losing it silently degrades device names back to UA-only. The
  login-notify fingerprint must hash the **stored** `user_agent` (incl. the CH suffix);
  "simplifying" it back to the raw meta UA makes every CH login look like a new device.
- The user sessions page renders **flat** (one row per session, duplicate device names
  stay side by side — grouping by name merges distinct devices); `.device-group`/group-kick
  were removed and `TestSessionsPageCurrentRowNeverKickable` pins their absence.
- Graph `sendMail` takes raw MIME as a **base64 text/plain body** (docs Example 4); the
  JSON body form does NOT parse multipart — putting the MIME source there mails boundary
  garbage (the 2026-10-22 乱码 incident). Don't "simplify" back.
- `.content` grid `gap` only reaches direct children: elements wrapped in an inner
  container (e.g. admin-sessions search form) need their own margin or they stick to the
  next card.
