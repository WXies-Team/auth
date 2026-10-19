# AGENTS.md — 统一账号服务 (auth.horatio.cn)

> Project-level rules only. Global standards (commit format, versioning, security) live in
> `~/.config/opencode/AGENTS.md` — **this file wins on conflict**.

## At a glance

Go + MySQL email account service for 热量日记 / 记账, package root `github.com/WXies-Team/auth`
(module at **repo root**, no server/ subdir). Its `/auth/*` endpoints mirror calorie-diary's
one-to-one with **identical JSON fields** — clients switch by changing base URL + adding `app`.
UIDs are **7-digit random ints** (1,000,000–9,999,999, `crypto/rand` + primary-key
collision retry, see `internal/auth/uid.go`); the snowflake node (id 1, never change)
now issues internal row ids only — `sessions` / `audit_logs` / `passkeys` /
`webauthn_challenges`. Repo `WXies-Team/auth`, push
straight to main; deploy = self-hosted CI → supervisord `auth:*` on `127.0.0.1:8868`
(BASE_DIR `/www/wwwroot/auth.horatio.cn/server`), nginx terminates TLS.

### Read first, by area

| You want to change | Read |
|---|---|
| Any auth DTO / JSON tag | `internal/protocol/protocol.go` **and** calorie-diary's `shared/.../dto/AuthDtos.kt` — they must stay一字不差 (extra `app` field is ours); diary-side field snapshot pinned by `internal/protocol/protocol_test.go` |
| Business logic reference | expense-diary `server/internal/auth/auth.go` + `otp.go` — this repo was照抄 from that family (calorie-diary's copy was deleted when accounts moved here, `34f7d0ab`); divergences are the 7-digit random uid / aud / OTP-in-DB, all commented in place |
| OTP semantics | `internal/auth/otp.go` + `otp_codes` comments in `internal/db/schema.sql` |
| Sessions / device management | `internal/auth/session.go` + `sessions` comments in `internal/db/schema.sql` (kick = session layer only, `token_version` untouched) |
| User profile (nickname/avatarColor/avatarImage) | `internal/auth/profile.go` + `GET/PUT /api/profile` in `cmd/server/routes.go`; one-off merge of the two diaries' `profiles` columns = `scripts/migrate-profile-to-auth.sh` (rules + known data shapes in its header) |
| User-visible email copy | `internal/auth/email.go` — brand registry keyed by app (热量日记 / 开支日记 / neutral **Auth**); one shared shell, only the brand strings swap |
| Web console (login, passkey, TOTP, admin) | `docs/spec-passkey-2fa-web.md` first — it is the authoritative spec (session mechanism, endpoint tables, page list); then `internal/auth/{websession,loginflow,totp,passkey,audit,admin}.go` for logic and `cmd/server/{web,admin,ui}.go` + `internal/ui/` for HTTP/pages |

## Commands

```bash
go build ./...        # compile gate
go test ./...         # unit tests; DB cases need TEST_MYSQL_DSN (dedicated test schema, never prod) else Skip
go vet ./...          # must stay clean
ci/build-server.sh    # test + package dist/server.tar (same entry CI uses)
```

## Boundaries

| Tier | Rule |
|---|---|
| Always | run build+vet+test after every change; keep protocol fields identical to calorie's auth block; `git add` per file, never `git add -A` |
| Ask first | new dependencies; schema changes (`internal/db/schema.sql`); adding an app to the `allowedApps` JWT aud whitelist; touching `ci/` or `.github/` |
| Never | secrets or real DSNs in the repo (`.env.example` placeholders only); commit `vendor/`; change snowflake `nodeID`; push without reading the diff |

## Work conventions

1. **JWT**: HS256, `iss="auth"`, `aud`=the `app` the login request declared (whitelist
   `calorie-diary` / `expense-diary`), TTL 90 days, claims `uid/email/ver`. Signature and
   validation both happen here, so aud is only a downstream boundary — single secret is enough.
2. **`uid` precision**: claims are parsed with `jwt.WithJSONNumber()` — mandatory for
   `sid`, a snowflake id that through float64 loses low bits and makes the session lookup
   hit the wrong row (uid itself is only 7 digits now, but the parser never forks per
   claim). Same for `/internal/verify` consumers: decode `uid` into an int64 field, never
   float64.
3. **Revocation**: `token_version` in `users`, compared on **every** token validation; logout /
   password-change do +1. It is **never cached** (config's 10s app_config cache must not spread here).
4. **OTP**: 6-digit, 5-min expiry, 60s cooldown, 10/day per (email,purpose), 5 wrong tries
   invalidate, cross-purpose recipient cap 15/day. Codes live in `otp_codes`; "burn" sets
   `used=1` (whole generation), **never deletes rows mid-day** — deletion loses the daily counts.
5. **Rate limits** (in-process sliding window, single-instance assumption): unauthed 15/min/IP,
   send-code 5/min/IP, authed 10/min/uid + 120/min/IP outer, verify 600/min **per app** (keyed
   by the request body's `app`, not clientIP — both diary callers come from loopback
   127.0.0.1, so an IP key would make them share one bucket); the session
   endpoints get their own uid scopes — list 30/min, kick and revoke-others 10/min each.
6. **Copy tone**: error = what went wrong + next step, Chinese; email brand comes from
   `brandFor(app)` — 热量日记 / 开支日记, and **Auth** when app is blank; mail subjects
   `<prefix><场景>验证码` (e.g. `【Auth】注册验证码`).
7. Commit format per `~/.config/opencode/COMMITTING.md`: `<type>(<scope>): 中文描述`.
8. **Web console session = cookie, apps = Bearer, same `sessions` row.** `__Host-auth_web`
   (HttpOnly+Secure+SameSite=Strict) stores only sha256 in `sessions.web_token_hash`; every
   non-GET request that carries that cookie must send `X-CSRF-Token` (value of the readable
   `__Host-auth_web_csrf` cookie) — **this applies to the legacy `/auth/*`, `/api/sessions*`
   routes too**, because accepting the cookie there is what makes the web pages work. Bearer
   callers never send it and are unaffected. `/admin/*` accepts **cookies only**, re-checks
   `users.role` per request, and requires MFA bound + `reauth_at` within 15 min
   (`POST /web/reauth` refreshes it; the UI retries automatically on the fixed 401 message
   `需要重新验证身份，请输入密码或验证码`).
9. Admin bootstrap & gates: `users.role` defaults to `user`; first admin is one manual
   `UPDATE users SET role='admin'`. Never re-introduce an email allow-list in `app_config`
   (spec A1.3 rejected it: email change bypasses it, no index, 10s cache revocation gap).

## Known pitfalls

- `JWT_SECRET` < 32 bytes → the process refuses to start (by design; don't "fix" it).
- `MYSQL_DSN` is the **only** env name accepted (`db.FromEnv`); calorie uses `DB_DSN` — don't mix.
- `app_config` reads are cached 10s in-process: after inserting mail keys, wait ≤10s (or restart)
  before expecting `/health` `mailConfigured:true`.
- `key` / `value` are SQL keywords-ish: always quote `` `key` `` in app_config SQL.
- self-hosted runner: the step process has **no HOME** — workflows set it per-step
  (`HOME: ${{ github.workspace }}/../go-home`); don't hoist to job level.
- `.github/**` and `*.md` pushes don't trigger build.yml; after editing a workflow verify with
  `gh workflow run` (concurrency group cancels queued runs on rerun of old commits).
- A Laravel leftover `vendor/` dir once made `go build` fail with "inconsistent vendoring" —
  Go auto-enables -mod=vendor when a `vendor/` exists. Never reintroduce one (no vendoring here).
- Email brand strings live in one registry (`internal/auth/email.go`), pinned by
  `TestBrandEmailStrings`; a new brand = registry row + that test table, and its key must stay
  in sync with the `allowedApps` aud whitelist (`TestBrandForSelection` fails on drift).
- The three delete-hook keys (`hook_token` / `hook_calorie_diary` / `hook_expense_diary` in
  `app_config`) **must all be set in production**: a missing key is the legitimate "skip this
  App" state (real-DB tests rely on it to avoid any network call), so don't "fix" it; lose one
  App key in prod and that App's business rows turn into orphans silently on every delete.
- `TOTP_ENC_KEY` is a **second refuse-to-start secret** (≥32 bytes, same gate as
  `JWT_SECRET`): local runs and real-DB tests must provide it (`newTestService` sets it via
  `t.Setenv`). Losing it in prod invalidates every enrolled TOTP — only recovery codes remain,
  so it belongs in the ops backup next to `JWT_SECRET`.
- `__Host-` cookies require `Secure`, so a real browser drops them on plain http. Smoke-test
  pages with curl (`-b` jar works) or behind TLS; the route tests attach cookies by hand for
  the same reason.
- The `token` returned by `/web/login/*` and `/webauthn/login/finish` is a **web session
  token, not a JWT**: it authenticates the dual-credential routes only. `/internal/verify`
  and the diary APIs still require a JWT from `/auth/login` — never treat the web token as a
  drop-in replacement in an app client.
- An invalid `webauthn_opaque_origins` value logs an Error and **degrades to web-only
  origins** instead of refusing to start (login availability beats an optional feature);
  after touching that key, read the startup log for the downgrade line.
- Don't mass-run `gofmt`: Go 1.27's gofmt wants a space after `//` before a full-width
  parenthesis while this repo's comments don't — a blanket run rewrites every doc comment
  and drowns the diff (CI only runs build/vet/test, never gofmt).
- `otpStore.issue` holds a per-email `GET_LOCK` on a pinned conn (`issueLocked`): never call a
  `s.pool` statement while that lock is held — with the 8-conn pool saturated by concurrent
  issuers, the holder waits forever for a connection and never releases the lock (self-deadlock,
  hit and caught by `TestOTPStoreConcurrency`); cleanups run after `issueLocked` returns.
