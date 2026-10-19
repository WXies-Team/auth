# auth.horatio.cn 三功能实现规格：Passkey / TOTP 2FA / Web 自助台+管理后台

> 2026-01-19 调研交付（只读调研+规格，来源见文末索引）。实现以本文为准；与代码冲突时先改本文再写码。
> 依据：通读本仓全部源码 + 联网取证（W3C、go-webauthn、pquerna/otp、OWASP ASVS 5.0 / Cheat Sheet Series、developer.android.com、Supabase auth 生产实现）。

## 0. 现状盘点（决定所有接法的代码事实）

| 事实 | 出处 | 对规格的影响 |
|---|---|---|
| `sessions` 表已有 `id/user_id/app/device/ip/user_agent/created_at/last_seen_at/revoked_at`，token `sid` claim 指向它，踢人=置 `revoked_at` | schema.sql, auth.go | web 登录=再建一行 session；web 会话失效天然复用 `revoked_at` 闸 |
| `app_config` 10s 进程内缓存、`config.Store.Require` 读键 | config.go | 配置中心写入后 ≤10s 热生效，管理页需提示 |
| OTP 全语义在 `otp_codes`（sha256 落库、用后即焚、5 次错作废） | otp.go | TOTP 与邮箱验证码是两套，互不复用 purpose |
| 限流是进程内滑动窗口，单实例假设 | main.go, AGENTS.md | 新端点限流复用 `limiter`，不引外部依赖 |
| `protocol.go` 与 calorie-diary 的 auth 块要求 JSON 字段逐字一致 | protocol.go:1-7 | **只新增端点和可选字段，绝不动既有 DTO** |
| JWT aud 白名单 `calorie-diary/expense-diary`，`/internal/verify` 按 aud 精确匹配 | auth.go | web 会话**不签 JWT**，不往白名单加 "web" |
| 注销删除 otp_codes + sessions + users 行 | auth.go DeleteAccount | 新表必须挂进同一事务的删除清单 |
| calorie 侧已有 `ai_usage(scope,subject,day,count)` 与 `ai_rate_per_minute/ai_concurrency/ai_daily_*` 键 | calorie schema/llm/quota.go | AI 看板沿用此语义，记账迁入 auth 后零改表 |

---

# A 批（后端）

## A1 关键决策总表

### A1.1 WebAuthn：RP 配置与库选型

**库**：`github.com/go-webauthn/webauthn v0.18.2`（BSD-3-Clause，2026-09-19）。**必须 pin 精确版本**：`SessionData.Extensions` 序列化形态随版本漂移，落库 JSON 与升级绑定；v0.18.0 是大 breaking（PQC、attestation 拆分、cross-origin 收紧，迁移见其 MIGRATION.md）；v0.18.2 增量=attestation 加固 + finish 时 challenge 校验修复（#794）——**直接上 0.18.2，不 pin 0.18.0**。

**RP ID = `horatio.cn` 合法性**：规范要求 RP ID 等于 origin 的 effective domain 或其 registrable domain suffix（eTLD+1 或更宽）；`horatio.cn` 是 `auth.horatio.cn` 的 eTLD+1，合法且天然覆盖所有子域——所有 `*.horatio.cn` 共用同一批 passkey，**不需要 Related Origin Requests**（ROR 只在跨 eTLD+1 时才需要）。将来若出现第二注册域（horatio.com），才在 `https://horatio.cn/.well-known/webauthn` 挂 ROR 文档（v0.18 已原生支持 `WebAuthn.RelatedOrigins()`）——**本规格不启用，只留注释位**。

**配置定案**（v0.18.2 Config，逐字段核自源码 types.go）：

```go
webauthn.Config{
    RPID:          "horatio.cn",
    RPDisplayName: "Auth",
    RPOrigins:     []string{"https://auth.horatio.cn"},
    // Android 原生仪式的 clientData origin 是不透明形态，逐一登记两 App 签名证书指纹
    RPOpaqueOrigins: []string{
        "android:apk-key-hash:<APP签名证书sha256的base64>",
    },
    // v0.18.2 实名核自源码：attestation:none = PreferNoAttestation，
    // UV required = VerificationRequired（旧稿写的 ConveyanceNone /
    // UserVerificationRequirementRequired 在该版本已不存在，按「与代码冲突先改本文」订正）
    AttestationPreference: protocol.PreferNoAttestation,
    AuthenticatorSelection: protocol.AuthenticatorSelection{
        ResidentKey:      protocol.ResidentKeyRequirementRequired, // discoverable 前提
        UserVerification: protocol.VerificationRequired,           // UV 必需
    },
    Timeouts: webauthn.TimeoutsConfig{
        Login:        webauthn.TimeoutConfig{Enforce: true}, // 服务端也执行超时
        Registration: webauthn.TimeoutConfig{Enforce: true},
    },
}
```

依据：`RPOpaqueOrigins` 官方注释即以 `android:apk-key-hash:` 举例；不透明 origin 精确串比对、不能被仪式绑定；attestation=none + UV=required 是消费级 passkey 标准组合（来源：go-webauthn types.go 原文）。

**SessionData 存法 → 落库**。库官方文档要求可恢复且「safely anchored to a user agent」，持久化只支持 json/MessagePack 整体序列化；Supabase auth 生产实现整体 JSON 落库带 expires_at、按 challenge 索引、Finish 消费；ASVS V7.2.3（CSPRNG ≥128 位熵服务端校验）、V6.5.5（认证凭证需定义生命周期）。定案：**5 分钟过期（对齐本仓验证码 TTL）、用后即焚（Finish 成功/失败都删行）**；内存 map 在重启/多实例下作废（本仓把 OTP 从内存迁库的同款理由）。

**Credential 服务端语义**：字段映射按库 README 的 Credential Record 表逐列落库（ID、PublicKey、SignCount、Transport、Flags.BackupEligible/BackupState、AAGUID）；**`rpId` 库不管必须自己存列**（credentials MUST be partitioned by RP ID）；**每次登录成功回写 signCount 与 backupState**。signCount 防克隆：同步型 passkey 常报 0，策略=**new≤old 且 old≠0 时记审计告警、不拒绝**（拒绝会误杀同步 passkey，业界通行）。

**改名/删除**：改名只 UPDATE name；删除=删行即刻对后续仪式不可见。删除守卫：**若该用户只剩这一个 passkey 且无密码、无 TOTP → 400**，保住「至少一种登录方式」（OWASP MFA CS：恢复不得弱于常规登录）。

**discoverable 登录 API**（v0.18.2 实名核实）：`BeginDiscoverableLogin(opts...) (*protocol.CredentialAssertion, *SessionData, error)`；`FinishPasskeyLogin(handler DiscoverableUserHandler, session SessionData, response *http.Request)`，handler 签名 `(rawID, userHandle []byte) (User, error)`——用 userHandle（=`WebAuthnID()`）反查用户。`WebAuthnID()` = **uid 的 8 字节大端**（≤64 字节、稳定、可逆；uid 自 2026-10 起为 **7 位随机整数** 1,000,000~9,999,999，本文旧版口径「雪花 uid」已随之作废，但编码仍是 8 字节定长，新旧 uid 同一套编解码）；不用邮箱（可改，userHandle 必须稳定）。注册侧 `BeginRegistration/FinishRegistration`；已登录二因子场景用 `BeginMediatedLogin`（identity 已知），与 discoverable 分开。

### A1.2 TOTP：参数、绑定流程、恢复码

**库**：`github.com/pquerna/otp v1.5.0`（Apache-2.0）。`totp.Generate(GenerateOpts{Issuer, AccountName,...})`（Issuer/AccountName 必填）；`totp.Validate(passcode, secret)` 内部 Period30/Digits6/Skew1——**30s/6位/±1 就是库的 Google-Authenticator 兼容默认**（RFC 6238 同；ASVS 6.5.5「TOTP lifetime 30s」）。QR：**库自带** `key.Image(w,h)`（内部 boombuler/barcode，MIT）→ `image/png` + base64 出 data URI，**零额外 QR 依赖**（skip2/go-qrcode 不引）。`otpauth://` 由 `key.URL()` 生成（Google Authenticator Key Uri Format）；同时回 secret 明文供手输（Supabase 同做法：`{qr_code, secret, uri}`）。

**「先验后启」绑定**（pquerna README 官方五步 + Supabase 佐证）：
1. `POST /api/totp/setup`：生成 secret，**落库 enabled=0（pending）**，返回二维码+secret——此时 2FA 状态恒「未开启」；
2. `POST /api/totp/enable {code}`：验一次码，**验过才 enabled=1**，同事务生成恢复码；
3. 已绑定再 setup = 重置流程：新 secret 仍 pending，**旧 TOTP 保持 enabled 直到新码验证通过**——攻击者无法用「发个 setup 就废掉受害者 2FA」。

**防重放**：`totp_factors.last_used_timestep`——验证成功记录 timestep，同 timestep 重放拒绝（ASVS 6.5.1「TOTP 只能成功使用一次」）。

**解绑需近期认证**：ASVS V7.5.1 明文要求 MFA 配置变更前 full re-auth。定案：解绑/重置 TOTP、改邮箱、改密码、删除全部 passkey 均要求 `reauth_at` **15 分钟内**，否则 401 `reauth_required` → 前端 `POST /web/reauth` 重验刷新。

**恢复码 = 标配，做**。pquerna 流程第 5 步、OWASP MFA CS 均要求；GitHub：16 个单次用、重生成全作废。定案 **10 个**，格式 `XXXX-XXXX-XXXX-XXXX`（16 位 Crockford 风格 ≈80 位熵）；存储 **HMAC-SHA256（pepper=JWT_SECRET 派生域分隔串）**（ASVS 6.5.2 lookup secret 口径，不引 bcrypt）。用一少一，用完/重置整组换新旧组即废。

**TOTP secret 存储**：pquerna README 明确「store the secret in an encrypted field」（验证需原值）。定案 **AES-256-GCM（标准库 crypto/aes+cipher，零新依赖）**，密钥=新环境变量 `TOTP_ENC_KEY`（≥32 字节，与 JWT_SECRET 同拒启口径）。**唯一新增环境变量（Ask-first 已批）**。

**登录编排**（与邮箱验证码体系的组合）：
- **邮箱验证码登录不做 TOTP 二步**（邮件通道即持有因子，ASVS 5.0 V6.3.6 email 不可作认证机制；叠输入体验差）。
- **密码登录 → TOTP 串行两步**（2FA 已启用时）：密码验过发**短时单次登录态令牌**（`login_states` 表，5 分钟、sha256 落库、用后即焚），再 `POST /web/login/totp` 换会话（Supabase/标准 IdP 同形）。
- **passkey 登录后不再要 TOTP**（discoverable+UV=required 属 NIST 多因子密码学认证器，AAL2 单独成立；ASVS 6.3.3 L2 允许 multi-factor **or** 组合单因子；GitHub/Google 实际行为一致）。
- TOTP 失败限流：login_state attempts **错 5 次烧毁**（与邮箱验证码同口径）+ IP 15/分 + uid 10/分（复用 limiter）。

### A1.3 管理员判定

| 方案 | 结论 |
|---|---|
| **users 加 role 列** | **推荐采纳**：按 uid 主键点查、与改绑解耦、可审计、deny-by-default（ASVS V8 server-side+least privilege） |
| app_config 邮箱白名单 | 否决：改绑绕过/无索引/10s 缓存撤销空窗 |
| 邀请码首管理员 | 不做（YAGNI，bootstrap 一次手工 SQL 即可） |

定案：`users.role VARCHAR(16) NOT NULL DEFAULT 'user'`（`user`/`admin`）；首管理员部署文档一条 SQL，也记审计。**admin 还必须绑定 TOTP 或 passkey 才能进管理后台**（OWASP MFA CS：admin 强制 MFA），管理写操作要求 reauth ≤15 分钟。

### A1.4 审计日志 schema（新建表）

依据 ASVS V16.3（认证成败全记含因子、授权失败、绕过尝试）、V16.2.1（who/what/when/where）、V16.2.5（敏感值掩码）、V16.4.2（不可篡改）：

```sql
CREATE TABLE IF NOT EXISTS audit_logs (
    id          BIGINT       NOT NULL,             -- 雪花，时间有序
    ts          BIGINT       NOT NULL,             -- UTC 毫秒
    actor_uid   BIGINT       NULL,                 -- 匿名事件（注册/登录失败）NULL
    actor_email VARCHAR(255) NOT NULL DEFAULT '',  -- maskEmail 后落库
    action      VARCHAR(64)  NOT NULL,
    result      VARCHAR(8)   NOT NULL,             -- ok / fail
    target_uid  BIGINT       NULL,
    ip          VARCHAR(45)  NOT NULL DEFAULT '',
    user_agent  VARCHAR(512) NOT NULL DEFAULT '',
    detail      TEXT         NULL,                 -- JSON，只放非密钥结构化信息
    PRIMARY KEY (id),
    KEY idx_audit_actor (actor_uid, ts),
    KEY idx_audit_target (target_uid, ts),
    KEY idx_audit_action (action, ts)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
```

**事件清单**：`register`、`login.success`/`login.fail`（detail.method=password/email_code/totp/recovery/passkey——与代码实值一致，恢复码的 method 落 `recovery`）、`logout`、`password.change`、`password.reset`、`email.change`、`passkey.create/rename/delete`、`totp.setup/enable/disable`、`recovery.generate/consume`、`session.kick`；admin 操作前缀 `admin.`：`admin.user.role_change`、`admin.user.session_revoke`、`admin.session.revoke`、`admin.config.set`（**只记 key 与「旧值是否已配置」，不记值**）、`admin.audit.view`、内部并入 `internal.ensure`。保留 90 天（照 otpRetention 清理模式挂发码路径）；表只增无业务 UPDATE/DELETE（应用层不可篡改；物理防篡改为已声明残余风险）。

### A1.5 表结构变更汇总（全部幂等）

```sql
-- passkey 凭证（rp_id 列必须有：rpId 要自己存、按 RP 分区）
CREATE TABLE IF NOT EXISTS passkeys (
    id               BIGINT       NOT NULL,
    user_id          BIGINT       NOT NULL,
    name             VARCHAR(64)  NOT NULL,        -- 用户可改名，默认 AAGUID/UA 推断
    credential_id    VARCHAR(512) NOT NULL,         -- base64url，UNIQUE
    rp_id            VARCHAR(64)  NOT NULL,         -- 恒 'horatio.cn'
    public_key       VARBINARY(1024) NOT NULL,
    sign_count       BIGINT       NOT NULL DEFAULT 0,
    transports       VARCHAR(64)  NOT NULL DEFAULT '',
    aaguid           CHAR(32)     NOT NULL DEFAULT '',
    backup_eligible  TINYINT      NOT NULL DEFAULT 0,
    backup_state     TINYINT      NOT NULL DEFAULT 0,
    created_at       BIGINT       NOT NULL,
    last_used_at     BIGINT       NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_passkeys_cred (credential_id),
    KEY idx_passkeys_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- TOTP 因子：一用户一条；enabled=0 为 pending（先验后启）
CREATE TABLE IF NOT EXISTS totp_factors (
    user_id            BIGINT      NOT NULL,
    secret_cipher      VARBINARY(256) NOT NULL,   -- AES-256-GCM(nonce||ct)
    enabled            TINYINT     NOT NULL DEFAULT 0,
    last_used_timestep BIGINT      NOT NULL DEFAULT 0,
    created_at         BIGINT      NOT NULL,
    confirmed_at       BIGINT      NULL,
    PRIMARY KEY (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- 恢复码：整组原子换新，used=1 不删行
CREATE TABLE IF NOT EXISTS recovery_codes (
    id         INT          NOT NULL AUTO_INCREMENT,
    user_id    BIGINT       NOT NULL,
    code_hash  CHAR(64)     NOT NULL,   -- HMAC-SHA256(pepper=JWT_SECRET 域分隔派生)
    used       TINYINT      NOT NULL DEFAULT 0,
    used_at    BIGINT       NULL,
    created_at BIGINT       NOT NULL,
    PRIMARY KEY (id),
    KEY idx_recovery_user (user_id, used)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- WebAuthn 仪式 SessionData（单次性+过期）
CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id           BIGINT      NOT NULL,   -- 雪花 ceremonyId，回给前端
    kind         VARCHAR(16) NOT NULL,   -- register / login
    user_id      BIGINT      NULL,       -- login(discoverable) NULL
    session_data TEXT        NOT NULL,   -- SessionData JSON 原样（库规定唯一持久化形态）
    expires_at   BIGINT      NOT NULL,   -- now+5min
    created_at   BIGINT      NOT NULL,
    PRIMARY KEY (id),
    KEY idx_chal_exp (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- 两步登录中间态（password 验过、TOTP 未验）
CREATE TABLE IF NOT EXISTS login_states (
    token_hash CHAR(64)    NOT NULL,     -- sha256(回给前端的随机 token)
    user_id    BIGINT      NOT NULL,
    method     VARCHAR(16) NOT NULL,     -- totp / recovery
    attempts   INT         NOT NULL DEFAULT 0,
    expires_at BIGINT      NOT NULL,     -- now+5min
    created_at BIGINT      NOT NULL,
    PRIMARY KEY (token_hash),
    KEY idx_ls_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- AI 记账（P2.5 迁入 auth；与 calorie 现表同构，先建空表零迁移）
CREATE TABLE IF NOT EXISTS ai_usage (
    scope   VARCHAR(8)  NOT NULL,        -- user / global
    subject VARCHAR(32) NOT NULL,         -- uid 或 'global'
    day     VARCHAR(10) NOT NULL,         -- YYYY-MM-DD
    count   INT         NOT NULL,
    PRIMARY KEY (scope, subject, day)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- 列变更（nullable/default，老行自动填充；MySQL ADD COLUMN 无 IF NOT EXISTS，
-- EnsureSchema 需新增 information_schema 探测的 ensureColumn 帮手）
ALTER TABLE users    ADD COLUMN role VARCHAR(16) NOT NULL DEFAULT 'user';
ALTER TABLE sessions ADD COLUMN web_token_hash CHAR(64) NULL;   -- web cookie sha256，UNIQUE
ALTER TABLE sessions ADD COLUMN web_csrf_hash  CHAR(64) NULL;   -- CSRF 同步器 token sha256
ALTER TABLE sessions ADD COLUMN reauth_at      BIGINT   NULL;   -- 最近强认证时间
```

`sessions.app` 写 `'web'`；`device` 走现有 `shortDevice`（桌面 UA 得「Chrome · Linux」）。**注销联动**：DeleteAccount 事务追加删 `passkeys`/`totp_factors`/`recovery_codes`/`webauthn_challenges`（按 user_id）；`audit_logs` 保留但匿名化（action 留存、actor_email 清空；作者倾向同删也可，两可标注）。

### A1.6 依赖清单

| 模块 | 版本 | 许可证 | 用途 | 替代 |
|---|---|---|---|---|
| `github.com/go-webauthn/webauthn` | **v0.18.2 精确 pin** | BSD-3-Clause | WebAuthn 全量校验 | 无（唯活跃 Go RP 库） |
| 　传递：fxamacker/cbor/v2、google/uuid 等 | — | BSD/MIT | 库自带 | — |
| `github.com/pquerna/otp` | **v1.5.0** | Apache-2.0 | TOTP | — |
| 　传递：`github.com/boombuler/barcode` | 传递 | **MIT** | QR（经 key.Image） | skip2/go-qrcode 不引 |

**新增直接依赖仅这两个**；QR 出图=标准库 image/png+base64；模板=html/template+embed；TOTP 加密=crypto/aes+cipher；token/恢复码=crypto/rand+sha256。不引路由框架、不引前端框架/构建链。

## A2 端点清单

统一：错误体 `ApiError{message}`（中文，what+next-step）；新端点挂 `/web/*`、`/webauthn/*`、`/api/totp*`、`/api/passkeys*`、`/admin/*`；**老端点一行不动**；JSON 命名沿用 camelCase。

**新中间件两件**：
- `withWebSession`：读 cookie `__Host-auth_web` → sha256 → 查 `sessions.web_token_hash`（行存活、未 revoked、created_at 绝对 90 天内、last_seen_at 空闲 7 天内）→ `Caller{UID, SID:行id, App:"web"}`；**同时接受 Bearer**（withUID 逻辑复用），C 批 App 复用 passkey/TOTP 管理端点——双凭据刻意并存：授权语义相同、互不串用（各自撞 revoked_at 闸），CSRF 头+Origin 校验兜住跨站。
- `requireReauth`（15 分钟窗）+ `requireAdmin`（role=admin，**每请求现查 users 行不缓存**——token_version「吊销从不缓存」同款理由）。

### A2.1 Passkey（web 与 Android 共用）

| Method/Path | 鉴权 | 请求 | 响应 |
|---|---|---|---|
| `POST /webauthn/register/options` | 已登录 | `{}` | `{publicKey: <CredentialCreation.publicKey>, ceremonyId}` |
| `POST /webauthn/register/finish` | 已登录 + reauth≤15min | `{ceremonyId, response}`（浏览器 Credential JSON 透传；日记 App 发的 JSON **字符串**形态由路由层解一层，两形态都交库校验） | `{id, name, createdAt}`；删 ceremony 行；审计 |
| `POST /webauthn/login/options` | 无 | `{}` | `{publicKey: <CredentialAssertion.publicKey>, ceremonyId}`（discoverable：空 allowCredentials+UV required） |
| `POST /webauthn/login/finish` | 无 | `{ceremonyId, response, app}`（`app` 可选） | `app` 空：建 session(app='web')+双 cookie+`{token,email}`（**与 AuthResponse 同形**，token 恒空串——凭据只在 cookie）；`app` 在白名单（calorie-diary/expense-diary）：建 session(app=`<app>`)、签**既有格式 JWT**（/auth/login 同一签发助手：同 aud 白名单/ver/sid/90 天）回 `{token,email}`、**不下发 cookie**，白名单外 400；2FA 不影响（passkey 单独成立）；审计 login.success method=passkey（detail 可带 app） |
| `GET /api/passkeys` | 已登录 | — | `[{id,name,createdAt,lastUsedAt,current}]`（current 按 credential_id） |
| `PATCH /api/passkeys/{id}` | 已登录 | `{name}`（≤64 trim） | `{ok:true}` |
| `DELETE /api/passkeys/{id}` | 已登录 + reauth | — | `{ok:true}`；最后一道登录方式守卫 400；审计 |

### A2.2 TOTP

| Method/Path | 鉴权 | 请求 | 响应 |
|---|---|---|---|
| `GET /api/totp` | 已登录 | — | `{enabled, createdAt}` |
| `POST /api/totp/setup` | 已登录+reauth | `{}` | `{secret, otpauthUri, qrPng(data URI)}`；落 pending |
| `POST /api/totp/enable` | 已登录+reauth | `{code}` | `{recoveryCodes:[×10]}`（**只回这一次**）；同事务 enabled=1+生成恢复码；审计×2 |
| `POST /api/totp/disable` | 已登录+reauth | `{code}`（TOTP 或恢复码） | `{ok:true}`；建议随后吊销其它会话（ASVS 7.4.3） |
| `POST /api/totp/regenerate-recovery-codes` | 已登录+reauth | `{code}` | 新 10 个；旧组即废 |

### A2.3 登录编排（新端点，老端点零改动）

| Method/Path | 请求 | 响应 |
|---|---|---|
| `POST /web/login/password` | `{email,password,app}` | 无 2FA：`{token,email}`；有 2FA：`{status:"2fa_required", loginToken, methods:["totp","recovery"]}`。**app 分流（C 批）**：缺省 = web 流程，双 cookie + 回体 token 恒空串（凭据只在 cookie）；在白名单 = App 流程，token 是业务 JWT、**不下发 cookie**（外值 400）。有 2FA 时 app 随 `login_states.app`（`VARCHAR(32) NOT NULL DEFAULT 'web'`，ensureColumn 幂等补列）带到第二步 |
| `POST /web/login/totp` | `{loginToken, code}` 或 `{loginToken, recoveryCode}` | `{token,email}`；恢复码消费记审计。**请求里没有 app**：按 `login_states.app` 决定发 web 会话 + 双 cookie（'web'，回体 token 恒空串）还是业务 JWT 无 cookie（白名单应用）；audit detail 可带 app |
| `POST /web/session`（登录态） | — | `{uid,email,role,csrfToken,totpEnabled,passkeyCount}` |
| `POST /web/reauth` | cookie + `{password}` 或 `{totpCode}` | `{ok:true}`（刷 reauth_at） |
| `POST /web/logout` | cookie + CSRF | `{ok:true}`；吊销本行 + `Clear-Site-Data` |

兼容开关：`app_config` 键 `totp_enforce_apps`（逗号分隔，**默认空=老客户端密码登录不拦**）——`/auth/login` 对名单内 app 在用户已启用 2FA 时回 401「请升级应用后使用新版登录」。C 批覆盖率足够后作者手动开。**老客户端不被破坏硬约束下的唯一开关，默认态零影响**（ASVS 6.3.4 一致化只能随客户端淘汰渐进，在此声明）。

### A2.4 用户自助（复用既有）

`GET/DELETE /api/sessions*`、`/auth/change-*`、`/auth/send-change-*`、`/auth/delete` **原样复用**（authed 中间件补 accept cookie 会话即可），响应体不动。

### A2.5 Admin

| Method/Path | 鉴权 | 说明 |
|---|---|---|
| `GET /admin/users?query=&limit=&offset=` | admin+MFA+reauth | `[{uid,email,role,createdAt,totpEnabled,passkeyCount}]` |
| `GET /admin/users/{uid}` | 同 | 详情+活跃会话摘要+凭证摘要 |
| `PATCH /admin/users/{uid}` | 同 | `{role}`；**禁止降级自己**（最后 admin 守卫）；审计 |
| `POST /admin/users/{uid}/revoke-sessions` | 同 | 踢全部（ASVS 7.4.5）；审计 |
| `GET /admin/sessions?uid=&limit=&offset=` | 同 | 全站会话总览 |
| `DELETE /admin/sessions/{id}` | 同 | 幂等；审计 |
| `GET /admin/audit?action=&actor=&target=&from=&to=&limit=&offset=` | 同 | 审计查询倒序分页 |
| `GET /admin/config` | 同 | 白名单键（mail_*/hook_*/llm_*/fcm*/ai_*）→ `[{key,configured,hint}]`；**secret 只回 configured+末4位 hint**；非 secret 回全文 |
| `PUT /admin/config/{key}` | 同 | `{value}`；空串=删键；未知键 404；**key 限 ≤64 字符 [A-Za-z0-9_]、`ai_*` 键值必须正整数、`ai_usage_merged_at` 只读（400「此键由迁移脚本写入，不可编辑」——防全站 AI 计数翻倍）**；提示「≤10 秒热生效」；审计只记 key |
| `GET /admin/ai-usage?days=30` |同 | `{days:[{day,total,byUserTop10}], quota:{perMinute,concurrency,dailyPerUser,dailyGlobal,configured}}`（限额键缺省对齐 quota.go 默认 20/8/500/5000）；空表回 `暂无记录` |

## A3 实现顺序与测试清单

1. **表结构**：schema.sql +6 表 +4 ALTER；EnsureSchema 新增 `ensureColumn` 帮手（information_schema 探测）。测试：空库全建、二跑幂等、老库补列。
2. **web 会话层**：cookie 签发/校验/过期/CSRF 中间件 + reauth_at。测试：往返、hash 不符 401、空闲/绝对超时、revoke 后 401、Bearer 与 cookie 并存互不干扰。
3. **TOTP 包**：setup/enable/disable/重放/恢复码。测试：先验后启、同 timestep 重放拒、5 次错烧 login_state、恢复码单次性与整组换新、AES-GCM 往返。
4. **Passkey 包**：注册/发现式登录/改名/删除守卫。测试：ceremonyId 单次性（重放 404）、过期 404、userHandle=uid 反查、signCount 回写与告警、credential_id 冲突 409、删除最后一道登录方式 400。
5. **登录编排**：`/web/login/*` + enforce 开关。测试：**老 `/auth/login` 回归零变化**、2FA 两步、passkey 直登。
6. **审计**：全事件落表+90 天清理。测试：断言存在且 detail 无密钥（白盒 grep）。
7. **Admin**：授权矩阵（非 admin 403、无 reauth 401、降级自己 400）、配置掩码（secret 不出现在任何响应体，全量 grep 断言）、AI 聚合。
8. **注销联动**：新表清理进事务。

测试基建：DB 用例沿用 `TEST_MYSQL_DSN` 专用 schema（绝不指向生产）；WebAuthn 测试用库 protocol 层构造（不引浏览器）。

---

# B 批（Web UI）

## B1 会话机制定案

**httpOnly cookie，不用 Bearer-in-SPA**。OWASP Session CS：「Do not store authentication tokens, session IDs, JWTs in localStorage」。

- 会话 cookie：`__Host-auth_web`（`Secure; HttpOnly; SameSite=Strict; Path=/`；`__Host-` 前缀为 OWASP 推荐形态）；值=32 字节 CSPRNG base64url（≥128 位熵，ASVS 7.2.3）；服务端只存 sha256（`sessions.web_token_hash`），常数时间比对（雪flake sid 可预测不能直接进 cookie——identifier/verifier 思路）。
- **CSRF：同步器 token 模式**（有状态站点 OWASP 定案）。双 cookie：`__Host-auth_web_csrf`（非 HttpOnly JS 可读）+ sha256 存 `sessions.web_csrf_hash`。所有 `/web/*`、`/admin/*` 非 GET 必须带 `X-CSRF-Token`，不符 403。SameSite=Strict 只当纵深防御不单独依赖（OWASP：SameSite 是 defense in depth，Lax 有 GET 顶层导航缺口）。自定义头是 OWASP 给 API-driven 站点的推荐路径。
- 超时：空闲 7 天（last_seen_at，已有 60s 节流）/ 绝对 90 天（created_at，对齐 JWT TTL）。OWASP 15-30 分钟参考区间对个人控制台过激——**文档化偏离**（ASVS 7.1.1 允许 documented+justified）：低敏个人数据、设备列表已有踢人自卫。
- 登出：吊销行 + `Clear-Site-Data` 头；全部会话响应 `Cache-Control: no-store`。web 登录/改密回体 `{token,email}` 形状不变但 **token 恒空串**——凭据只在 HttpOnly cookie，前端（internal/ui/app.js）不读 body token。
- 与 Bearer 并存：`/webauthn/*`、`/api/totp*`、`/api/passkeys*` 双凭据；**`/admin/*` 只收 cookie**（缩小面）。web 登录=sessions 又一行（app='web'），App 设备页自然看到并可踢。

## B2 页面清单（零 CDN：html/template+内联 CSS/JS；图标内联 SVG；系统字体）

文案：错误=发生了什么+下一步、中文、按钮动词；对比度 AA（沿用 #1c1c1e/#6e6e73 on #fff）；点击区 ≥40px；动效仅 opacity/transform ≤150ms + reduced-motion 关闭；中性品牌「Auth」。

| 页面 | 线框要点 | 端点 |
|---|---|---|
| `/web/login` | 单卡片：邮箱+密码 or 邮箱验证码 tab；分隔线「或」+「使用 Passkey 登录」（不支持则隐藏）；2FA 用户密码提交后原地变「输入两步验证码」（含「用恢复码登录」） | `/web/login/*`、`/webauthn/login/*`、`/auth/send-code` |
| `/web/console` 概览 | 身份卡；安全状态三行（密码/两步验证/Passkey N 个）各带管理入口；退出登录 | `POST /web/session`、`GET /api/totp`、`GET /api/passkeys` |
| `/web/console/sessions` 设备 | 行：设备标签·App·IP·最近活跃；本机行不可踢；踢除；顶部「退出其它设备」 | `/api/sessions*` |
| `/web/console/passkeys` | 名称行内改名；「添加 Passkey」；删除确认（原生 `<dialog>`）；**至少保留一种登录方式**提示 | `/api/passkeys*`、`/webauthn/register/*` |
| `/web/console/security` 2FA | 未开启：开启→弹层二维码 data URI+手输密钥+6 位→绑定→**恢复码一次性列表**（等宽排版、「关闭后无法再查看」、Blob 下载 .txt 全内联）→已保存。已开启：状态+重生成恢复码+关闭（均需当前 TOTP/恢复码） | `/api/totp*` |
| `/web/console/account` | 改密码两 tab（原密码版/验证码版）、改邮箱、注销（红「清除数据并注销」+密码确认+`<dialog>` 二次） | `/auth/change-*`、`/auth/delete` |
| `/web/admin` 用户 | 搜索+分页表；详情抽屉：会话列表、吊销；角色切换（最后守卫） | `/admin/users*` |
| `/web/admin/sessions` | 全站会话表+uid 过滤+吊销 | `/admin/sessions*` |
| `/web/admin/audit` | 时间/actor/action/result/target/IP+筛选 | `/admin/audit` |
| `/web/admin/config` 配置中心 | 分组（邮件/注销钩子/LLM/FCM/AI 限额）；secret 显示「已配置····末4」或「未配置」，留空提交=不改，「清除」单独按钮；提交后提示「≤10 秒生效」；**任何 secret 全文不回显** | `GET /admin/config`、`PUT /admin/config/{key}` |
| `/web/admin/ai-usage` | 30 天柱状条（纯 CSS div 宽度，无图表库）+今日计数+四限额当前值；空数据 `暂无记录` | `GET /admin/ai-usage` |

**assetlinks.json 要求**（主 agent 落地）：挂 `https://horatio.cn/.well-known/assetlinks.json`（按 RP ID 域名取，非 auth 子域），`Content-Type: application/json`，每 App 一条 statement：

```json
[{"relation": ["delegate_permission/common.get_login_creds"],
  "target": {"namespace": "android_app",
             "package_name": "<包名>",
             "sha256_cert_fingerprints": ["<发布签名证书 SHA-256>"]}}]
```

依据：developer.android.com prerequisites（passkey 必须 DAL、relation=get_login_creds、指纹取 Release/App signing 页）。

---

# C 批（日记 App 客户端：calorie 先行，expense 跟进）

## C1 Kotlin 侧 API 契约

- **Passkey 注册**（已登录设置页）：`POST {authBase}/webauthn/register/options`（Bearer）→ `{publicKey, ceremonyId}`；**publicKey 整体序列化为 JSON string** 进 `CreatePublicKeyCredentialRequest(requestJson=…)` → `CredentialManager.createCredential` → 类型判别 `PublicKeyCredential.TYPE_PUBLIC_KEY_CREDENTIAL` → `registrationResponseJson` → `POST /webauthn/register/finish {ceremonyId, response:<该JSON>}`。（1.6.0 起 `isAutoSelectAllowed` 适合登录成功后顺手引导绑定。）
- **Passkey 登录**：`POST /webauthn/login/options {}` → `GetCredentialRequest(listOf(GetPublicKeyCredentialOption(requestJson=…)))` → `authenticationResponseJson`（**JSON 字符串**）→ `POST /webauthn/login/finish {ceremonyId, response:<该JSON>, app}` → **响应即 `{token,email}`（AuthResponse 同形），登录态落地零新写**；带 `app`（白名单）时该 token 是业务 JWT、服务端不下发 cookie，缺省 app = web 会话 token + 双 cookie（旧网页流程原样）。
- **TOTP 二步**：`POST /web/login/password {email,password,app}` → `{status:"2fa_required", loginToken}` → TOTP 输入页 → `POST /web/login/totp {loginToken, code}` → `{token,email}`（第二步不传 app，服务端随 `login_states` 带下来决定发 JWT 还是 web 会话）。2FA 管理页复用 `/api/totp*`（Bearer）。
- base URL 已是 auth.horatio.cn，本批只加端点。

## C2 Credential Manager 集成要点

- 依赖 `androidx.credentials:credentials:1.6.0` + `credentials-play-services-auth:1.6.0`（2026-04-08 稳定版；1.7.0-alpha 不追）。**Android-only 未 KMP 化**——放 androidMain，commonMain 不引。
- minSdk passkeys 要求 **API 28+**（Android 9）——calorie 现 minSdk 需核对，<28 则按 `Build.VERSION` 隐藏入口。
- RP ID 同 `horatio.cn`：**App 建的与网页建的是同一批 passkey**（同 RP+DAL 配对互通）；App 仪式 clientData origin 为 `android:apk-key-hash:…`，服务端 `RPOpaqueOrigins` 精确放行。
- `GetCredentialException`/`CreateCredentialException`（用户取消）走现有错误 toast 口径，不弹恐吓文案。

## C3 assetlinks

同 B 批格式；两仓各供包名+发布证书指纹（Play App Signing 取 Google 签名那份）；部署在主 agent 批次。可选二期：`/.well-known/passkey-endpoints` 让密码管理器直连管理 passkey（Google 官方建议）。

---

# D 风险与兼容性清单

1. **老客户端（硬约束）**：`/auth/*` 与 `/api/sessions*` 零形状变化；新字段只在新端点。唯一交互变化= `totp_enforce_apps` 开启后的 401，默认关、翻开关是作者显式动作。decode 不拒未知字段保证前向兼容。
2. **生产数据**：sessions/users ALTER 对小表瞬时（Ask-first 已批）；audit_logs 只增+90 天清理不会无限长。
3. **单实例假设**：新限流全进程内；challenge/login_state 落库重启不丢；多实例前需换共享限流（仓 AGENTS 已声明，本批不加剧）。
4. **依赖面**：新增直接依赖 2（BSD-3/Apache-2.0）；go-webauthn v0.x minor 可能 breaking——**pin 精确版本**，升级必须连挑战表未过期行一起清。
5. **`TOTP_ENC_KEY`**：缺失拒启（与 JWT_SECRET 同口径）；丢失=已绑用户 TOTP 全作废（只剩恢复码）——运维备份写进部署文档。
6. TOTP 密钥轮换：未设计（YAGNI，文档写明）。
7. 管理员自举：一次手工 SQL；忘记/失窃走另一管理员或 SQL（个人规模可接受）。
8. 审计物理防篡改（DBA 可改行）：已声明残余风险；slog 双文件流可当旁路。
9. signCount 克隆检测：告警不拒绝（防误杀同步 passkey），接受残余风险（业界同）。
10. **nginx**：新路径同 origin 无需新 vhost；`/.well-known/assetlinks.json` 由 horatio.cn 根站提供且 `Content-Type: application/json`（DAL 失效=App 看不到网页建的 passkey，静默失效——上线后用 Google DAL 验证工具过一遍）。

## 来源索引

- W3C WebAuthn L3 RP ID 规则 https://www.w3.org/TR/webauthn-3/#sctn-rp-id-requirements ；web.dev RP ID 深潜 https://web.dev/articles/webauthn-rp-id
- go-webauthn v0.18.2 https://pkg.go.dev/github.com/go-webauthn/webauthn ；releases（v0.18.0 breaking/MIGRATION、v0.18.2 #794）；master types.go/doc.go 原文
- Supabase auth 生产实现 internal/api/passkey_authentication.go、mfa.go
- pquerna/otp v1.5.0 https://pkg.go.dev/github.com/pquerna/otp ；boombuler/barcode(MIT)
- OWASP ASVS 5.0 V6/V7/V8/V16（条款号见正文）；Cheat Sheets：Session Management、CSRF Prevention、Multifactor Authentication、Authentication
- GitHub 恢复码文档（16 个/单次/重生成作废）
- Android：credentials releases（1.6.0）、Credential Manager prerequisites（DAL/get_login_creds）、About passkeys（API 28+）、CreatePublicKeyCredentialRequest/PublicKeyCredential API 参考
