-- 统一账号服务表结构。
--
-- 全新库，仍只用 CREATE TABLE IF NOT EXISTS：幂等对重复启动与并发启动都安全，
-- 本文件不出现任何 DROP/ALTER。
-- 时间戳列一律 BIGINT 毫秒（与两个日记服务同口径），不用 DATETIME，
-- DSN 里的 parseTime 因此无关紧要。

-- 账号表。id 是 **7 位随机整数**（1,000,000~9,999,999，注册时由服务生成，
-- **不自增**，见 internal/auth/uid.go 的 newUserID）——随机取号同样不暴露注册顺序，
-- 且可口播可手输；2026-10 前为 63 位雪花 id，存量行已由一次性迁移改写
-- （迁移已完成，脚本已移除；映射表由主 agent 清库）。
-- password_hash 允许 NULL：预留给纯验证码登录的账号形态（P0 的注册路径恒写入）。
-- role / password_must_change / pending_delete_at / login_notify 四列由 internal/db
-- 的 ensureColumn 启动时探测后补（见文件末尾的补列说明）：password_must_change=1 是
-- 「强制改密」态（管理员重置后置位、自助改密时清零），pending_delete_at 非 0 是注销
-- 申请时刻毫秒（0=正常，7 天宽限到期由清扫执行，见 internal/auth 的注销宽限期），
-- login_notify=1 开启「新设备登录提醒」（W1，默认开，GET/PUT /api/profile 可改）。
CREATE TABLE IF NOT EXISTS users (
    id            BIGINT       NOT NULL,
    email         VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NULL,
    created_at    BIGINT       NOT NULL,
    token_version INT          NOT NULL DEFAULT 1,
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_email (email)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;

-- 邮箱验证码。语义对齐原内存实现（6 位数字 / 5 分钟过期 / 60 秒冷却 / 每用途每日
-- 10 条 / 错 5 次作废 / 用后即焚 / 跨用途收件人每日总闸 15 条），全部闸门靠这张表
-- 与 (email, purpose, used, created_at) 上的查询实现，重启不再丢码。
--
-- used 标记「这行已作废」而不是删行：删行会让按 created_at 的每日计数丢账
-- （收件人总闸要数今天发过的**全部**码，包括已用掉的）；作废行只是不参与验码与冷却。
-- code_hash 存 sha256 十六进制：库里不落明文码。
--
-- uid = 发码时的账号归属：0 = 匿名发码（register/reset/login/login_2fa/delete，
-- /auth/send-code 无登录态）；非 0 = 登录态发码（change / email_change，见
-- internal/auth 的 SendChangeCode / SendChangeEmailCode）。两个用途：验码按
-- uid 做归属校验（防拿别的账号申请地址的码）、管理员换邮按 uid 烧该用户全部
-- 在途改邮码（防「管理员改完用户拿旧申请码改回去」的覆盖竞态）。
CREATE TABLE IF NOT EXISTS otp_codes (
    id           INT          NOT NULL AUTO_INCREMENT,
    email        VARCHAR(255) NOT NULL,
    purpose      VARCHAR(16)  NOT NULL,
    code_hash    CHAR(64)     NOT NULL,
    expires_at   BIGINT       NOT NULL,
    attempts     INT          NOT NULL DEFAULT 0,
    used         TINYINT      NOT NULL DEFAULT 0,
    created_at   BIGINT       NOT NULL,
    last_sent_at BIGINT       NOT NULL,
    uid          BIGINT       NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    KEY idx_otp_active (email, purpose, used, created_at),
    KEY idx_otp_day (email, created_at),
    KEY idx_otp_uid (uid, purpose)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;

-- 应用级配置：改库即热生效（读取带 10s 进程缓存，见 internal/config）。
-- P0 只用 mail_tenant_id / mail_client_id / mail_client_secret 三键，部署时人工灌，
-- 表结构为后续配置中心（P2.5）预留。
CREATE TABLE IF NOT EXISTS app_config (
    `key`  VARCHAR(64) NOT NULL,
    value  TEXT        NOT NULL,
    PRIMARY KEY (`key`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;

-- 登录会话：三条登录路（注册即登录 / 密码登录 / 验证码登录）与改密换发各建一行，
-- token 的 sid claim 指向它——「已登录设备」列表与踢人就作用在这张表上。
--
-- id 是雪花（s.ids 签发，不自增；与 users.id 的 7 位随机号段无关）；device 是**插入时** shortDevice(UA) 的
-- 展示快照（认不出即「未知设备」，仅供排障兜底）——展示一律读取时用 user_agent 现算（legacy 行存过
-- 库名 UA 原文），user_agent 才是设备名的唯一真相源，解析规则变好存量行自动受益。
-- revoked_at 非空 = 已登出/被踢：列表只回 IS NULL 的行；踢人不改 token_version，
-- 所以被踢设备的 token 靠 /internal/verify 的会话校验当场失效。
-- last_seen_at 由 verify 节流回写（旧于 60 秒才写），按它倒序排设备列表。
CREATE TABLE IF NOT EXISTS sessions (
    id           BIGINT       NOT NULL,
    user_id      BIGINT       NOT NULL,
    app          VARCHAR(32)  NOT NULL,
    device       VARCHAR(191) NOT NULL,
    ip           VARCHAR(45)  NOT NULL,
    user_agent   VARCHAR(512) NOT NULL,
    created_at   BIGINT       NOT NULL,
    last_seen_at BIGINT       NOT NULL,
    revoked_at   BIGINT       NULL,
    PRIMARY KEY (id),
    KEY idx_sessions_user (user_id, revoked_at)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;

-- 用户档案三件套（昵称 / 头像色 / 头像图）：OIDC UserInfo 同款思路——**档案归身份
-- 提供方**，两个日记 App 各自的 profiles 资料列已由一次性迁移并入这里
-- （迁移已完成，脚本已移除；映射表由主 agent 清库），
-- 之后经 GET/PUT /api/profile 读写（见 internal/auth/profile.go）。
--   nickname     空串 = 未设置（VARCHAR(64) 按字符计，与日记库同宽）
--   avatar_color 颜板索引，0 = 默认色
--   avatar_image **base64 原文**（无 data: 前缀、无换行——与日记库 profiles.avatar_image
--                同形态），NULL = 无头像；MEDIUMTEXT 与日记同款，装得下 700KB 解码上限
--                对应的 ~955,736 个 base64 字符
--   updated_at   毫秒；PUT 全量替换时由服务端置 now（日记侧的 LWW updated_at 口径）
CREATE TABLE IF NOT EXISTS user_profile (
    user_id      BIGINT       NOT NULL,
    nickname     VARCHAR(64)  NOT NULL DEFAULT '',
    avatar_color INT          NOT NULL DEFAULT 0,
    avatar_image MEDIUMTEXT   NULL,
    updated_at   BIGINT       NOT NULL,
    PRIMARY KEY (user_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;

-- app-admin 的按 app 授权（W2 分级授权）：role='admin' 且持有 ≥1 行才是有效
-- app-admin，只管本 app 范围内的会话/用量/审计；role='super'（平台管理员）绕过
-- 本表全量通行。一人可管多个项目 = 多行叠加；granted_by/granted_at 只为追溯
-- 「谁在什么时候授的」，判定不读它们。授予只能由 super 做（只能授予低于自己）。
CREATE TABLE IF NOT EXISTS admin_scopes (
    uid        BIGINT      NOT NULL,
    app        VARCHAR(32) NOT NULL,          -- calorie-diary / expense-diary（与 allowedApps 同源校验）
    granted_by BIGINT      NOT NULL,
    granted_at BIGINT      NOT NULL,
    PRIMARY KEY (uid, app)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;

-- 多处列变更（role / web_token_hash / web_csrf_hash / reauth_at）与两步登录中间态的
-- login_states.app、users 的 password_must_change / pending_delete_at / login_notify
-- 由 internal/db 的 ensureColumn 在启动时按 information_schema 探测后补：MySQL 的
-- ADD COLUMN 没有 IF NOT EXISTS，写进本文件会撞「重复列」错误让二跑的启动失败。

-- 用户封禁（W2）：app='*' 是全站封禁，具体项目 slug 是单项目封禁。
-- until_ms=0 永久，>0 为解除时刻毫秒——**判定时惰性判过期**（until_ms>0 且已过 = 已解封，
-- 读到过期行顺手删），不引入定时任务；banned_by/created_at 只为追溯。
-- 封禁在写入时立即吊销范围内会话，但**不 bump token_version**（避免误伤范围外项目）。
CREATE TABLE IF NOT EXISTS user_bans (
  uid BIGINT NOT NULL, app VARCHAR(64) NOT NULL DEFAULT '*',
  until_ms BIGINT NOT NULL DEFAULT 0, reason VARCHAR(255) NOT NULL DEFAULT '',
  banned_by BIGINT NOT NULL DEFAULT 0, created_at BIGINT NOT NULL,
  PRIMARY KEY (uid, app)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;

-- 项目登录白名单（W5，Entra「Assignment required」模式）：restricted=1 时该项目
-- 只放行 super / project_access 在册用户 / 该项目的 admin_scopes 管理员。
-- 直查本表判定（**不进 app_config 的 10s 缓存**——开关必须当场生效）。
CREATE TABLE IF NOT EXISTS project_policy (
  app VARCHAR(64) NOT NULL PRIMARY KEY, restricted TINYINT NOT NULL DEFAULT 0,
  updated_by BIGINT NOT NULL DEFAULT 0, updated_at BIGINT NOT NULL DEFAULT 0
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;

-- 项目的受邀用户名单（W5）：restricted=1 时的放行名单；移除成员即吊销其该 app 会话。
CREATE TABLE IF NOT EXISTS project_access (
  app VARCHAR(64) NOT NULL, uid BIGINT NOT NULL, granted_by BIGINT NOT NULL DEFAULT 0,
  created_at BIGINT NOT NULL DEFAULT 0, PRIMARY KEY (app, uid)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;

-- 审计日志（ASVS V16.2/V16.3）：认证成败、授权失败、配置改动都落这里。
-- 只增不改不删（应用层不可篡改；物理篡改风险见规格 D8）；保留 90 天，过期行在
-- 发码路径上顺手清（与 otp_codes 同款「挂高频路径」的清理模式）。
-- actor_email 存掩码、detail 只放非密钥结构化信息——这张表本身不能成为泄密面。
CREATE TABLE IF NOT EXISTS audit_logs (
    id          BIGINT       NOT NULL,
    ts          BIGINT       NOT NULL,
    actor_uid   BIGINT       NULL,
    actor_email VARCHAR(255) NOT NULL DEFAULT '',
    action      VARCHAR(64)  NOT NULL,
    result      VARCHAR(8)   NOT NULL,
    target_uid  BIGINT       NULL,
    ip          VARCHAR(45)  NOT NULL DEFAULT '',
    user_agent  VARCHAR(512) NOT NULL DEFAULT '',
    detail      TEXT         NULL,
    PRIMARY KEY (id),
    KEY idx_audit_actor (actor_uid, ts),
    KEY idx_audit_target (target_uid, ts),
    KEY idx_audit_action (action, ts)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;

-- passkey 凭证。rp_id 必须自己存列——库只按它校验仪式，不替你按 RP 分区凭证。
CREATE TABLE IF NOT EXISTS passkeys (
    id               BIGINT       NOT NULL,
    user_id          BIGINT       NOT NULL,
    name             VARCHAR(64)  NOT NULL,
    credential_id    VARCHAR(512) NOT NULL,
    rp_id            VARCHAR(64)  NOT NULL,
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
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;

-- TOTP 因子，一用户一条。enabled=0 是 pending（先验后启）：新 secret 落库后
-- 旧的 enabled 行保持原样，直到新码验过才整体替换。
CREATE TABLE IF NOT EXISTS totp_factors (
    user_id            BIGINT      NOT NULL,
    secret_cipher      VARBINARY(256) NOT NULL,
    enabled            TINYINT     NOT NULL DEFAULT 0,
    last_used_timestep BIGINT      NOT NULL DEFAULT 0,
    created_at         BIGINT      NOT NULL,
    confirmed_at       BIGINT      NULL,
    PRIMARY KEY (user_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;

-- 恢复码：存 HMAC-SHA256（不存明文），用一少一（used=1 不删行，删了就没法数「用过几个」），
-- 重生成时整组换新、旧组即废。
CREATE TABLE IF NOT EXISTS recovery_codes (
    id         INT          NOT NULL AUTO_INCREMENT,
    user_id    BIGINT       NOT NULL,
    code_hash  CHAR(64)     NOT NULL,
    used       TINYINT      NOT NULL DEFAULT 0,
    used_at    BIGINT       NULL,
    created_at BIGINT       NOT NULL,
    PRIMARY KEY (id),
    KEY idx_recovery_user (user_id, used)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;

-- WebAuthn 仪式中间态：SessionData 整体 JSON 落库（库规定唯一持久化形态），
-- 5 分钟过期、用后即焚——内存 map 撑不过重启，正是本仓把验证码迁库的同款理由。
CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id           BIGINT      NOT NULL,
    kind         VARCHAR(16) NOT NULL,
    user_id      BIGINT      NULL,
    session_data TEXT        NOT NULL,
    expires_at   BIGINT      NOT NULL,
    created_at   BIGINT      NOT NULL,
    PRIMARY KEY (id),
    KEY idx_chal_exp (expires_at)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;

-- 两步登录中间态：密码已验、TOTP 未验的 5 分钟窗口。token 只存 sha256，
-- 错 5 次整条烧毁（与邮箱验证码同口径）。
CREATE TABLE IF NOT EXISTS login_states (
    token_hash CHAR(64)    NOT NULL,
    user_id    BIGINT      NOT NULL,
    method     VARCHAR(16) NOT NULL,
    attempts   INT         NOT NULL DEFAULT 0,
    expires_at BIGINT      NOT NULL,
    created_at BIGINT      NOT NULL,
    PRIMARY KEY (token_hash),
    KEY idx_ls_user (user_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;

-- AI 用量计数（管理台看板读，限额键仍在 app_config）。先建空表：迁入逻辑
-- 由后续批次接，这里只保证看板有表可查。
CREATE TABLE IF NOT EXISTS ai_usage (
    scope   VARCHAR(8)  NOT NULL,
    subject VARCHAR(32) NOT NULL,
    day     VARCHAR(10) NOT NULL,
    count   INT         NOT NULL,
    PRIMARY KEY (scope, subject, day)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;

-- 管理端邀请建号（B9）：管理员发一封带链接的邀请信，收件人点开设置密码即建号
--（邮箱视为已验证，见 internal/auth 的 invite.go）。token 只存 sha256（明文只在
-- 创建/重发那一刻进邮件），24 小时过期。
-- 状态**不存列**，由三个时间戳派生：accepted_at>0=已接受、revoked_at>0=已撤销、
-- now>expires_at=已过期，否则待接受（四态，见 inviteState）。接受是单次语义：
-- 消费走 `accepted_at=0` 的条件 UPDATE，防并发双开。
-- id 走既有雪花（s.ids 签发，与 users.id 的 7 位随机号段无关）；invited_by 记
-- 发起人 uid（0 = 历史/未知）；app='' 是账号级邀请（不限项目），非空时**接受即
-- 自动加入该项目的 project_access**（项目受限时正是放行名单要的行）。
CREATE TABLE IF NOT EXISTS user_invites (
  id BIGINT PRIMARY KEY,
  email VARCHAR(255) NOT NULL,
  app VARCHAR(64) NOT NULL DEFAULT '',
  invited_by BIGINT NOT NULL DEFAULT 0,
  token_hash VARCHAR(64) NOT NULL,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  accepted_at BIGINT NOT NULL DEFAULT 0,
  revoked_at BIGINT NOT NULL DEFAULT 0,
  KEY idx_invites_email (email, accepted_at, revoked_at, expires_at)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;

-- OAuth 跳转授权的客户端登记（每项目一行，主键 app）：client_id 随机 16 位、
-- secret 随机 32 位且**只存 sha256**（明文仅在创建/重置那一刻回执一次）；
-- redirect_uris 存 JSON 数组，授权时**精确串匹配**（RFC 9700，不做前缀/通配）。
-- secret_hash 允许空串 = 已登记 client_id 但还没签发过 secret。
CREATE TABLE IF NOT EXISTS oauth_clients (
  app VARCHAR(64) NOT NULL PRIMARY KEY,
  client_id VARCHAR(64) NOT NULL UNIQUE,
  secret_hash VARCHAR(128) NOT NULL DEFAULT '',
  redirect_uris TEXT NOT NULL,
  created_by BIGINT NOT NULL DEFAULT 0,
  created_at BIGINT NOT NULL DEFAULT 0
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;
