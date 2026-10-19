-- 统一账号服务表结构。
--
-- 全新库，仍只用 CREATE TABLE IF NOT EXISTS：幂等对重复启动与并发启动都安全，
-- 本文件不出现任何 DROP/ALTER。
-- 时间戳列一律 BIGINT 毫秒（与两个日记服务同口径），不用 DATETIME，
-- DSN 里的 parseTime 因此无关紧要。

-- 账号表。id 是雪花 63 位整数（注册时由服务生成，**不自增**）——
-- 统一账号要被多个下游服务引用，自增 id 会暴露注册顺序、也不便跨服务规划号段。
-- password_hash 允许 NULL：预留给纯验证码登录的账号形态（P0 的注册路径恒写入）。
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
    PRIMARY KEY (id),
    KEY idx_otp_active (email, purpose, used, created_at),
    KEY idx_otp_day (email, created_at)
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
-- id 是雪花（与 users.id 同一个 s.ids，不自增）；device 是从 UA 尽力解析出的短标签
--（解析不出存 UA 原文截断），user_agent 留原文以便下次解析规则变好后回填口径。
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

-- Web 管理台的三张列变更（role / web_token_hash / web_csrf_hash / reauth_at）由
-- internal/db 的 ensureColumn 在启动时按 information_schema 探测后补：MySQL 的
-- ADD COLUMN 没有 IF NOT EXISTS，写进本文件会撞「重复列」错误让二跑的启动失败。

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
