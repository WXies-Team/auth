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
