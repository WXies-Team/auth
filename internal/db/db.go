// Package db 负责连接池与建表。
package db

import (
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

//go:embed schema.sql
var schemaFS embed.FS

// Open 建连接池并 ping 通。
//
// DSN 形如 `auth:<pass>@tcp(127.0.0.1:3306)/auth?charset=utf8mb4&parseTime=true&loc=Local`，
// 用户名与密码内嵌其中。时间戳列都是 BIGINT，parseTime/loc 只影响 DATETIME 类型的列
// （本库没有），保留是为了 DSN 示例与常见模板一致。
func Open(dsn string) (*sql.DB, error) {
	return openDSN(dsn)
}

// OpenWithRetry 在给定时长内反复尝试连接，**覆盖 MySQL 冷启动**。
//
// 起因（热量日记服务实踩的生产事故）：MySQL 重启花了约 9 秒，而 Go 启动时
// Ping 失败就退出——只试几次 supervisor 的 startretries 就耗尽、状态变 FATAL；
// 更糟的是 MySQL 恢复后进程已不在、**不会自己回来**，只能人工 start。
// 所以这里不立刻退出而是等到 deadline：进程一直存活，supervisor 判定启动成功，
// MySQL 一就绪就自动对外服务。
func OpenWithRetry(dsn string, wait time.Duration) (*sql.DB, error) {
	deadline := time.Now().Add(wait)
	var lastErr error
	for attempt := 1; ; attempt++ {
		pool, err := openDSN(dsn)
		if err == nil {
			if attempt > 1 {
				slog.Info("数据库已就绪", "attempts", attempt)
			}
			return pool, nil
		}
		lastErr = err
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, fmt.Errorf("等待 %s 后仍连不上数据库: %w", wait, lastErr)
		}
		// 2 秒一次：覆盖 MySQL 冷启（实测约 9 秒），也不会太密刷日志
		sleep := 2 * time.Second
		if sleep > remaining {
			sleep = remaining
		}
		slog.Warn("数据库未就绪，重试中", "attempt", attempt, "还有", remaining.Round(time.Second).String())
		time.Sleep(sleep)
	}
}

// FromEnv 从环境变量读连接串，**只认 MYSQL_DSN**。
// 缺失即报错退出：supervisord 拉不起来 → /health 失败，能立刻看出配置没跟上。
func FromEnv() (string, error) {
	dsn := strings.TrimSpace(os.Getenv("MYSQL_DSN"))
	if dsn == "" {
		return "", fmt.Errorf("缺少 MYSQL_DSN（环境变量），检查 supervisord 的 environment")
	}
	slog.Info("数据库连接串", "source", "MYSQL_DSN")
	return dsn, nil
}

func openDSN(dsn string) (*sql.DB, error) {
	pool, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("打开连接池: %w", err)
	}
	// 账号服务的流量远小于日记同步：8 条连接足够（验证码与登录都是短查询），
	// 空闲 60s 回收防长连堆积。
	pool.SetMaxOpenConns(8)
	pool.SetMaxIdleConns(8)
	pool.SetConnMaxLifetime(time.Hour)
	pool.SetConnMaxIdleTime(60 * time.Second)

	if err := pool.Ping(); err != nil {
		_ = pool.Close()
		return nil, fmt.Errorf("连接数据库: %w", err)
	}
	return pool, nil
}

// EnsureSchema 逐条执行 schema.sql（**只用 CREATE TABLE IF NOT EXISTS**，对已存在的表是 no-op）。
//
// 必须**逐条执行**：MySQL 驱动默认 multiStatements=false，整份文件丢给一次 Exec 会语法错。
// 也**不能**简单按 `;` 拆——将来若默认值里出现分号就会拆错，所以逐行拼到行尾分号为止，
// 并跳过 `--` 注释行。
func EnsureSchema(pool *sql.DB) error {
	raw, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		return fmt.Errorf("读 schema.sql: %w", err)
	}

	var stmts []string
	var cur []string
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if len(cur) == 0 && (trimmed == "" || strings.HasPrefix(trimmed, "--")) {
			continue
		}
		cur = append(cur, line)
		if strings.HasSuffix(trimmed, ";") {
			stmts = append(stmts, strings.Join(cur, "\n"))
			cur = nil
		}
	}
	if rest := strings.Join(cur, "\n"); strings.TrimSpace(strings.TrimPrefix(rest, "--")) != "" {
		stmts = append(stmts, rest) // 末尾没写分号的兜底
	}

	for i, stmt := range stmts {
		if _, err := pool.Exec(stmt); err != nil {
			return fmt.Errorf("执行第 %d 条建表语句失败: %w\n语句: %s", i+1, err, truncate(stmt, 160))
		}
	}
	// 列变更单独走探测式补列：MySQL 的 ADD COLUMN 没有 IF NOT EXISTS，直接写进
	// schema.sql 会让第二次启动撞 Duplicate column 而拒启。探测用 information_schema
	//（读元数据，不加表锁），列已存在即整条 no-op。
	for _, c := range extraColumns {
		if err := ensureColumn(pool, c.table, c.column, c.ddl); err != nil {
			return err
		}
	}
	slog.Info("schema ensured", "statements", len(stmts), "columns", len(extraColumns))
	return nil
}

// columnDef 是一条「老库补列」的 DDL。table/column 只为探测与报错定位，ddl 才是执行体。
type columnDef struct {
	table, column, ddl string
}

// extraColumns 是 schema.sql 之外的列变更（同一批新增，一次补齐）。
var extraColumns = []columnDef{
	{"users", "role",
		"ALTER TABLE users ADD COLUMN role VARCHAR(16) NOT NULL DEFAULT 'user'"},
	// UNIQUE 建在列上：web cookie 的 sha256 命中查询按唯一键走，且 DB 层兜住
	//「同一 token 落两行」的实现错误（生成端再随机也挡不住）。
	{"sessions", "web_token_hash",
		"ALTER TABLE sessions ADD COLUMN web_token_hash CHAR(64) NULL, ADD UNIQUE KEY uq_sessions_web_token (web_token_hash)"},
	{"sessions", "web_csrf_hash",
		"ALTER TABLE sessions ADD COLUMN web_csrf_hash CHAR(64) NULL"},
	{"sessions", "reauth_at",
		"ALTER TABLE sessions ADD COLUMN reauth_at BIGINT NULL"},
	// 两步登录中间态要记住第一步声明的目标应用（C 批）：第二步 /web/login/totp 读它
	// 决定发 web 会话还是业务 JWT。DEFAULT 'web' 让存量行与 web 流程共用一个取值。
	{"login_states", "app",
		"ALTER TABLE login_states ADD COLUMN app VARCHAR(32) NOT NULL DEFAULT 'web'"},
}

// ensureColumn 幂等地补一列：先查 information_schema，没有才执行 DDL。
func ensureColumn(pool *sql.DB, table, column, ddl string) error {
	var found int
	err := pool.QueryRow(
		"SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?",
		table, column).Scan(&found)
	if err != nil {
		return fmt.Errorf("探测 %s.%s 列: %w", table, column, err)
	}
	if found > 0 {
		return nil
	}
	if _, err := pool.Exec(ddl); err != nil {
		return fmt.Errorf("补 %s.%s 列: %w", table, column, err)
	}
	slog.Info("补列完成", "table", table, "column", column)
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
