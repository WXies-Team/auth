package db

import (
	"strings"
	"testing"
)

// FromEnv 只认 MYSQL_DSN：缺了要在启动时立刻炸，而不是带着空串去连库。
func TestFromEnvRequiresDSN(t *testing.T) {
	t.Setenv("MYSQL_DSN", "")
	if _, err := FromEnv(); err == nil {
		t.Error("缺 MYSQL_DSN 应报错")
	}
	t.Setenv("MYSQL_DSN", "  ")
	if _, err := FromEnv(); err == nil {
		t.Error("全空白应视为缺失")
	}
	t.Setenv("MYSQL_DSN", "user:pass@tcp(127.0.0.1:3306)/auth")
	got, err := FromEnv()
	if err != nil {
		t.Fatalf("正常 DSN 不该报错: %v", err)
	}
	if strings.TrimSpace(got) != "user:pass@tcp(127.0.0.1:3306)/auth" {
		t.Errorf("DSN 被改动了: %q", got)
	}
}

// EnsureSchema 的语句切分不依赖数据库本身，可以拿一个未连通的池验「整份文件能被拆成
// 合法语句」——但拆分逻辑要 Exec 才走得到，所以这里只测内嵌文件存在且非空。
func TestSchemaFileEmbedded(t *testing.T) {
	raw, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		t.Fatalf("schema.sql 未内嵌: %v", err)
	}
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS users",
		"CREATE TABLE IF NOT EXISTS otp_codes",
		"CREATE TABLE IF NOT EXISTS app_config",
		"CREATE TABLE IF NOT EXISTS sessions",
		"CREATE TABLE IF NOT EXISTS passkeys",
		"CREATE TABLE IF NOT EXISTS totp_factors",
		"CREATE TABLE IF NOT EXISTS recovery_codes",
		"CREATE TABLE IF NOT EXISTS webauthn_challenges",
		"CREATE TABLE IF NOT EXISTS login_states",
		"CREATE TABLE IF NOT EXISTS ai_usage",
		"CREATE TABLE IF NOT EXISTS audit_logs",
		"CREATE TABLE IF NOT EXISTS user_profile",
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("schema.sql 缺少 %q", want)
		}
	}
	if strings.Contains(string(raw), "DROP TABLE") || strings.Contains(string(raw), "ALTER TABLE") {
		t.Error("schema.sql 只许 CREATE TABLE IF NOT EXISTS，不应含 DROP/ALTER")
	}
}
