package auth

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// B9 批量操作的纯单测：汇总/去重/批次号/错误文案四个纯函数 + 入参闸的无 DB 路径
//（真库端到端在 cmd/server 的路由用例与 adminctl 的单发用例里合起来覆盖）。

// 汇总：计数、透传 kind/batchId、逐项原样带回（面板按 items 逐行渲染）。
func TestSummarizeBulk(t *testing.T) {
	items := []BulkItem{
		{UID: 1, OK: true},
		{UID: 2, OK: false, Message: "没有该项目的管理权限"},
		{UID: 3, OK: true},
	}
	got := summarizeBulk(bulkKindBan, "batch-9", items)
	if got.Total != 3 || got.Succeeded != 2 || got.Failed != 1 {
		t.Errorf("汇总计数不对: %+v", got)
	}
	if got.Kind != bulkKindBan || got.BatchID != "batch-9" {
		t.Errorf("kind/batchId 应原样带出: %+v", got)
	}
	if len(got.Items) != 3 || got.Items[1].Message != "没有该项目的管理权限" {
		t.Errorf("逐项结果应原样透传: %+v", got.Items)
	}
	// 空批次（不可能经 AdminBulk 到达，但纯函数要稳）
	empty := summarizeBulk(bulkKindPasswordReset, "b", nil)
	if empty.Total != 0 || empty.Succeeded != 0 || empty.Failed != 0 || len(empty.Items) != 0 {
		t.Errorf("空批次应全零: %+v", empty)
	}
	// 全失败
	allBad := summarizeBulk(bulkKindUnban, "b", []BulkItem{{UID: 7}})
	if allBad.Succeeded != 0 || allBad.Failed != 1 {
		t.Errorf("全失败计数不对: %+v", allBad)
	}
}

// 去重保序 + 滤非正数：同一 uid 只动一次、顺序不乱、0/负数直接出局。
func TestDedupeUIDs(t *testing.T) {
	got := dedupeUIDs([]int64{5, 0, 3, 5, -1, 3, 9, 9, 1})
	want := []int64{5, 3, 9, 1}
	if len(got) != len(want) {
		t.Fatalf("去重结果应为 %v，得到 %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("去重应保序，得到 %v，应为 %v", got, want)
		}
	}
	if out := dedupeUIDs(nil); len(out) != 0 {
		t.Errorf("空输入应回空，得到 %v", out)
	}
}

// 批次号：单发（空串）不落空键，批量补 batch_id —— 审计页靠它把「哪一批」还原出来。
func TestWithBatchID(t *testing.T) {
	d := map[string]string{"app": "calorie-diary"}
	if got := withBatchID(d, ""); got["app"] != "calorie-diary" {
		t.Errorf("原 detail 应保留: %v", got)
	}
	if _, leaked := d["batch_id"]; leaked {
		t.Error("单发（batchID 空）不该落 batch_id 空键")
	}
	d2 := map[string]string{"app": "*"}
	withBatchID(d2, "1234567890")
	if d2["batch_id"] != "1234567890" {
		t.Errorf("批量应补 batch_id，得到 %v", d2)
	}
	// 就地补键：调用方直接把同一个 map 交给审计（返回值与入参同一张表）
	d3 := map[string]string{"k": "v"}
	withBatchID(d3, "b1")
	if d3["batch_id"] != "b1" || d3["k"] != "v" {
		t.Errorf("withBatchID 应就地改写入参 map，得到 %v", d3)
	}
}

// 逐项错误的面板文案：HTTPError 取自带中文（越权/参数错要能直接读），
// 其余一律中性白话（根因进日志，不把内部串甩到管理台）。
func TestBulkErrText(t *testing.T) {
	httpErr := &HTTPError{403, "没有该项目的管理权限，请联系平台管理员开通"}
	if got := bulkErrText(httpErr); got != "没有该项目的管理权限，请联系平台管理员开通" {
		t.Errorf("HTTPError 应取自带文案，得到 %q", got)
	}
	// 包一层 %w 的 HTTPError 也要解得出来（errors.As 语义）
	wrapped := fmt.Errorf("逐项执行: %w", httpErr)
	if got := bulkErrText(wrapped); got != "没有该项目的管理权限，请联系平台管理员开通" {
		t.Errorf("包装后的 HTTPError 应解出自带文案，得到 %q", got)
	}
	if got := bulkErrText(errors.New("sql: connection refused")); got != "操作失败，请稍后重试" {
		t.Errorf("非 HTTPError 应回中性白话，得到 %q", got)
	}
	if got := bulkErrText(nil); got != "操作失败，请稍后重试" {
		t.Errorf("nil 应回落中性白话，得到 %q", got)
	}
}

// 入参闸的无 DB 路径：非法 kind / 空选择 / 超单批上限都在碰库（含批次号签发、
// 审计）之前 400——零值 Service 直接打即可证明没有隐藏的 DB 依赖。
func TestAdminBulkRejectsBadInputWithoutDB(t *testing.T) {
	var s Service
	actor := Caller{UID: 1, Email: "a@example.com"}
	scope := AdminScope{Super: true}

	_, err := s.AdminBulk(actor, scope, "delete_users", []int64{1}, AdminBanInput{})
	if code, msg := httpMsg(err); code != 400 || !strings.Contains(msg, "kind") {
		t.Errorf("非法 kind 应 400 且点名值域，得到 code=%d msg=%q", code, msg)
	}
	_, err = s.AdminBulk(actor, scope, bulkKindBan, nil, AdminBanInput{})
	if code, msg := httpMsg(err); code != 400 || !strings.Contains(msg, "请先选择") {
		t.Errorf("空选择应 400「请先选择」，得到 code=%d msg=%q", code, msg)
	}
	over := make([]int64, 0, maxBulkUsers+1)
	for i := 1; i <= maxBulkUsers+1; i++ { // 去重后仍超上限（101 个真 uid）才提示分批
		over = append(over, int64(i))
	}
	_, err = s.AdminBulk(actor, scope, bulkKindPasswordReset, over, AdminBanInput{})
	if code, msg := httpMsg(err); code != 400 || !strings.Contains(msg, "分批") {
		t.Errorf("超上限应 400 且提示分批，得到 code=%d msg=%q", code, msg)
	}
}

// 入参闸：**先去重再判上限**（prepareBulkUIDs）——含重复的 150 条按去重后的真数判，
// 不整批打回；去重后 101 个才提示分批；全 0/负数经去重出局后回「请先选择」
//（老实现先 len 后去重，200 个全 0 会误报「分批」）。
func TestPrepareBulkUIDs(t *testing.T) {
	// total 条输入平铺成 distinct 个真 uid（其余重复）
	batch := func(distinct, total int) []int64 {
		out := make([]int64, 0, total)
		for i := 0; i < total; i++ {
			out = append(out, int64(i%distinct+1))
		}
		return out
	}
	// 期望 400 且文案含 substr（httpMsg 对非 HTTPError 回 0 空串，一并兜住「没报错」）
	wantReject := func(what string, uids []int64, substr string) {
		t.Helper()
		_, err := prepareBulkUIDs(uids)
		if code, msg := httpMsg(err); code != 400 || !strings.Contains(msg, substr) {
			t.Errorf("%s 应 400 且含 %q，得到 code=%d msg=%q（err=%v）", what, substr, code, msg, err)
		}
	}

	got, err := prepareBulkUIDs(batch(80, 150))
	if err != nil || len(got) != 80 {
		t.Errorf("150 条（80 个真 uid）应去重后放行，得到 len=%d err=%v", len(got), err)
	}
	wantReject("去重后 101 个超上限", batch(101, 150), "分批")
	if _, err := prepareBulkUIDs(batch(100, 100)); err != nil {
		t.Errorf("去重后正好 %d 个应放行，得到 %v", maxBulkUsers, err)
	}
	wantReject("空选择", nil, "请先选择")
	wantReject("200 个全 0 输入（去重后出局）", make([]int64, 200), "请先选择")
}

// ---- 真库端到端（无 TEST_MYSQL_DSN 跳过）----

// 三个 kind 全跑一遍 + 权限矩阵：批量层只负责逐项执行与汇总，单发的语义
//（强制改密/吊销会话/写封禁行）与权限（越权项落成单条失败，不整批 403）都得在。
func TestAdminBulkEndToEnd(t *testing.T) {
	svc, mailer := newTestService(t)
	super := seedAdminUser(t, svc, mailer, "bulk-super@example.com", adminRoleSuper)
	scope := AdminScope{Super: true}
	v1 := newPasskeyUser(t, svc, mailer, "bulk-v1@example.com")
	v2 := newPasskeyUser(t, svc, mailer, "bulk-v2@example.com")
	uids := []int64{v1.UID, v2.UID}

	// ---- ① password_reset：逐项成功 + 强制改密 + 旧密码失效 + 每人一封通知信 ----
	beforeMail := len(mailer.sent)
	res, err := svc.AdminBulk(super, scope, bulkKindPasswordReset, uids, AdminBanInput{})
	if err != nil {
		t.Fatalf("批量重置: %v", err)
	}
	if res.Total != 2 || res.Succeeded != 2 || res.Failed != 0 || res.Kind != bulkKindPasswordReset {
		t.Fatalf("应 2/2 成功且 kind 回执，得到 %+v", res)
	}
	if res.BatchID == "" {
		t.Error("回执应带批次号")
	}
	for _, it := range res.Items {
		if it.OK && it.Message != "" {
			t.Errorf("成功项不该带失败文案: %+v", it)
		}
	}
	if got := len(mailer.sent) - beforeMail; got != 2 {
		t.Errorf("notify=true 应每人一封通知信，得到 %d", got)
	}
	var must int
	if err := svc.pool.QueryRow("SELECT password_must_change FROM users WHERE id = ?", v1.UID).Scan(&must); err != nil || must != 1 {
		t.Errorf("批量重置应强制下次登录改密（must_change=1），得到 %d（%v）", must, err)
	}
	if _, err := svc.Login("bulk-v1@example.com", "secret123", "calorie-diary", testMeta); err == nil {
		t.Error("重置后旧密码应失效")
	}
	// 双层审计：批次总账一条 + 逐用户 password.reset 带同一 batch_id
	var ledger int
	if err := svc.pool.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE action = ?", AuditAdminBulk).Scan(&ledger); err != nil || ledger != 1 {
		t.Errorf("应有 1 条批次总账，得到 %d（%v）", ledger, err)
	}
	var shared int
	if err := svc.pool.QueryRow(
		"SELECT COUNT(*) FROM audit_logs WHERE action = ? AND detail LIKE ?",
		AuditPasswordReset, "%"+res.BatchID+"%").Scan(&shared); err != nil || shared != 2 {
		t.Errorf("逐用户重置审计应 2 条且带同一 batch_id，得到 %d（%v）", shared, err)
	}

	// ---- ② ban：封禁行落库（范围 + 原因） ----
	if _, err := svc.AdminBulk(super, scope, bulkKindBan, uids, AdminBanInput{
		App: "calorie-diary", Reason: "批量测试"}); err != nil {
		t.Fatalf("批量封禁: %v", err)
	}
	var bans int
	if err := svc.pool.QueryRow("SELECT COUNT(*) FROM user_bans WHERE app = 'calorie-diary'").Scan(&bans); err != nil || bans != 2 {
		t.Errorf("应落 2 条封禁行，得到 %d（%v）", bans, err)
	}
	var reason string
	_ = svc.pool.QueryRow("SELECT reason FROM user_bans WHERE uid = ?", v1.UID).Scan(&reason)
	if reason != "批量测试" {
		t.Errorf("封禁原因应套用到每个所选用户，得到 %q", reason)
	}

	// ---- ③ unban + 去重：输入 3 个 uid（v1 重复）→ 只执行 2 项 ----
	un, err := svc.AdminBulk(super, scope, bulkKindUnban, []int64{v1.UID, v1.UID, v2.UID},
		AdminBanInput{App: "calorie-diary"})
	if err != nil {
		t.Fatalf("批量解封: %v", err)
	}
	if un.Total != 2 {
		t.Errorf("重复 uid 应在入口折掉，得到 Total=%d（输入 3 个）", un.Total)
	}
	if err := svc.pool.QueryRow("SELECT COUNT(*) FROM user_bans WHERE app = 'calorie-diary'").Scan(&bans); err != nil || bans != 0 {
		t.Errorf("解封后应无封禁行，得到 %d（%v）", bans, err)
	}
	// 总账条数：三次批次 = 3 条
	var ledgers int
	_ = svc.pool.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE action = ?", AuditAdminBulk).Scan(&ledgers)
	if ledgers != 3 {
		t.Errorf("每个批次一条总账，应 3 条，得到 %d", ledgers)
	}

	// ---- ④ 权限矩阵：app-admin 的越权项落成单条失败，err 本身不回 403 ----
	appAdmin := seedAdminUser(t, svc, mailer, "bulk-one@example.com", adminRoleAdmin)
	if err := svc.AdminSetScope(super, appAdmin.UID, "calorie-diary", true); err != nil {
		t.Fatalf("授 scope: %v", err)
	}
	appScope := AdminScope{Apps: []string{"calorie-diary"}}

	// 越权项目：逐项失败、消息可读、整批不报错（选 10 个人有 2 个不归你管 → 动另外 8 个）
	out, err := svc.AdminBulk(appAdmin, appScope, bulkKindBan, uids, AdminBanInput{App: "expense-diary"})
	if err != nil {
		t.Fatalf("越权批量应逐项失败而非整批报错: %v", err)
	}
	if out.Succeeded != 0 || out.Failed != 2 {
		t.Errorf("越权项应全失败，得到 %+v", out)
	}
	for _, it := range out.Items {
		if !it.OK && !strings.Contains(it.Message, "管理权限") {
			t.Errorf("失败文案应可读，得到 %q", it.Message)
		}
	}
	// '*' 只属 super：每项 400
	star, err := svc.AdminBulk(appAdmin, appScope, bulkKindBan, []int64{v1.UID}, AdminBanInput{App: "*"})
	if err != nil || star.Failed != 1 || !strings.Contains(star.Items[0].Message, "平台管理员") {
		t.Errorf("app-admin 批量全局封禁应逐项 400，得到 %+v（%v）", star, err)
	}
	// 目标在授权项目下无活跃会话：app-admin 的批量重置逐项 403
	//（v2 的会话已随 ① 的重置全部吊销，正是这个形态）
	noSess, err := svc.AdminBulk(appAdmin, appScope, bulkKindPasswordReset, []int64{v2.UID}, AdminBanInput{})
	if err != nil || noSess.Failed != 1 || !strings.Contains(noSess.Items[0].Message, "管理权限") {
		t.Errorf("无授权项目会话应逐项 403，得到 %+v（%v）", noSess, err)
	}
	// 授权范围内照常成功
	okRes, err := svc.AdminBulk(appAdmin, appScope, bulkKindBan, []int64{v1.UID}, AdminBanInput{App: "calorie-diary"})
	if err != nil || okRes.Succeeded != 1 {
		t.Errorf("授权项目内应成功，得到 %+v（%v）", okRes, err)
	}
}
