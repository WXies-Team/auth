package auth

import (
	"errors"
	"fmt"
	"strconv"
)

// B9 批量操作（量级适配 = 同步逐个执行）：批量重置密码 / 批量封禁 / 批量解除封禁。
// **不做**批量改角色 / 改邮 / 重置资料——风险收益不划算（误操作不可逆面大、
// 单发路径已覆盖真实频次），范围收缩是定案而非遗漏。
//
// 口径（调研定案）：
//   - 逐用户**与单发同语义**——复用 AdminResetPassword / AdminBan / AdminUnban，
//     权限矩阵、参数闸、逐用户审计一条不放松；批量层只负责「逐项执行 + 汇总 +
//     双层审计」；
//   - 单批 ≤ maxBulkUsers（**先去重再判**，见 prepareBulkUIDs），执行同步（管理台一次
//     选中的量级不到 100，逐项点查 + bcrypt 在秒级内回——引入任务队列只是给同一张
//     管理台多一个转圈页）；
//   - 批量重置的临时密码**只进逐用户的通知邮件**（回执里的 tmp 当场丢弃）：结果
//     面板与日志只见成功/失败（凭证卫生，坑#6）；
//   - 双层审计：批次总账 admin.bulk_action（kind/batch_id/count/succeeded/failed）
//     + 每用户一条既有事件（password.reset / user.ban / user.unban，detail 带同一
//     batch_id）——审计页按 batch_id 关联还原「这是哪一次操作」。

const (
	// maxBulkUsers 是单批用户数上限：与 EnsureUsers 的单批同量级——一次误操作的
	// 爆炸半径有界，善后（重发/解封）也有可预期的规模。
	maxBulkUsers = 100

	// 批量动作三值：与请求体 kind、BulkResult.Kind 同一值域。
	bulkKindPasswordReset = "password_reset"
	bulkKindBan           = "ban"
	bulkKindUnban         = "unban"
)

// BulkItem 是结果面板的一行：逐项成功/失败 + 失败原因。**没有密码位**——凭证只进
// 逐用户的邮件，不进回执（见文件头注释）。
type BulkItem struct {
	UID     int64  `json:"uid"`
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

// BulkResult 是批量端点的回执：批次号 + 汇总 + 逐项结果（失败项可勾选重试，
// 前端只重跑失败子集）。
type BulkResult struct {
	BatchID   string     `json:"batchId"`
	Kind      string     `json:"kind"`
	Total     int        `json:"total"`
	Succeeded int        `json:"succeeded"`
	Failed    int        `json:"failed"`
	Items     []BulkItem `json:"items"`
}

// summarizeBulk 汇总逐项结果（纯函数：单测直接打，不碰库）。
func summarizeBulk(kind, batchID string, items []BulkItem) BulkResult {
	out := BulkResult{BatchID: batchID, Kind: kind, Total: len(items), Items: items}
	for _, it := range items {
		if it.OK {
			out.Succeeded++
		} else {
			out.Failed++
		}
	}
	return out
}

// dedupeUIDs 去重保序：同一 uid 在选择集里出现两次等于把同一个用户重置/封禁两遍
//（第二次多烧一次 bcrypt、多吊一次会话，审计也多一条）——入口折掉，纯函数可单测。
// 非正数一并滤掉（它们只会变成一排 404 噪声）。
func dedupeUIDs(uids []int64) []int64 {
	seen := make(map[int64]bool, len(uids))
	out := make([]int64, 0, len(uids))
	for _, uid := range uids {
		if uid <= 0 || seen[uid] {
			continue
		}
		seen[uid] = true
		out = append(out, uid)
	}
	return out
}

// prepareBulkUIDs 是 AdminBulk 的入参闸（纯函数，碰库前收口）：**先去重再判上限**——
// 含重复的 150 条按去重后的真数判（去重后 ≤ maxBulkUsers 照跑，而不是整批打回）；
// 去重后为空 = 「请先选择」，去重后仍超上限才提示分批。非正数与重复都在
// dedupeUIDs 出局（口径见其注释）。
func prepareBulkUIDs(uids []int64) ([]int64, error) {
	uids = dedupeUIDs(uids)
	if len(uids) == 0 {
		return nil, badRequest("请先选择要操作的用户")
	}
	if len(uids) > maxBulkUsers {
		return nil, badRequest(fmt.Sprintf("单批最多 %d 个用户，请分批操作", maxBulkUsers))
	}
	return uids, nil
}

// withBatchID 给审计 detail 补 batch_id（单发不带批次号时原样返回，不落空键）。
func withBatchID(detail map[string]string, batchID string) map[string]string {
	if batchID != "" {
		detail["batch_id"] = batchID
	}
	return detail
}

// bulkErrText 把逐项错误翻成结果面板的一句话：HTTPError 取自带文案，其余一律
// 中性白话（根因进服务端日志）——与路由层 errText 同一口径。
func bulkErrText(err error) string {
	var he *HTTPError
	if errors.As(err, &he) {
		return he.Message
	}
	return "操作失败，请稍后重试"
}

// AdminBulk 批量执行（kind ∈ password_reset | ban | unban），同步逐个调用对应
// 单发方法；任一用户失败不打断其余（失败项进结果面板，可勾选重试只重跑子集）。
//
// 权限不在这里整体判：每个单发方法各自跑同一套矩阵（su / 根收口 / app-admin 需
// 目标在授权项目下有活跃会话），越权项落成单条失败而不是整批 403——「选了 10 个人、
// 其中 2 个不归你管」的正确答案是动那 8 个、把 2 个报出来。
func (s *Service) AdminBulk(actor Caller, scope AdminScope, kind string, uids []int64, in AdminBanInput) (*BulkResult, error) {
	switch kind {
	case bulkKindPasswordReset, bulkKindBan, bulkKindUnban:
	default:
		return nil, badRequest("kind 只能是 password_reset、ban 或 unban，请重新选择后重试")
	}
	uids, err := prepareBulkUIDs(uids)
	if err != nil {
		return nil, err
	}
	batchID := strconv.FormatInt(s.ids.Generate().Int64(), 10)
	items := make([]BulkItem, 0, len(uids))
	for _, uid := range uids {
		switch kind {
		case bulkKindPasswordReset:
			// 逐用户与单发同语义：16 位强随机 + 默认强制改密 + 通知邮件。
			// tmp 回执当场丢弃——批量的凭证只进各自的邮件，不进面板、不进日志。
			_, err = s.AdminResetPassword(actor, scope, uid, AdminPasswordReset{
				Mode: "generate", ForceChange: true, Notify: true, BatchID: batchID,
			})
		case bulkKindBan:
			in.BatchID = batchID
			err = s.AdminBan(actor, scope, uid, in)
		case bulkKindUnban:
			err = s.AdminUnban(actor, scope, uid, in.App, batchID)
		}
		item := BulkItem{UID: uid, OK: err == nil}
		if err != nil {
			item.Message = bulkErrText(err)
		}
		items = append(items, item)
	}
	result := summarizeBulk(kind, batchID, items)
	s.Audit(AuditEvent{
		Action: AuditAdminBulk, OK: result.Failed == 0, ActorUID: uidPtr(actor.UID),
		ActorEmail: maskEmail(actor.Email), Meta: actor.Meta,
		Detail: map[string]string{
			"kind": kind, "batch_id": batchID,
			"count":     strconv.Itoa(result.Total),
			"succeeded": strconv.Itoa(result.Succeeded),
			"failed":    strconv.Itoa(result.Failed),
		},
	})
	return &result, nil
}
