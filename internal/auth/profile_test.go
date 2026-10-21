package auth

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/WXies-Team/auth/internal/protocol"
)

// base64Of 造一段指定**解码后**字节数的合法 base64（内容是 'a'，不是真图片，
// 但对校验而言只有长度与字母表有意义）。
func base64Of(decodedBytes int) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", decodedBytes)))
}

// putReq 组一个 PUT /api/profile 的请求体。
func putReq(nickname string, color int, avatar *string) protocol.ProfileUpdateRequest {
	return protocol.ProfileUpdateRequest{Nickname: nickname, AvatarColor: color, AvatarImage: avatar}
}

// 档案读的默认值口径：没写过的账号 GET 回 {nickname:"",avatarColor:0,
// avatarImage:null,updatedAt:0}——而不是 404 或 null 整体。
func TestProfileGetReturnsDefaultsBeforeAnyWrite(t *testing.T) {
	svc, mailer := newTestService(t)
	reg := registerViaCode(t, svc, mailer, "profile-default@example.com", "secret123")
	caller, err := svc.ValidUserID("Bearer " + reg.Token)
	if err != nil {
		t.Fatalf("校验失败: %v", err)
	}

	got, err := svc.GetProfile(caller.UID)
	if err != nil {
		t.Fatalf("读档案: %v", err)
	}
	if got.Nickname != "" || got.AvatarColor != 0 || got.AvatarImage != nil || got.UpdatedAt != 0 {
		t.Errorf("默认档案应为全零值，得到 %+v", got)
	}
}

// PUT→GET 往返：三字段原样回读、updated_at 被服务端推进；nil 头像 = 清除。
// 昵称入库前 trim（回读不带空格），且空串昵称合法（=未设置）。
func TestProfileUpdateRoundTrip(t *testing.T) {
	svc, mailer := newTestService(t)
	reg := registerViaCode(t, svc, mailer, "profile-round@example.com", "secret123")
	caller, err := svc.ValidUserID("Bearer " + reg.Token)
	if err != nil {
		t.Fatalf("校验失败: %v", err)
	}

	avatar := base64Of(1024)
	if _, err := svc.UpdateProfile(caller, putReq("阿橘  ", 3, &avatar)); err != nil {
		t.Fatalf("写档案: %v", err)
	}
	got, err := svc.GetProfile(caller.UID)
	if err != nil {
		t.Fatalf("读档案: %v", err)
	}
	if got.Nickname != "阿橘" {
		t.Errorf("昵称应 trim 后原样回读，得到 %q", got.Nickname)
	}
	if got.AvatarColor != 3 {
		t.Errorf("头像色应回读为 3，得到 %d", got.AvatarColor)
	}
	if got.AvatarImage == nil {
		t.Error("头像应回读为非空")
	} else if *got.AvatarImage != avatar {
		t.Errorf("头像应往返一致，得到 %d 字符", len(*got.AvatarImage))
	}
	if got.UpdatedAt == 0 {
		t.Error("写过档案后 updatedAt 不该是 0")
	}
	first := got.UpdatedAt

	// 全量替换：清掉头像（nil）、换昵称与颜色——没传的字段就是被清空，不做局部合并
	if _, err := svc.UpdateProfile(caller, putReq("新昵称", 0, nil)); err != nil {
		t.Fatalf("二次写档案: %v", err)
	}
	got, err = svc.GetProfile(caller.UID)
	if err != nil {
		t.Fatalf("读档案: %v", err)
	}
	if got.Nickname != "新昵称" || got.AvatarColor != 0 || got.AvatarImage != nil {
		t.Errorf("全量替换后应是新值且头像已清除，得到 %+v", got)
	}
	if got.UpdatedAt < first {
		t.Errorf("updatedAt 应随写入推进，得到 %d < %d", got.UpdatedAt, first)
	}
	// 空串头像与 nil 同义（日记客户端 clearAvatarImage 发的正是空串）
	empty := ""
	if _, err := svc.UpdateProfile(caller, putReq("新昵称", 0, &empty)); err != nil {
		t.Fatalf("空串头像应放行: %v", err)
	}
	got, err = svc.GetProfile(caller.UID)
	if err != nil {
		t.Fatalf("读档案: %v", err)
	}
	if got.AvatarImage != nil {
		t.Errorf("空串头像应回读成 null，得到 %q", *got.AvatarImage)
	}
}

// 校验三闸：昵称 64 字过 / 65 字拒、坏 base64 拒、解码后超 700KB 回 **413**。
func TestProfileUpdateValidatesNicknameAndAvatar(t *testing.T) {
	svc, mailer := newTestService(t)
	reg := registerViaCode(t, svc, mailer, "profile-valid@example.com", "secret123")
	caller, err := svc.ValidUserID("Bearer " + reg.Token)
	if err != nil {
		t.Fatalf("校验失败: %v", err)
	}
	mustFail := func(nickname string, color int, avatar *string) (int, string) {
		t.Helper()
		if _, err := svc.UpdateProfile(caller, putReq(nickname, color, avatar)); err == nil {
			t.Fatalf("这次写入本该被拒: nicknameLen=%d", len(nickname))
		} else {
			return httpMsg(err)
		}
		return 0, ""
	}

	// 64 字（含中文，按字符计）放行、65 字拒绝——与日记库 VARCHAR(64) 同宽
	if _, err := svc.UpdateProfile(caller, putReq(strings.Repeat("昵", 64), 1, nil)); err != nil {
		t.Errorf("64 字昵称应放行: %v", err)
	}
	code, msg := mustFail(strings.Repeat("昵", 65), 1, nil)
	if code != 400 || !strings.Contains(msg, "64") || !strings.Contains(msg, "精简") {
		t.Errorf("65 字昵称应 400 且带 what+next，得到 %d %q", code, msg)
	}
	// 空串/全空白昵称是合法的（=未设置）
	if _, err := svc.UpdateProfile(caller, putReq("   ", 0, nil)); err != nil {
		t.Errorf("空昵称应放行: %v", err)
	}

	bad := "这不是 base64 /!!"
	code, msg = mustFail("n", 1, &bad)
	if code != 400 || !strings.Contains(msg, "Base64") {
		t.Errorf("坏 base64 应 400 并说明要 Base64，得到 %d %q", code, msg)
	}

	// 解码后 701KB > 700KB 上限 → 413（不是 400：载荷问题，重发同样的内容还是超）
	tooBig := base64Of(701 * 1024)
	code, msg = mustFail("n", 1, &tooBig)
	if code != 413 || !strings.Contains(msg, "过大") || !strings.Contains(msg, "压缩") {
		t.Errorf("超限头像应 413 且带 what+next，得到 %d %q", code, msg)
	}
	// 压线放行：解码正好 700KB
	edge := base64Of(700 * 1024)
	if _, err := svc.UpdateProfile(caller, putReq("n", 1, &edge)); err != nil {
		t.Errorf("解码正好 700KB 应放行: %v", err)
	}
}

// 审计：profile.update 成败都落行；detail 里只有字段名与长度类元信息——
// 昵称内容与头像数据一个字节都不许进 audit_logs。
func TestProfileUpdateWritesAuditWithoutContent(t *testing.T) {
	svc, mailer := newTestService(t)
	reg := registerViaCode(t, svc, mailer, "profile-audit@example.com", "secret123")
	caller, err := svc.ValidUserID("Bearer " + reg.Token)
	if err != nil {
		t.Fatalf("校验失败: %v", err)
	}

	const secretNick = "绝密昵称不要外传"
	avatar := base64Of(512)
	if _, err := svc.UpdateProfile(caller, putReq(secretNick, 5, &avatar)); err != nil {
		t.Fatalf("写档案: %v", err)
	}
	bad := "not-base64!!"
	if _, err := svc.UpdateProfile(caller, putReq(secretNick, 5, &bad)); err == nil {
		t.Fatal("坏 base64 本该被拒")
	}

	rows, _, err := svc.QueryAudit(AuditQuery{Action: AuditProfileUpdate, Actor: caller.UID, Limit: 10})
	if err != nil {
		t.Fatalf("查审计: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("profile.update 应落两行（ok + fail），得到 %d 行", len(rows))
	}
	byResult := map[string]AuditRow{}
	for _, r := range rows {
		byResult[r.Result] = r
	}
	okRow, ok := byResult["ok"]
	if !ok || okRow.Detail["nickname_len"] != "8" || okRow.Detail["avatar_image_set"] != "1" ||
		okRow.Detail["avatar_image_len"] != "684" {
		t.Errorf("成功审计应记长度类元信息（昵称 8 字、头像 684 字符），得到 %+v", okRow.Detail)
	}
	failRow, ok := byResult["fail"]
	if !ok || failRow.Detail["rejected_field"] != "avatar_image" {
		t.Errorf("失败审计应记被拒字段名，得到 %+v", failRow.Detail)
	}
	// 白盒：昵称内容与头像数据不得出现在 detail 任何一个值里
	for _, r := range rows {
		joined := strings.Join(detailValues(r.Detail), " ")
		for _, leak := range []string{secretNick, "绝密", avatar} {
			if strings.Contains(joined, leak) {
				t.Errorf("审计 detail 泄露了 %q: %+v", leak, r.Detail)
			}
		}
	}
}

// detailValues 把审计 detail 的值摊平成切片，失败信息里才看得到全部内容。
func detailValues(d map[string]string) []string {
	out := make([]string, 0, len(d))
	for _, v := range d {
		out = append(out, v)
	}
	return out
}

// 注销联动删行：user_profile 是按 user_id 存行的新表，账号删了它必须同批消失。
func TestProfileRowRemovedOnDeleteAccount(t *testing.T) {
	svc, mailer := newTestService(t)
	reg := registerViaCode(t, svc, mailer, "profile-del@example.com", "secret123")
	caller, err := svc.ValidUserID("Bearer " + reg.Token)
	if err != nil {
		t.Fatalf("校验失败: %v", err)
	}
	avatar := base64Of(256)
	if _, err := svc.UpdateProfile(caller, putReq("待注销", 2, &avatar)); err != nil {
		t.Fatalf("写档案: %v", err)
	}
	profileRows := func() int {
		var n int
		if err := svc.pool.QueryRow("SELECT COUNT(*) FROM user_profile WHERE user_id = ?", caller.UID).
			Scan(&n); err != nil {
			t.Fatalf("数档案行: %v", err)
		}
		return n
	}
	if profileRows() != 1 {
		t.Fatalf("注销前应有 1 行档案，得到 %d", profileRows())
	}

	// 钩子三键全缺 = 跳过日记侧清理（newTestService 的形态），本服务的删除事务照走
	if err := svc.DeleteAccount(caller.UID, "secret123"); err != nil {
		t.Fatalf("注销: %v", err)
	}
	if n := profileRows(); n != 0 {
		t.Errorf("注销后 user_profile 应被删空，残留 %d 行", n)
	}
}

// loginNotify（W1 新设备登录提醒开关）：默认开；显式 PUT 才改值，缺省 PUT 不动
//（App 的全量档案提交不带该字段，绝不能把提醒关掉）；GET 回执恒带当前值。
func TestProfileLoginNotifyRoundTrip(t *testing.T) {
	svc, mailer := newTestService(t)
	reg := registerViaCode(t, svc, mailer, "profile-notify@example.com", "secret123")
	caller, err := svc.ValidUserID("Bearer " + reg.Token)
	if err != nil {
		t.Fatalf("校验失败: %v", err)
	}

	// 默认开（users.login_notify DEFAULT 1），且从未写过档案也拿得到开关值
	got, err := svc.GetProfile(caller.UID)
	if err != nil {
		t.Fatalf("读档案: %v", err)
	}
	if !got.LoginNotify {
		t.Error("loginNotify 默认应为 true")
	}

	// 显式关：回执 false、GET 回读 false，档案三字段照常写
	off := false
	req := putReq("关提醒", 1, nil)
	req.LoginNotify = &off
	resp, err := svc.UpdateProfile(caller, req)
	if err != nil {
		t.Fatalf("关提醒: %v", err)
	}
	if resp.LoginNotify {
		t.Error("PUT 回执的 loginNotify 应为 false")
	}
	if got, err = svc.GetProfile(caller.UID); err != nil || got.LoginNotify {
		t.Errorf("关掉后 GET 应回 false（err=%v），得到 %v", err, got.LoginNotify)
	}

	// 缺省 PUT（App 的全量档案提交形态，不带 loginNotify）：开关保持 false 不被重置
	if _, err := svc.UpdateProfile(caller, putReq("再改名", 2, nil)); err != nil {
		t.Fatalf("缺省 PUT: %v", err)
	}
	if got, err = svc.GetProfile(caller.UID); err != nil || got.LoginNotify {
		t.Errorf("缺省 PUT 不该动开关，应保持 false（err=%v），得到 %v", err, got.LoginNotify)
	}
	if got.Nickname != "再改名" {
		t.Errorf("档案字段照常全量替换，昵称应为 再改名，得到 %q", got.Nickname)
	}

	// 再开：true 往返
	on := true
	req = putReq("再改名", 2, nil)
	req.LoginNotify = &on
	if resp, err = svc.UpdateProfile(caller, req); err != nil || !resp.LoginNotify {
		t.Fatalf("开提醒失败（err=%v），回执 %v", err, resp)
	}
	if got, err = svc.GetProfile(caller.UID); err != nil || !got.LoginNotify {
		t.Errorf("开启后 GET 应回 true（err=%v），得到 %v", err, got.LoginNotify)
	}
}
