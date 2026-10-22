package auth

import (
	"context"
	"log/slog"
	"time"
)

// 新设备登录提醒（W1）：登录成功建会话后，若本次 UA 的规范化指纹与该用户**其它**
// 活跃会话的 UA 集合无匹配，就发一封提醒信。判定与发信都收口在 notifyNewLoginDevice
// 一处——completeLogin（web 密码/2FA/passkey、App passkey）、Login、LoginByEmailCode
// 与 OAuth token 兑换四族建会话路径都调它，新增登录路只要记得接这一处。
//
// **best-effort**：发信失败只 slog（带 uid），绝不拖慢/阻断登录（发送器自带 15s 超时
// 封顶）；进程内同步发即可——只有「新设备」才发，量级不需要队列。
//
// 触发面的两个刻意排除：
//   - **注册不算**（Register 建的首行会话）：刚注册就收「新设备登录」是噪音；
//   - **改密换发不算**（reissueToken）：同一台设备的凭据轮换，不是新设备。
//
// 审计不加新事件：登录审计（login.success）已有，通知是派生动作。

// uaFingerprint 把 UA 压成**机型族级**指纹：复用 shortDevice 的解析链（App UA →
// 友好机型；浏览器 UA → 「系统 · 机型」或「浏览器 · 系统」；认不出 → 未知设备），
// 不含浏览器版本号——同机同浏览器升个版本不该触发提醒。注意 App UA 与浏览器 UA
// 对同一台手机会得到两个指纹（「Pixel 8」vs「Android · Pixel 8」）：设备页本来就把
// App 会话与网页会话分列，跨形态登录同样值得提醒（契约性决策，见 B8 报告 D3）。
func uaFingerprint(ua string) string { return shortDevice(ua) }

// isNewDevice 判定「本次登录是不是新设备」：指纹不在其它活跃会话的指纹集合里即新。
// 抽成纯函数是为了不依赖数据库就能钉住判定口径。
func isNewDevice(known map[string]bool, ua string) bool { return !known[uaFingerprint(ua)] }

// otherSessionFingerprints 取该用户**除本次会话外**全部未吊销会话的 UA 指纹集合。
// 排除 sid 是必须的：新会话行在判定前已落库，不排掉它，自己的 UA 永远「匹配」。
func (s *Service) otherSessionFingerprints(uid, sid int64) (map[string]bool, error) {
	rows, err := s.pool.QueryContext(context.Background(),
		"SELECT user_agent FROM sessions WHERE user_id = ? AND revoked_at IS NULL AND id <> ?", uid, sid)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	known := map[string]bool{}
	for rows.Next() {
		var ua string
		if err := rows.Scan(&ua); err != nil {
			return nil, err
		}
		known[uaFingerprint(ua)] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return known, nil
}

// loginNotifyAppLabel 是提醒信里「项目」一行的取值：App 登录 = 品牌名，web 登录 =
// Auth 控制台（提醒信是账号级通知，说法与会话页的分列口径一致）。
func loginNotifyAppLabel(app string) string {
	if app == "" {
		return "Auth 控制台"
	}
	return brandFor(app).name
}

// notifyNewLoginDevice 登录成功后的提醒收口。sid 是本次新建的会话 id；email 是本次
// 登录的账号邮箱；app 空 = web 流程（中性品牌），非空 = App 流程（该 App 品牌）。
// 任何失败只记日志——通知是派生动作，不参与登录成败。
func (s *Service) notifyNewLoginDevice(uid, sid int64, email, app string, meta SessionMeta) {
	if s.mailer == nil {
		return
	}
	notify, err := s.loginNotify(uid)
	if err != nil {
		slog.Error("查登录提醒开关失败（跳过新设备提醒）", "uid", uid, "err", err)
		return
	}
	if !notify {
		return
	}
	known, err := s.otherSessionFingerprints(uid, sid)
	if err != nil {
		slog.Error("查活跃会话 UA 失败（跳过新设备提醒）", "uid", uid, "err", err)
		return
	}
	// 指纹与设备名都按**存储串**算：库里 user_agent 带 CH 后缀（uaWithCH），
	// 这里算的必须与 otherSessionFingerprints 读列现算的同一口径——否则带 CH 的
	// 每次登录都对不上指纹，每次登录都发一封「新设备」提醒。
	stored := meta.uaWithCH()
	if !isNewDevice(known, stored) {
		return
	}
	b := brandFor(app)
	subject, htmlBody, text := loginNotifyEmail(b, shortDevice(stored), loginNotifyAppLabel(app), time.Now())
	// 不接请求 ctx：发送器自带 15s 总超时，最坏也只是把这一次登录的收尾拖住
	if err := s.mailer.Send(context.Background(), b.name, email, subject, htmlBody, text); err != nil {
		slog.Error("发送新设备登录提醒失败", "uid", uid, "email", maskEmail(email), "err", err)
	}
}
