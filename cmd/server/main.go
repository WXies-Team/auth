// Command server 是统一账号服务（auth.horatio.cn）。
//
// 与两个日记服务的 /auth/* 端点一一对应、JSON 字段完全一致（见 internal/protocol），
// 客户端从日记自带后端切到本端点时只需改 base URL 并在登录请求加 app 字段。
// 部署形态与日记服务相同：Go 单二进制 + supervisord，对外只经 nginx TLS 反代
// （默认绑 127.0.0.1:8868）。
package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/WXies-Team/auth/internal/auth"
	"github.com/WXies-Team/auth/internal/config"
	"github.com/WXies-Team/auth/internal/db"
	// 别名 mailsvc：包名 mail 与标准库 net/mail 同名，直引易混
	mailsvc "github.com/WXies-Team/auth/internal/mail"
	"github.com/WXies-Team/auth/internal/protocol"
)

// 请求体上限：认证请求都是小 JSON，64KB 足够挡住异常大包
const maxBodyBytes = 64 << 10

// maxProfileBodyBytes 是 PUT /api/profile 单独放大的请求体上限（1.5MB）：档案带
// 头像 base64，700KB 解码上限对应 955,736 个字符（见 internal/auth 的
// maxAvatarImageBytes 及其实测依据），通用 64KB 装不下。其余端点一律 maxBodyBytes。
const maxProfileBodyBytes = 1536 * 1024

type ctxKey int

// callerKey 放业务身份（老端点只认它）；webCallerKey 放双凭据解析的完整现场
//（CSRF hash、role、凭 cookie 还是 Bearer 进来）——两把钥匙同一次解析填。
const (
	callerKey ctxKey = iota
	webCallerKey
)

func main() {
	// 日志按级别分流（12-factor 口径）：Info→stdout，Warn/Error→stderr，
	// 让 supervisord 的两个日志文件各归各位。
	slog.SetDefault(slog.New(&splitHandler{
		out: slog.NewTextHandler(os.Stdout, nil),
		err: slog.NewTextHandler(os.Stderr, nil),
	}))

	if err := requireJWTSecret(os.Getenv("JWT_SECRET")); err != nil {
		slog.Error("JWT_SECRET 不可用", "err", err)
		os.Exit(1)
	}
	secret := os.Getenv("JWT_SECRET")

	// 连接串只认 MYSQL_DSN。启动失败 → supervisord 拉不起来 → deploy 脚本的
	// 健康检查失败 → 自动回滚。
	dsn, err := db.FromEnv()
	if err != nil {
		slog.Error("数据库连接串不可用", "err", err)
		os.Exit(1)
	}
	// 带重试地连库（不是一次失败就退出）：MySQL 冷启实测约 9 秒，立刻退出会让
	// supervisor 的 startretries 耗尽变成 FATAL，而且 MySQL 恢复后进程已不在、
	// **不会自己回来**。等 90 秒期间进程一直存活，MySQL 一就绪就自动服务。
	pool, err := db.OpenWithRetry(dsn, 90*time.Second)
	if err != nil {
		slog.Error("等待数据库超时，退出交给 supervisord 继续重试", "err", err)
		os.Exit(1)
	}
	defer func() { _ = pool.Close() }()
	if err := db.EnsureSchema(pool); err != nil {
		slog.Error("建表失败", "err", err)
		os.Exit(1)
	}

	cfg := config.New(pool)
	// 邮件凭据从 app_config 现读（10s 缓存，改库即热生效）。没配好时发码回 503
	//「邮件服务暂不可用」，属于可自愈的配置态而不是崩溃；启动时 Warn 一次，
	// 免得等用户注册失败才发现。
	for _, key := range []string{"mail_tenant_id", "mail_client_id", "mail_client_secret"} {
		v, err := cfg.Require(key)
		// 读库失败 ≠ 没配：分开喊，否则 DB 抖动会被「未配置」这条 Warn 带偏
		if err != nil {
			slog.Error("读邮件凭据失败（继续启动）", "key", key, "err", err)
		} else if v == "" {
			slog.Warn("邮件凭据未配置，注册与验证码邮件会失败", "key", key)
		}
	}
	// Passkey 的 RP 实例：网页 origin 固定；Android 原生仪式的 apk-key-hash 指纹
	// 从 app_config 键现读（webauthn_opaque_origins，逗号分隔，App 批次供指纹后灌库，
	// 改库 ≤10 秒热生效）。键没配 = 只放行网页端，两个 App 的原生仪式暂不可用。
	// 指纹写错也不拖垮启动：记 Error 后降级为「仅网页端」——登录服务的可用性优先，
	// 错误状态在启动日志里可见。
	wa, err := auth.NewWebAuthn(splitList(cfgRequire(cfg, "webauthn_opaque_origins")))
	if err != nil {
		slog.Error("Passkey 不透明 origin 配置无效，降级为仅网页端可用", "err", err)
		if plain, err2 := auth.NewWebAuthn(nil); err2 == nil {
			wa = plain
		}
	}

	authSvc, err := auth.NewService(pool, secret, mailsvc.New(cfg.StringFunc), auth.NewHooks(cfg.Require), wa)
	if err != nil {
		slog.Error("初始化认证服务", "err", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	// 路由注册整体挪进 registerRoutes：端点形状只有打到 handler 上才作数，
	// 抽出来才能被路由级回归测试钉住（老客户端契约见 routes_test.go）。
	registerRoutes(mux, authSvc, cfg, pool)

	// 兜底：未知错误 500 + ApiError 体，而不是让 Go 把栈吐给客户端
	handler := withRecover(mux)

	// 默认只绑回环：对外一律经 nginx TLS 反代，直连 8868 会把 JWT 走明文。
	addr := envOr("BIND_ADDR", "127.0.0.1:8868")
	// 超时三件套：没有它们，慢速 body（slowloris）或挂住不读的连接能长期占着 fd
	// 把服务拖垮。认证请求都是小包，60s 读写绰绰有余。
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		// 头部上限收到 16KB（默认 1MB）：防超大 header 内存占用
		MaxHeaderBytes: 16 << 10,
	}

	// 优雅关闭：supervisor stop/restart 发 SIGTERM，等在途请求处理完再退
	//（健康检查轮询有 30s 窗口，15s 收尾足够且不至于拖慢部署）。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		slog.Info("收到退出信号，等待在途请求完成")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("优雅关闭超时，强制退出", "err", err)
		}
	}()

	slog.Info("server starting", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server stopped", "err", err)
		os.Exit(1)
	}
	slog.Info("server exited")
}

// requireJWTSecret 校验签名密钥：缺失或短于 32 字节直接拒启——短 secret = 弱签名，
// 统一账号服务的 token 被破解波及所有下游应用，这里没有妥协余地。
func requireJWTSecret(secret string) error {
	if secret == "" {
		return errors.New("缺少 JWT_SECRET（环境变量），检查 supervisord 的 environment")
	}
	if len(secret) < 32 {
		return fmt.Errorf("JWT_SECRET 过短，至少 32 字节（当前 %d）", len(secret))
	}
	return nil
}

// envOr 读环境变量，空则给默认值。
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// cfgRequire 读配置键；读失败只记日志后按未配置处理——可选功能的配置读不出
// 不该挡住启动（mail 凭据那三键是另一档：发信是主流程，读失败会单独喊）。
func cfgRequire(cfg *config.Store, key string) string {
	v, err := cfg.Require(key)
	if err != nil {
		slog.Error("读配置键失败（按未配置处理）", "key", key, "err", err)
	}
	return v
}

// splitList 把逗号分隔的配置值拆成去空白的非空列表。
func splitList(raw string) []string {
	out := make([]string, 0, 4)
	for _, part := range strings.Split(raw, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// health 复刻日记服务的 /health 语义：**ping 数据库**（DB 挂了返回 5xx，
// deploy-server.sh 靠 `curl -fsS` 判定失败并自动回滚），再给两个配置开关位。
// 开关位**刻意外显**（定案不改）：本服务的健康即运维监控面，布尔只报
//「凭据配没配」，不含任何敏感值。
func health(pool *sql.DB, cfg *config.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ping 带 2s 超时：连接池被占满时 /health 不能无限排队——
		// 部署健康检查拿不到响应会误判回滚
		pingCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := pool.PingContext(pingCtx); err != nil {
			writeError(w, http.StatusServiceUnavailable, "数据库不可用")
			return
		}
		// 邮件凭据没有兜底值：缺键时发码全 503，/health 给个开关位让部署方自查，
		// 不用翻日志
		mailKey, err := cfg.Require("mail_client_secret")
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "数据库不可用")
			return
		}
		writeJSON(w, http.StatusOK, healthResponse{
			Status:         "ok",
			MailConfigured: mailKey != "",
			// 能启动到这里就说明 JWT_SECRET 已通过 ≥32 字节校验（拒启在 main 最前面），
			// 恒为 true——给部署方一眼确认「这个进程带着可用密钥在跑」
			JWTConfigured: true,
		})
	})
}

type healthResponse struct {
	Status         string `json:"status"`
	MailConfigured bool   `json:"mailConfigured"`
	JWTConfigured  bool   `json:"jwtConfigured"`
}

// verifier 是 internalVerify 依赖的最小接口：路由层测试注入假实现，不必拉起真库。
type verifier interface {
	Verify(bearer, expectApp string) (*auth.VerifyResult, error)
}

// verifyRatePerApp 是 /internal/verify 每个 app 每分钟的上限，额度与原设计一致
//（600 = 给多租户共享留的余量，挡的是误配置成公网可达后的打爆）。
const verifyRatePerApp = 600

// internalVerify 是日记服务 withUID 中间件要调的端点：POST /internal/verify，
// Bearer 用户 token + body {"app":"<期望 aud>"}。通过回 uid/email/app，
// 否则 401（错误体走 writeResult，含 503 的 DB 抖动分支）。
func internalVerify(v verifier) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req protocol.VerifyRequest
		if !decodeOr400(w, r, &req) {
			return
		}
		// app 缺失/未知在这里挡掉，不进 Verify——期望值都对不上就别浪费一次查库
		if req.App == "" {
			writeError(w, http.StatusBadRequest, "参数不正确")
			return
		}
		// 限流**按 app 分键**（键里不含来源）：两个日记服务都经同机回环调用，
		// clientIP 恒为 127.0.0.1——按 IP 分键等于全站共享一个 600/分桶，两家
		// 业务互相挤兑成 10rps 天花板。键里不放来源还有个副作用是正向的：
		// 误配公网可达时攻击者换 IP 也换不出新桶，整体打爆面仍然有界。
		// 未知 app 值乱敲会攒出无主桶，由 allow 的 >4096 惰性清理兜底。
		if !limiter.allow("verify:"+req.App, verifyRatePerApp, time.Minute) {
			limit429(w, r, "verify:"+req.App)
			return
		}
		res, err := v.Verify(r.Header.Get("Authorization"), req.App)
		if err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, protocol.VerifyResponse{UID: res.UID, Email: res.Email, App: res.App})
	})
}

// userEnsurer 是 internalEnsure 依赖的最小接口：路由层测试注入假实现，不必拉起真库。
type userEnsurer interface {
	EnsureUsers(entries []protocol.EnsureUserEntry) ([]protocol.EnsureUserResult, error)
}

// internalEnsure 是存量用户并入端点：POST /internal/users/ensure，
// 头 `Authorization: Bearer <hook_token>`，体是 0~100 条 EnsureUserEntry 数组，
// 回与入参同序的 [{email,uid}]。用途见 Service.EnsureUsers 的注释。
//
// hook_token 从 app_config 现读（10s 缓存，改库即热生效）。**键没配时恒 401**——
// 迁移凭据没进库就该一条也进不来；而读库失败回 503 而不是 401：把 DB 抖动当成
// 鉴权失败，会把排障方向带偏到「token 插错了」。
func internalEnsure(tokenFor auth.ConfigFunc, svc userEnsurer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want, err := tokenFor(auth.HookTokenKey)
		if err != nil {
			slog.Error("读 hook_token 失败", "err", err)
			writeError(w, http.StatusServiceUnavailable, "服务暂时不可用，请稍后重试")
			return
		}
		if want == "" {
			slog.Warn("hook_token 未配置，内部并入端点拒绝一切请求")
		}
		// 对不上连请求体都不读：不给为错配凭据白解一次 JSON 的机会。
		// 比较走常数时间（各自 sha256 后再比，长度差也被散列拉平）：直比字符串
		// 会按匹配前缀泄露进度，等于把这根共享密钥摆上线上逐位爆破的台面。
		wantSum := sha256.Sum256([]byte("Bearer " + want))
		gotSum := sha256.Sum256([]byte(r.Header.Get("Authorization")))
		if want == "" || subtle.ConstantTimeCompare(gotSum[:], wantSum[:]) != 1 {
			writeError(w, http.StatusUnauthorized, "未授权")
			return
		}
		var entries []protocol.EnsureUserEntry
		if !decodeOr400(w, r, &entries) {
			return
		}
		// 结果按入参顺序回，uid 是 int64（writeJSON 不会把它转成浮点）
		results, err := svc.EnsureUsers(entries)
		writeResult(w, results, err)
	})
}

// ---- 以下为通用中间件与 JSON 工具 ----

// decodeLimited 解码请求体。**故意不拒绝未知字段**——日记客户端的 DTO 可能多发字段，
// 客户端多发不该报错（否则加字段会让老客户端直接失败）。
// 超限走 http.MaxBytesReader：截断回结构化 413 而不是静默截断后的 400。
// limit 由调用方给：常规端点 maxBodyBytes（64KB），PUT /api/profile 单独放大到
// maxProfileBodyBytes——头像 base64 装不下小包口径，但只放大这一条路由。
func decodeLimited(w http.ResponseWriter, r *http.Request, v any, limit int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	err := json.NewDecoder(r.Body).Decode(v)
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		return errBodyTooLarge
	}
	return err
}

var errBodyTooLarge = errors.New("body too large")

// decodeOr400：decode 失败统一回执——超限 413、其余 400。全部 decode 入口共用，
// 避免每处手抄错误映射再漏掉 413。
func decodeOr400(w http.ResponseWriter, r *http.Request, v any) bool {
	return decodeOr400Limit(w, r, v, maxBodyBytes)
}

// decodeOr400Limit 同 decodeOr400 但可指定请求体上限（档案端点用）。
func decodeOr400Limit(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	if err := decodeLimited(w, r, v, limit); err != nil {
		if errors.Is(err, errBodyTooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "请求体过大")
		} else {
			writeError(w, http.StatusBadRequest, "请求格式不正确")
		}
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, message string) {
	writeJSON(w, code, protocol.ApiError{Message: message})
}

// writeResult 把业务结果翻译成「状态码 + ApiError 体」。
func writeResult(w http.ResponseWriter, v any, err error) {
	if err == nil {
		writeJSON(w, http.StatusOK, v)
		return
	}
	var he *auth.HTTPError
	if errors.As(err, &he) {
		writeError(w, he.Code, he.Message)
		return
	}
	// 内部错误（含 SQL 与路径）全进日志，客户端只拿固定文案——排障信息不丢，
	// 但不再外泄
	slog.Error("handler failed", "err", err, "cause", err.Error())
	writeError(w, http.StatusInternalServerError, "服务出了点问题，请稍后重试")
}

func withRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic", "err", rec, "path", r.URL.Path)
				// panic 穿过路由层的 withLogging（其 slog.Info 不再执行）：
				// 这里补一条同构 request 日志，panic 轮次也能按 500 检索
				slog.Info("request", "method", r.Method, "path", r.URL.Path,
					"status", http.StatusInternalServerError, "panicked", true)
				writeError(w, http.StatusInternalServerError, "服务出了点问题，请稍后再试")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// statusRecorder 记录状态码给 withLogging（只记 method/path 没法事后发现
// 429/503 异常与限流误伤）。
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		// nosniff 防 MIME 嗅探
		w.Header().Set("X-Content-Type-Options", "nosniff")
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		slog.Info("request", "method", r.Method, "path", r.URL.Path,
			"status", rec.status, "took", time.Since(start).Round(time.Millisecond))
	})
}

// withUID 解析**双凭据**并把身份放进 context；失败直接回 401/503。
//
// 三条路径（见 resolveCaller）：网页会话 cookie、JWT Bearer（老客户端的 /auth/login
// 与日记 App 经 app 分流拿到的同一种 token）、以及 web 会话 token 的 Bearer。顺带做两件事：
//
//   - 本次请求的来源（IP/UA）填进 Caller.Meta——改密换发新会话、审计都要它，
//     过了这层再想取原始请求就取不到了；
//   - **凭 cookie 进来的非 GET 请求校验 CSRF**（同步器 token，见 auth.WebCaller.CheckCSRF）。
//     Bearer 请求不做这一步：跨站脚本设置不了 Authorization 头，没有可搭的顺风车，
//     给它加校验只会把老客户端挡在门外。
func withUID(svc *auth.Service, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wc, err := resolveCaller(svc, r)
		if err != nil {
			writeResult(w, nil, err)
			return
		}
		wc.Meta = sessMeta(r)
		if wc.ViaCookie && !readMethod(r.Method) && !wc.CheckCSRF(r.Header.Get("X-CSRF-Token")) {
			writeError(w, http.StatusForbidden, "请求校验失败，请刷新页面后重试")
			return
		}
		ctx := context.WithValue(r.Context(), callerKey, wc.Caller)
		ctx = context.WithValue(ctx, webCallerKey, wc)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// readMethod 判定「不改状态的动词」——GET/HEAD/OPTIONS 不需要 CSRF token。
func readMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

// resolveCaller 按优先级解析凭据：
//
//  1. 会话 cookie（网页）→ sha256 点查 sessions.web_token_hash；
//  2. Bearer 是 JWT 形状（三个点）→ 走原有 ValidUserID，**语义与老客户端时代一字不变**
//     （日记 App 经 /web/login/* 与 /webauthn/login/finish 的 app 分流拿到的也是它）；
//  3. Bearer 不是 JWT 形状（web 台登录签的 32 字节会话 token）→ 同 1 的点查。
//
// 只有「非 JWT 形状」才落到 3：JWT 的验签失败在解析阶段就出错、不打库，
// 少一次无谓的点查；真 503（DB 抖动）原样往上抛，不能被当成「换个凭据再试」。
//
// **cookie 校验失败且带了 Bearer 头时继续尝试 Bearer**：浏览器会把过期/被踢的
// 残留 cookie 一并发上来，旧实现被它绑架成 401——同一浏览器里的 API 调用方
//（App WebView、脚本）明明带着有效 Bearer 也进不来。cookie 失败分两档：
// 503（DB 抖动）仍原样上抛（不能把抖动当成「换凭据再试」）；401 才回落 Bearer，
// 两者皆败才 401。
func resolveCaller(svc *auth.Service, r *http.Request) (auth.WebCaller, error) {
	header := r.Header.Get("Authorization")
	if ck, err := r.Cookie(auth.WebCookieName); err == nil && ck.Value != "" {
		wc, werr := svc.ValidWebSession(ck.Value)
		if werr == nil {
			return wc, nil
		}
		if header == "" {
			return auth.WebCaller{}, werr
		}
		var he *auth.HTTPError
		if errors.As(werr, &he) && he.Code == http.StatusServiceUnavailable {
			return auth.WebCaller{}, werr
		}
		// 401 的残留 cookie：落到下面的 Bearer 尝试
	}
	if header == "" {
		return auth.WebCaller{}, &auth.HTTPError{Code: 401, Message: "请先登录"}
	}
	caller, err := svc.ValidUserID(header)
	if err == nil {
		return auth.WebCaller{Caller: caller}, nil
	}
	if strings.Contains(strings.TrimPrefix(header, "Bearer "), ".") {
		return auth.WebCaller{}, err
	}
	return svc.ValidWebBearer(header)
}

// sessMeta 取登录会话要记的来源：IP 用限流同一套 clientIP（受信代理口径——
// 生产里裸 RemoteAddr 恒是同机 nginx，记它等于所有设备一个 IP），
// UA 取原文，设备标签由 auth 包解析（解析不出就存原文）。
func sessMeta(r *http.Request) auth.SessionMeta {
	return auth.SessionMeta{IP: clientIP(r), UserAgent: r.UserAgent()}
}

// loopbackOnly 只放行环回与受信内网来源的请求，其余 403。
//
// 内部端点（/internal/*）不该经 nginx 暴露：它们凭一根共享 bearer 就能用、
// 不挂面向公网的限流——一旦被反代到公网，等于在防火墙外开了扇没锁的侧门，
// 所以先按来源掐掉，再谈鉴权与限流。
//
// 判定只看 RemoteAddr：环回上的调用方就是同机的日记服务与迁移脚本，受信代理头
// （X-Forwarded-For / X-Real-IP）一律不看——公网客户端能随便伪造它们，看了等于没设。
// 信任范围与限流共用 TRUSTED_PROXIES（默认环回 + RFC1918/ULA 内网段）。
func loopbackOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !containsIP(trustedProxies(), hostOnly(r.RemoteAddr)) {
			slog.Warn("内部端点拒绝非受信来源", "path", r.URL.Path, "remote", r.RemoteAddr)
			writeError(w, http.StatusForbidden, "禁止访问")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---- 进程内滑动窗口限流（单实例部署假设：supervisord 只跑一个进程，多实例时
// 每个实例各自一套窗口，限流额度翻倍——上多实例前要把这里换成共享存储）----

type window struct {
	hits []time.Time
}

type rateLimiter struct {
	mu      sync.Mutex
	windows map[string]*window
}

var limiter = &rateLimiter{windows: map[string]*window{}}

// allow 每 [scope:key] 每 windowMs 内最多 max 次。
func (l *rateLimiter) allow(key string, max int, windowMs time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	// 攒太多时全量扫一遍，把**过期且再没人来过**的键清掉：惰性清理只在该键
	// 再次被访问时发生，长期不访问的键（如已注销账号）会永远留在 map 里。
	if len(l.windows) > 4096 {
		for k, w := range l.windows {
			stale := true
			for _, t := range w.hits {
				if now.Sub(t) < windowMs {
					stale = false
					break
				}
			}
			if stale {
				delete(l.windows, k)
			}
		}
	}
	w := l.windows[key]
	if w == nil {
		w = &window{}
		l.windows[key] = w
	}
	// 淘汰窗口外的；窗口清空后**整个键重建**——否则键会随账号数无限攒；
	// 重建时必须把当前请求记上，只删不记会把这一次漏计（首请求被静默放行两次）。
	kept := w.hits[:0]
	for _, t := range w.hits {
		if now.Sub(t) < windowMs {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		if max <= 0 {
			delete(l.windows, key)
			return false
		}
		l.windows[key] = &window{hits: []time.Time{now}}
		return true
	}
	w.hits = kept
	if len(w.hits) >= max {
		return false
	}
	w.hits = append(w.hits, now)
	return true
}

func limit(scope string, next http.Handler) http.Handler {
	return limitN(scope, 15, next)
}

// limitN 同 limit 但可指定每分钟上限（健康检查要放行部署轮询，15/分不够用）。
// 注意几条路由把本闸放在 withLogging **之外**（挡在读体/JWT 之前是刻意的）：
// 拒绝分支因此要自带 nosniff 与访问日志，否则 429 轮次在运维侧不可见。
func limitN(scope string, max int, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.allow(scope+":"+clientIP(r), max, time.Minute) {
			limit429(w, r, scope)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// limit429 是限流拒绝的统一回执（limitN 与 internalVerify 的按 app 分键共用）：
// 429 + Retry-After + nosniff，外加一条 429 状态的访问日志——限流拒绝发生在
// withLogging 内外的路由都有，少了这条日志，429 轮次在运维侧不可见。
func limit429(w http.ResponseWriter, r *http.Request, scope string) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Retry-After", "60")
	slog.Info("request", "method", r.Method, "path", r.URL.Path,
		"status", http.StatusTooManyRequests, "scope", scope)
	writeError(w, http.StatusTooManyRequests, "操作过于频繁，请稍后再试")
}

// clientIP 解析真实客户端 IP，只用于限流键。
//
// 生产里 nginx 在同机做 TLS 反代，请求转到本进程时 RemoteAddr 恒为代理地址——
// 直接当键会让**所有用户挤进同一个桶**，15 次/分的全站共享额度可被单点打满
//（打挂登录注册），反爆破的分 IP 粒度也完全失效。业界共识是「只信任受信代理
// 追加的转发值」，所以：
//
//  1. RemoteAddr 不是受信代理（环回/内网）→ 认定直连，用 RemoteAddr，XFF 一律不信
//     （否则任何客户端伪造一个 X-Forwarded-For 就能每请求换一个键，限流被绕过）
//  2. 是受信代理 → 优先 X-Forwarded-For：从**右端**往左找第一个非受信地址——右端是
//     代理自己按 TCP 对端追加的、客户端伪造不了；左端的旧值才可能是客户端自带的。
//     XFF 没有（nginx 只配了 X-Real-IP 的常见部署）→ 用 X-Real-IP（同样是代理
//     按 $remote_addr 写的，客户端改不了），它也不可信才回落 RemoteAddr
//  3. 两个头都没有（本机 curl /health 这类）→ 回落 RemoteAddr
//
// 想改信任范围用 TRUSTED_PROXIES（逗号分隔 CIDR/IP，默认环回+内网）。
func clientIP(r *http.Request) string {
	remote := hostOnly(r.RemoteAddr)
	trusted := trustedProxies()
	if !containsIP(trusted, remote) {
		return remote
	}
	for _, header := range r.Header.Values("X-Forwarded-For") {
		parts := strings.Split(header, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(parts[i])
			if ip == "" || net.ParseIP(ip) == nil {
				continue // 空串/非 IP（伪造垃圾）跳过，继续往左找
			}
			if !containsIP(trusted, ip) {
				return ip
			}
		}
	}
	if real := strings.TrimSpace(r.Header.Get("X-Real-IP")); net.ParseIP(real) != nil {
		return real
	}
	return remote
}

// hostOnly 去掉 RemoteAddr 的端口；SplitHostPort 失败时按原样返回。
func hostOnly(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// trustedProxies 解析受信代理集合：TRUSTED_PROXIES 显式配置优先，
// 未配置时默认环回 + RFC1918/ULA 内网段（同机 nginx 与机房内部负载都在此列）。
func trustedProxies() []string {
	if v := os.Getenv("TRUSTED_PROXIES"); v != "" {
		return strings.Split(v, ",")
	}
	return []string{"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"}
}

// containsIP 判断 ip 是否命中受信集合中的某一项（精确 IP 或 CIDR）。
func containsIP(trusted []string, ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, t := range trusted {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if strings.Contains(t, "/") {
			if _, cidr, err := net.ParseCIDR(t); err == nil && cidr.Contains(parsed) {
				return true
			}
			continue
		}
		if addr := net.ParseIP(t); addr != nil && addr.Equal(parsed) {
			return true
		}
	}
	return false
}

// jsonBody 解码请求体后交给 h。不拒绝未知字段（见 decode 注释）。
func jsonBody[T any](h func(*T, http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req T
		if !decodeOr400(w, r, &req) {
			return
		}
		h(&req, w, r)
	})
}

// splitHandler 按级别把记录分流到两个 handler（<Warn→stdout，≥Warn→stderr），
// 让 supervisord 的 stdout/stderr 两个日志文件各归各位。
type splitHandler struct {
	out slog.Handler
	err slog.Handler
}

func (h *splitHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.out.Enabled(ctx, level) || h.err.Enabled(ctx, level)
}

func (h *splitHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= slog.LevelWarn {
		return h.err.Handle(ctx, r)
	}
	return h.out.Handle(ctx, r)
}

func (h *splitHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &splitHandler{out: h.out.WithAttrs(attrs), err: h.err.WithAttrs(attrs)}
}

func (h *splitHandler) WithGroup(name string) slog.Handler {
	return &splitHandler{out: h.out.WithGroup(name), err: h.err.WithGroup(name)}
}
