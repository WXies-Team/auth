// Package auth 实现注册/登录/改密/注销与 JWT 会话。
//
// 业务逻辑照抄热量日记服务的同名包（久经生产考验），差异只在三处：
//   - **users.id 是 7 位随机整数**（1,000,000~9,999,999，crypto/rand + 主键撞号重试，
//     见 newUserID）：不暴露注册顺序、可口播可手输。雪花（bwmarrin/snowflake，
//     node id=1）退居**内部 id**——sessions/audit_logs/passkeys/webauthn_challenges
//     的行 id 仍用它，`s.ids` 不动；
//   - **JWT aud = 登录请求声明的应用**（白名单 calorie-diary / expense-diary）：
//     本服务是所有应用的统一签发方，aud 是下游服务划界的依据；
//   - **验证码落库**（原实现存进程内存，重启即失效）：语义逐条对齐，见 otp.go。
//
// 客户端依赖的行为契约（不能变）：
//   - bcrypt cost 12、密码 8~72 字节、邮箱 trim+小写 + 254 字符
//   - JWT: HS256、iss=auth、claims uid/email/ver/aud、有效期 90 天（与旧版一致，
//     避免客户端为切换服务端改 token 刷新逻辑）
//   - 校验时**必须查库比对 ver**——logout 靠 token_version+1 吊销，不比对则吊销是假的
//   - 错误语义：格式类 400、凭据类 401（客户端据此区分「重填」与「重新登录」）
package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/WXies-Team/auth/internal/protocol"
	"github.com/bwmarrin/snowflake"
	"github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	minPassword  = 8
	maxPasswordB = 72

	issuer   = "auth"
	// 与旧版一致：90 天。下游客户端按旧口径刷新，切换服务端不需要改造
	tokenTTL = 90 * 24 * time.Hour
	// 与旧版 BCrypt.withDefaults().hashToString(12, ...) 一致
	bcryptCost = 12

	// nodeID 是雪花节点号固定值。内部 id（会话/审计/凭证/仪式行）只有这一个签发点，
	// 1 即可；改它会让新 id 与存量 id 撞号段，**永远不要动**。
	nodeID = 1
)

// dummyPasswordHash 是一条**预先生成的、合法的 bcrypt cost12 哈希**。
//
// 唯一用途：登录时邮箱**不存在**的分支也要跑一次等价的 bcrypt 比对（结果必然
// 不匹配），把「查无此邮箱」的响应时间拉平到与「密码错」一致——否则攻击者靠
// 这几百毫秒的差值就能枚举哪些邮箱注册过。
//
// 它不参与任何放行判定——比对结果被丢弃、只为了烧等量 CPU。生成一次写死即可：
//
//	bcrypt.GenerateFromPassword([]byte("<任意字符串>"), 12)
//
// 换成别的 cost 或坏串会让「拉平」名存实亡，TestDummyPasswordHashIsPrecomputedCost12
// 钉住这条。
const dummyPasswordHash = "$2a$12$fLhdHrkU7451wJMbFcZKnOa0fZVVzqzWBgVx26XH1iYr2MA7crh8W"

// allowedApps 是 JWT aud 白名单。加新应用 = 改这里（同时下游服务要实现
// /internal/verify 的期望 aud 比对）。
var allowedApps = map[string]bool{
	"calorie-diary": true,
	"expense-diary": true,
}

// HTTPError 携带状态码，由路由层翻译成 ApiError 响应体。
type HTTPError struct {
	Code    int
	Message string
}

func (e *HTTPError) Error() string { return e.Message }

func badRequest(msg string) error   { return &HTTPError{400, msg} }
func unauthorized(msg string) error { return &HTTPError{401, msg} }

// Response 是 /auth/register 与 /auth/login 的响应体，字段名与 AuthResponse 一致。
type Response struct {
	Token string `json:"token"`
	Email string `json:"email"`
}

// Mailer 是发信能力的最小接口：生产用 internal/mail 的 Graph 实现，测试注入假实现
// （这样真库测试不会往外真发信）。fromName 是这封信的发件人显示名（品牌名，见
// brandFor）——与正文品牌同源取值，分头各传一套必然漂。
type Mailer interface {
	Send(ctx context.Context, fromName, to, subject, html string) error
}

// Caller 是已验签会话的身份信息：路由层验完放进 context，业务层直接用——
// 改密重发 token 的 aud/email 从这里来，客户端不用在改密请求里再传一遍。
type Caller struct {
	UID   int64
	Email string
	App   string
	// SID 是本 token 绑定的登录会话 id：设备列表的 current、踢人时保留谁都看它。
	SID int64
	// Meta 是本次请求的来源（IP + UA），改密换发新 token 时给新会话建行用；
	// 由路由层的 withUID 从 *http.Request 填，业务层不碰 HTTP。
	Meta SessionMeta
}

// VerifyResult 是 /internal/verify 的成功回执。
type VerifyResult struct {
	UID   int64
	Email string
	App   string
}

// Service 依赖一个 *sql.DB；nil 会让所有调用返回错误（未接库时的降级）。
// mailer 为 nil 时只有 SendCode 降级（回 503），登录等既有功能不受影响。
// hooks 为 nil 表示不接注销钩子（仅测试形态）；生产恒传入，见 [NewHooks]。
type Service struct {
	pool   *sql.DB
	secret string
	ids    *snowflake.Node
	otps   *otpStore
	mailer Mailer
	hooks  *Hooks
	// totpKey 是 TOTP secret 的 AES-256-GCM 密钥（TOTP_ENC_KEY，≥32 字节拒启）；
	// recoveryPepper 是恢复码 HMAC 的密钥，由 JWT_SECRET 域分隔派生——同一根密钥
	// 派两把子密钥，一把出事不牵连另一把。
	totpKey        []byte
	recoveryPepper []byte
	// wa 是 WebAuthn RP 实例（配置见 auth.NewWebAuthn）。nil = Passkey 端点回 503，
	// 其余功能不受影响——主流程不该因为一个可选功能起不来就全站宕掉。
	wa *webauthn.WebAuthn
	// credBySID 记「本会话用哪把 Passkey 登录」（列表页 current 标记），见 passkey.go。
	credBySIDMu sync.RWMutex
	credBySID   map[int64]string
	// enforceCfg 读 totp_enforce_apps（老客户端密码登录的兼容开关，默认空=不拦）。
	// nil 时恒放行（测试形态与「配置还没接」的形态一致）。
	enforceCfg ConfigFunc
}

// SetEnforceApps 注入兼容开关的配置读取器（生产传 cfg.Require，测试不设即全放行）。
func (s *Service) SetEnforceApps(f ConfigFunc) { s.enforceCfg = f }

// enforceTOTPFor 判定这条老端点密码登录要不要被拦：app 在 totp_enforce_apps 名单里
// **且**该账号已启用两步验证。
//
// 这是老客户端唯一的行为开关（规格 D1）：默认空名单 = 一行影响都没有；翻开关是
// 作者在 App 覆盖率够了之后的显式动作。读键失败按未配置放行——兼容开关读不出来
// 不该变成全站拦登录。
func (s *Service) enforceTOTPFor(app string, uid int64) bool {
	if s.enforceCfg == nil || app == "" {
		return false
	}
	raw, err := s.enforceCfg("totp_enforce_apps")
	if err != nil {
		slog.Warn("读 totp_enforce_apps 失败，按未配置处理", "err", err)
		return false
	}
	if !containsCSV(raw, app) {
		return false
	}
	enabled, err := s.TOTPEnabled(uid)
	if err != nil {
		// DB 抖动时不拦：开关的目的是渐进迁移，不是把老客户端误杀在抖动上
		slog.Warn("查两步验证状态失败，放行老端点登录", "uid", uid, "err", err)
		return false
	}
	return enabled
}

// containsCSV 判断 value 是否在逗号分隔的列表里（大小写敏感，App 名是标识符）。
func containsCSV(list, value string) bool {
	for _, item := range strings.Split(list, ",") {
		if strings.TrimSpace(item) == value {
			return true
		}
	}
	return false
}

// NewService 组装服务。除 JWT 密钥外还要求 TOTP_ENC_KEY 就位：TOTP secret 必须存
// 原值（验证要用），没有可用加密密钥时上线只会埋一颗「绑了却验不了」的雷，
// 与 JWT_SECRET 短于 32 字节同款拒启口径。wa 为 nil 时只有 Passkey 端点降级。
func NewService(pool *sql.DB, jwtSecret string, mailer Mailer, hooks *Hooks, wa *webauthn.WebAuthn) (*Service, error) {
	node, err := snowflake.NewNode(nodeID)
	if err != nil {
		return nil, fmt.Errorf("初始化雪花节点: %w", err)
	}
	totpKey, err := requireTOTPEncKey()
	if err != nil {
		return nil, err
	}
	return &Service{
		pool: pool, secret: jwtSecret, ids: node, otps: &otpStore{pool: pool},
		mailer: mailer, hooks: hooks,
		totpKey: totpKey, recoveryPepper: deriveRecoveryPepper(jwtSecret), wa: wa,
	}, nil
}

var emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

func normalizeEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

func validateEmail(email string) error {
	if len(email) > 254 || !emailRe.MatchString(email) {
		return badRequest("邮箱格式不正确，例如 123@example.com")
	}
	return nil
}

// validatePassword 与旧版同规则；超长密码在登录时**故意按凭据错误处理**，
// 避免 bcrypt 抛异常变成 500。
func validatePassword(password string) error {
	if len([]rune(password)) < minPassword {
		return badRequest("密码至少8位")
	}
	if len(password) > maxPasswordB {
		return badRequest("密码过长，请换用更短的密码")
	}
	return nil
}

// validateApp 校验登录请求声明的应用（JWT aud 的来源）：白名单外一律拒。
func validateApp(app string) error {
	if !allowedApps[app] {
		return badRequest("参数不正确")
	}
	return nil
}

// AppAllowed 导出白名单查询，给路由层校验调用方声明的应用标识用
//（/internal/ai/* 三端点）：加新应用仍只改 allowedApps 一处。
func AppAllowed(app string) bool { return allowedApps[app] }

func hash(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("生成口令散列: %w", err)
	}
	return string(b), nil
}

func verify(password, hashed string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password)) == nil
}

// createToken 签发 JWT。
//
// **uid 与 sid 都以 JSON 数字（int64）进 claims**：序列化无损；解析侧必须配
// jwt.WithJSONNumber（见 parseToken），否则 sid 这个 63 位雪花 id 过一遍 float64 就花位。
// sid 指向本次登录建的会话行——校验时要对上（见 sessionAlive），没有 sid 的 token
// 一律不认（切换到会话表之前的存量 token，客户端重登即消）。
//
// 签名与校验都发生在本服务，aud 只做下游服务之间的权限边界标记（A 服务的 token
// 不能被 B 服务接受），所以单密钥即可，不需要按应用分密钥。
func (s *Service) createToken(userID int64, email, app string, version int, sid int64) (string, error) {
	claims := jwt.MapClaims{
		"aud":   app,
		"iss":   issuer,
		"uid":   userID,
		"email": email,
		"ver":   version,
		"sid":   sid,
		"exp":   time.Now().Add(tokenTTL).Unix(),
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(s.secret))
	if err != nil {
		return "", fmt.Errorf("签发 token: %w", err)
	}
	return signed, nil
}

// parseToken 验签并抽出 claims（**不含** aud 校验：登录端点查白名单、/internal/verify
// 查精确匹配，两处期望不同）。
//
// jwt.WithJSONNumber 是硬要求：**sid 是 63 位雪花整数**，默认解析走 float64
//（53 位尾数）丢精度，错位的 sid 会让会话校验查到别的会话上。uid 自 2026-10 起
// 只是 7 位随机数（float64 装得下），但同一份 claims 解析不按 uid 宽度分叉，一律读整数。
func (s *Service) parseToken(token string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("意外的签名算法 %v", t.Header["alg"])
		}
		return []byte(s.secret), nil
	},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(issuer),
		// 无 exp 的 token 不该过签名校验
		jwt.WithExpirationRequired(),
		jwt.WithJSONNumber(),
	)
	if err != nil || !parsed.Valid {
		return nil, unauthorized("登录已过期，请重新登录")
	}
	return claims, nil
}

// claimInt64 读 json.Number 形态的数字 claim（WithJSONNumber 下所有数字都是它）。
func claimInt64(claims jwt.MapClaims, key string) (int64, bool) {
	n, ok := claims[key].(json.Number)
	if !ok {
		return 0, false
	}
	v, err := n.Int64()
	return v, err == nil
}

// bearerToken 严格 "Bearer " 前缀（带空格）：无空格甚至无前缀一律不认——
// 把解析宽容度留给攻击面不值得。
func bearerToken(header string) (string, bool) {
	if !strings.HasPrefix(header, "Bearer ") {
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	return token, token != ""
}

// ValidUserID 校验 JWT（aud 在白名单内）、**查库比对 ver** 并确认会话还活着，
// 返回会话身份。
//
// 只验签名不验 ver 的话，logout / 改密的吊销就完全失效——正是靠
// tokenVersion(uid) == claims.ver 挡住已登出的 token；会话是第二道闸：
// 设备列表里被踢的那台靠 sessionAlive 判失效（踢人不 bump token_version，
// 只有会话层能拦住它——不拦的话被踢设备还能调改密注销这类 auth 端点）。
//
// **没有 sid 的 token 一律 401**：切换到会话表之前签的存量 token 全部要求重登
// （作者定案：切换后客户端全部重登，线上存量为 0，不为它们留兼容分支）。
func (s *Service) ValidUserID(bearer string) (Caller, error) {
	token, ok := bearerToken(bearer)
	if !ok {
		return Caller{}, unauthorized("请先登录")
	}
	claims, err := s.parseToken(token)
	if err != nil {
		return Caller{}, err
	}
	aud, _ := claims.GetAudience()
	if len(aud) == 0 || !allowedApps[aud[0]] {
		return Caller{}, unauthorized("登录已过期，请重新登录")
	}
	uid, ok1 := claimInt64(claims, "uid")
	ver, ok2 := claimInt64(claims, "ver")
	sid, ok3 := claimInt64(claims, "sid")
	email, ok4 := claims["email"].(string)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return Caller{}, unauthorized("登录已过期，请重新登录")
	}
	stored, err := s.tokenVersion(uid)
	if err != nil {
		// DB 抖动不能当会话失效：客户端收到 401 会**清掉本地 token**，
		// 一次 MySQL 超时就等于把全站设备静默登出 → 503 按普通失败重试
		return Caller{}, &HTTPError{503, "服务暂时不可用，请稍后重试"}
	}
	if stored != int(ver) {
		return Caller{}, unauthorized("登录已过期，请重新登录")
	}
	alive, err := s.sessionAlive(uid, sid)
	if err != nil {
		return Caller{}, &HTTPError{503, "服务暂时不可用，请稍后重试"}
	}
	if !alive {
		return Caller{}, unauthorized("登录已过期，请重新登录")
	}
	return Caller{UID: uid, Email: email, App: aud[0], SID: sid}, nil
}

// Verify 供日记服务的 withUID 中间件调用：验签 + **aud 精确匹配**期望应用 +
// 查库比对 token_version + **会话未被踢**。通过回 uid/email/app，否则 401（DB 抖动
// 503，调用方按普通失败重试，别把一次超时当成会话失效）。
//
// 会话闸与 ValidUserID 同源（sessionAlive）：设备列表踢掉一台，被踢设备的 token
// 在**所有**入口当场失效，而不是只在日记侧失效；无 sid 的存量 token 同样 401。
func (s *Service) Verify(bearer, expectApp string) (*VerifyResult, error) {
	token, ok := bearerToken(bearer)
	if !ok {
		return nil, unauthorized("登录已过期，请重新登录")
	}
	claims, err := s.parseToken(token)
	if err != nil {
		return nil, err
	}
	aud, _ := claims.GetAudience()
	// 精确匹配而非白名单：下游服务只该接受为自己签发的会话。expectApp 不在
	// 白名单时这里自然不匹配（本服务只会为白名单应用签发），无需单独校验。
	if len(aud) == 0 || aud[0] != expectApp {
		return nil, unauthorized("登录已过期，请重新登录")
	}
	uid, ok1 := claimInt64(claims, "uid")
	ver, ok2 := claimInt64(claims, "ver")
	sid, ok3 := claimInt64(claims, "sid")
	email, ok4 := claims["email"].(string)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return nil, unauthorized("登录已过期，请重新登录")
	}
	stored, err := s.tokenVersion(uid)
	if err != nil {
		return nil, &HTTPError{503, "服务暂时不可用，请稍后重试"}
	}
	if stored != int(ver) {
		return nil, unauthorized("登录已过期，请重新登录")
	}
	alive, err := s.sessionAlive(uid, sid)
	if err != nil {
		return nil, &HTTPError{503, "服务暂时不可用，请稍后重试"}
	}
	if !alive {
		return nil, unauthorized("登录已过期，请重新登录")
	}
	return &VerifyResult{UID: uid, Email: email, App: aud[0]}, nil
}

func (s *Service) tokenVersion(userID int64) (int, error) {
	var v int
	err := s.pool.QueryRowContext(context.Background(), "SELECT token_version FROM users WHERE id = ?", userID).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return v, err
}

// userExists 查邮箱是否已注册（Register 的查重与 SendCode 的用途分流共用一处）。
func (s *Service) userExists(email string) (bool, error) {
	var exists bool
	if err := s.pool.QueryRowContext(context.Background(),
		"SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)", email).Scan(&exists); err != nil {
		return false, fmt.Errorf("查重: %w", err)
	}
	return exists, nil
}

// Register 注册并直接返回可登录的 token（与旧版一致：注册即登录）。
//
// **验证码必填**：校验放在「查重」之后——注册状态本就是既有接口对所有请求可见的
// 信息，提前验证码校验换不来任何防护，只会让老客户端看到陌生的「验证码错误」。
// meta 是本次请求的来源（IP/UA），注册即登录，所以同样要建一行登录会话。
func (s *Service) Register(rawEmail, password, code, app string, meta SessionMeta) (resp *Response, err error) {
	// 审计成败都记：注册是账号生命周期的起点，失败尝试（验证码错、邮箱已占）
	// 同样有排查价值。uid 在生成后回填，defer 闭包读的是最终值。
	var uid int64
	defer func() {
		s.Audit(AuditEvent{
			Action: AuditRegister, OK: err == nil, ActorUID: uidPtr(uid),
			ActorEmail: maskEmail(normalizeEmail(rawEmail)), Meta: meta,
			Detail: map[string]string{"app": app},
		})
	}()
	email := normalizeEmail(rawEmail)
	if err := validateEmail(email); err != nil {
		return nil, err
	}
	if err := validatePassword(password); err != nil {
		return nil, err
	}
	if err := validateApp(app); err != nil {
		return nil, err
	}
	exists, err := s.userExists(email)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, badRequest("该邮箱已注册，请直接登录")
	}
	if err := s.otps.verify(PurposeRegister, email, code); err != nil {
		return nil, err
	}
	// bcrypt 放到所有校验之后：前几步失败时不必白烧一次百毫秒的 cost12
	hashed, err := hash(password)
	if err != nil {
		return nil, err
	}

	// 用户行与会话行同批提交：会话插入单走一次、失败了却把账号留下，用户重试
	// 只会撞「该邮箱已注册」，而他手里既没有 token 也没有会话。
	ctx := context.Background()
	tx, err := s.pool.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("开事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// uid 由服务生成（7 位随机，撞号由 newUserID 换号重试），不走 LastInsertId——
	// users.id 不是自增列
	uid, err = newUserID(randUserID, func(id int64) error {
		_, e := tx.ExecContext(ctx,
			"INSERT INTO users (id, email, password_hash, created_at, token_version) VALUES (?, ?, ?, ?, 1)",
			id, email, hashed, time.Now().UnixMilli())
		return e
	})
	if err != nil {
		// 并发下同邮箱先被占：uq_users_email 挡住，翻译成人话（与 ChangeEmail 同口径；
		// 顺带把含邮箱的 MySQL 错误串挡在日志外）。撞号的 1062 到不了这里——
		// newUserID 已经换号重试，原样上抛的只有邮箱键与真故障。
		var me *mysql.MySQLError
		if errors.As(err, &me) && me.Number == 1062 {
			return nil, badRequest("该邮箱已注册，请直接登录")
		}
		return nil, fmt.Errorf("创建用户: %w", err)
	}
	sid, err := s.createSessionOn(tx, uid, app, meta)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("提交注册: %w", err)
	}
	tok, err := s.createToken(uid, email, app, 1, sid)
	if err != nil {
		return nil, err
	}
	return &Response{Token: tok, Email: email}, nil
}

// maxEnsureBatch 是单批并入条数上限。100 条（每条约 370 字节 JSON）远在路由层
// 64KB 请求体上限之内；不设上限则一次误操作能把整库灌进 users，
// 出错时回滚的代价也随批大小无界放大。
const maxEnsureBatch = 100

// EnsureUsers 把两个日记服务的存量用户批量并入本服务——**这是存量迁移的唯一入口**。
//
// uid 一律由本服务单点生成（与 Register 同一个 newUserID：7 位随机 + 撞号重试），
// 业务侧禁止各自造号：账号 id 只有一个签发点，两个 App 各造各的号，
// 同一账号在 auth 与业务库就会长出两套对不上的 uid。
//
// 已存在的邮箱只回它的 uid，**不动已有行的任何字段**——迁移脚本因此可以整批重跑
// （幂等），重复执行不会覆盖用户后来改过的密码或注册时间。
// password_hash 原样落库（NULL = 该用户在旧库只有邮箱验证码登录），created_at 用入参：
// 迁移要保留真实注册时间，写成 now 会让全部老用户看起来都是今天注册的。
//
// 整批一个事务：任何一条失败全部回滚。邮箱归一化与格式校验在事务内逐条做，
// 是刻意的——后半批出现非法条目时，前半批已插入的行靠事务一起回滚，
// 「要么整批进、要么一条不进」由数据库保证，不靠调用方自觉。
func (s *Service) EnsureUsers(entries []protocol.EnsureUserEntry) ([]protocol.EnsureUserResult, error) {
	if len(entries) > maxEnsureBatch {
		return nil, badRequest(fmt.Sprintf("单批最多 %d 条", maxEnsureBatch))
	}
	results := make([]protocol.EnsureUserResult, 0, len(entries))

	tx, err := s.pool.BeginTx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("开事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for i, e := range entries {
		email := normalizeEmail(e.Email)
		if err := validateEmail(email); err != nil {
			// 迁移脚本按批排错，报出条目下标（0 起）才定位得到源数据
			return nil, badRequest(fmt.Sprintf("下标 %d 的条目: %s", i, err.Error()))
		}
		var uid int64
		err := tx.QueryRowContext(context.Background(),
			"SELECT id FROM users WHERE email = ?", email).Scan(&uid)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			// nil 指针走 NULL（纯验证码账号），非 nil 原样落库
			var hash any
			if e.PasswordHash != nil {
				hash = *e.PasswordHash
			}
			uid, err = newUserID(randUserID, func(id int64) error {
				_, insErr := tx.ExecContext(context.Background(),
					"INSERT INTO users (id, email, password_hash, created_at, token_version) VALUES (?, ?, ?, ?, 1)",
					id, email, hash, e.CreatedAt)
				return insErr
			})
			if err != nil {
				return nil, fmt.Errorf("并入用户（下标 %d）: %w", i, err)
			}
		case err != nil:
			return nil, fmt.Errorf("查存量用户（下标 %d）: %w", i, err)
		default:
			// 已存在：回 uid 即可，已有行的 password_hash / created_at / token_version 一律不碰
		}
		results = append(results, protocol.EnsureUserResult{Email: email, UID: uid})
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("提交并入: %w", err)
	}
	slog.Info("存量用户并入完成", "count", len(results))
	return results, nil
}

// Login 校验凭据并签发 token。邮箱不存在与密码错误**返回同一句话**，
// 避免被人用来枚举哪些邮箱注册过。meta（IP/UA）给这次登录建 session 行。
func (s *Service) Login(rawEmail, password, app string, meta SessionMeta) (resp *Response, err error) {
	// 审计：成功/失败都记，detail.method=password 与另外两条登录路区分。
	// 密码**绝不**进 detail（测试有白盒断言钉这一条）。
	var uid int64
	defer func() {
		s.Audit(AuditEvent{
			Action: AuditLogin, OK: err == nil, ActorUID: uidPtr(uid),
			ActorEmail: maskEmail(normalizeEmail(rawEmail)), Meta: meta,
			Detail: map[string]string{"method": "password", "app": app},
		})
	}()
	// app 格式错是客户端 bug，先于凭据校验回 400（凭据类 401 会误导排障）
	if err := validateApp(app); err != nil {
		return nil, err
	}
	uid, version, err := s.checkPassword(rawEmail, password)
	if err != nil {
		return nil, err
	}
	// 兼容开关（默认关）：账号开了 2FA 且该 App 在 totp_enforce_apps 名单里 →
	// 拒绝老端点密码登录，提示升级。判定放在密码验过**之后**——没对上密码的
	// 请求不该听得出「这账号开了 2FA」。
	if s.enforceTOTPFor(app, uid) {
		return nil, &HTTPError{401, "请升级应用后使用新版登录"}
	}
	sid, err := s.createSession(uid, app, meta)
	if err != nil {
		return nil, err
	}
	tok, err := s.createToken(uid, normalizeEmail(rawEmail), app, version, sid)
	if err != nil {
		return nil, err
	}
	return &Response{Token: tok, Email: normalizeEmail(rawEmail)}, nil
}

// checkPassword 校验邮箱+密码，回 uid 与当前 token_version。
//
// **JWT 路（Login）与 web 密码登录共用这一处**：凭据判定只有一份实现，防枚举的
// 恒时假比对（邮箱不存在也烧一次 cost12 bcrypt）才不会在某条路上漏掉。
// 语义与旧版逐条一致：邮箱格式错、超长密码一律按「邮箱或密码错误」回 401——
// 客户端把它们当凭据类处理，细分原因等于给爆破递进度条。
func (s *Service) checkPassword(rawEmail, password string) (int64, int, error) {
	email := normalizeEmail(rawEmail)
	if err := validateEmail(email); err != nil {
		return 0, 0, unauthorized("邮箱或密码错误")
	}
	// 超长密码直接判失败：bcrypt 对超 72 字节的输入会返回错误，别让它变成 500
	if len(password) > maxPasswordB {
		return 0, 0, unauthorized("邮箱或密码错误")
	}
	var (
		id      int64
		hashed  sql.NullString
		version int
	)
	err := s.pool.QueryRowContext(context.Background(),
		"SELECT id, password_hash, token_version FROM users WHERE email = ?", email).
		Scan(&id, &hashed, &version)
	if errors.Is(err, sql.ErrNoRows) {
		// **计时侧信道**：邮箱不存在的分支也要烧一次等价的 cost12 bcrypt，
		// 把响应延迟拉平到与「密码错」一致，否则可枚举注册过的邮箱
		_ = bcrypt.CompareHashAndPassword([]byte(dummyPasswordHash), []byte(password))
		return 0, 0, unauthorized("邮箱或密码错误")
	}
	if err != nil {
		return 0, 0, fmt.Errorf("查用户: %w", err)
	}
	// password_hash 为 NULL（纯验证码账号形态）时也烧一次等价的 cost12 bcrypt：
	// 这类账号没有可比对的散列，跳过比对会让「存在但无密码」的响应比「密码错」
	// 快几百毫秒，把无密码账号的存在性漏出去（与「邮箱不存在」分支同款防护）。
	if !hashed.Valid {
		_ = bcrypt.CompareHashAndPassword([]byte(dummyPasswordHash), []byte(password))
		return 0, 0, unauthorized("邮箱或密码错误")
	}
	if !verify(password, hashed.String) {
		return 0, 0, unauthorized("邮箱或密码错误")
	}
	return id, version, nil
}

// SendCode 发送「注册 / 找回密码 / 登录」验证码。purpose 走白名单。
//
// app 可选：给了就决定这封验证码邮件的品牌（空 = 中性品牌 Auth，留给将来的 web
// 账号台），未知值 400——与登录等端点同口径，老客户端不传照常工作。
//
// **不额外做防枚举是有意的**：注册侧本就对所有请求回「该邮箱已注册」（既有行为），
// 同一信息在找回侧保持沉默换不来任何防护，只换来「等 60 秒却收不到信」的困惑。
func (s *Service) SendCode(rawEmail, purpose, app string) error {
	// app 是客户端 bug 的第一现场，先于邮箱/用途校验回 400（与 Login 的顺序一致）
	if app != "" {
		if err := validateApp(app); err != nil {
			return err
		}
	}
	email := normalizeEmail(rawEmail)
	if err := validateEmail(email); err != nil {
		return err
	}
	if purpose != PurposeRegister && purpose != PurposeReset && purpose != PurposeLogin {
		return badRequest("参数不正确")
	}
	if s.mailer == nil {
		return &HTTPError{503, "邮件服务暂不可用，请稍后重试"}
	}

	exists, err := s.userExists(email)
	if err != nil {
		return err
	}
	if purpose == PurposeRegister && exists {
		return badRequest("该邮箱已注册，请直接登录")
	}
	if purpose == PurposeReset && !exists {
		return badRequest("该邮箱尚未注册")
	}
	if purpose == PurposeLogin && !exists {
		return badRequest("邮箱未注册，请先注册")
	}
	action := "注册"
	switch purpose {
	case PurposeReset:
		action = "找回密码"
	case PurposeLogin:
		action = "登录"
	}
	return s.sendOTP(purpose, email, action, app)
}

// sendOTP 公共发码尾段：占坑（issue，冷却与日限额在**发信之前**就挡）→ 投信 →
// 信没发出去回滚。注册 / 找回密码 / 修改密码三条发码路共用；app 只用来选邮件品牌。
func (s *Service) sendOTP(purpose, email, action, app string) error {
	if s.mailer == nil {
		return &HTTPError{503, "邮件服务暂不可用，请稍后重试"}
	}
	code, err := s.otps.issue(purpose, email)
	if err != nil {
		return err
	}
	b := brandFor(app)
	subject, html := codeEmail(b, action, code)
	// 不接请求 ctx：发送器自带 15s 超时（含取 token 一次往返），不会把 handler 拖成悬挂
	if err := s.mailer.Send(context.Background(), b.name, email, subject, html); err != nil {
		// 码已生成但信没发出去：撤销，否则用户要白等 60 秒冷却
		s.otps.revoke(purpose, email)
		mailLog(err, purpose, email)
		return &HTTPError{503, "验证码发送失败，请稍后重试"}
	}
	return nil
}

// SendChangeCode 给**登录用户绑定的邮箱**发「修改密码」验证码。
// 收件人只能来自 uid 查库——不像无登录态的 SendCode 收客户端传入的邮箱，
// 改密码码发错人等于把改密权交给收件人列表。
func (s *Service) SendChangeCode(c Caller) error {
	email, _, err := s.loadUserAuth(c.UID)
	if err != nil {
		return err
	}
	return s.sendOTP(PurposeChange, email, "修改密码", c.App)
}

// SendChangeEmailCode 给**新**邮箱发「修改邮箱」验证码。收件人是客户端传入的新邮箱，
// 所以四道闸：登录态（路由 authed）、按 uid 限流（路由）、格式/查重/同邮箱（这里）、
// 发码冷却与日限（otp store）。查重放在投信之前：拿一个已被占用的邮箱先烧一封信、
// 走完整个流程最后一步才报错更糟。品牌取自现会话的 app（改绑通知同源）。
func (s *Service) SendChangeEmailCode(c Caller, rawEmail string) error {
	current, _, err := s.loadUserAuth(c.UID)
	if err != nil {
		return err
	}
	email := normalizeEmail(rawEmail)
	if err := validateEmail(email); err != nil {
		return err
	}
	if email == current {
		return badRequest("新邮箱与当前邮箱相同")
	}
	exists, err := s.userExists(email)
	if err != nil {
		return err
	}
	if exists {
		return badRequest("该邮箱已被其他账号使用")
	}
	return s.sendOTP(PurposeChangeEmail, email, "修改邮箱", c.App)
}

// LoginByEmailCode 用邮箱验证码登录：与 Login 同款成功响应（token + email）。
//
// purpose 进 key，注册/找回/登录三种码互不串用——拿注册码来这里登录会得到
// 「验证码已过期」。**未注册先于验码返回**：没发过码的邮箱若先验码只会回
// 「验证码已过期」，那不是可执行的下一步，「邮箱未注册，请先注册」才是。
// 免密登录，与 Login 同语义：只签发、不动 token_version（不吊销其它会话）。
func (s *Service) LoginByEmailCode(rawEmail, code, app string, meta SessionMeta) (resp *Response, err error) {
	var uid int64
	defer func() {
		s.Audit(AuditEvent{
			Action: AuditLogin, OK: err == nil, ActorUID: uidPtr(uid),
			ActorEmail: maskEmail(normalizeEmail(rawEmail)), Meta: meta,
			Detail: map[string]string{"method": "email_code", "app": app},
		})
	}()
	if err := validateApp(app); err != nil {
		return nil, err
	}
	uid, version, email, err := s.checkLoginCode(rawEmail, code)
	if err != nil {
		return nil, err
	}
	sid, err := s.createSession(uid, app, meta)
	if err != nil {
		return nil, err
	}
	tok, err := s.createToken(uid, email, app, version, sid)
	if err != nil {
		return nil, err
	}
	return &Response{Token: tok, Email: email}, nil
}

// checkLoginCode 校验「登录」用途的邮箱验证码，回 uid / token_version / 归一化邮箱。
// **JWT 路（LoginByEmailCode）与 web 邮箱验证码登录共用**：报错顺序（格式 → 未注册 →
// 验码）与文案只此一份，两条路不会漂。
func (s *Service) checkLoginCode(rawEmail, code string) (int64, int, string, error) {
	email := normalizeEmail(rawEmail)
	if err := validateEmail(email); err != nil {
		return 0, 0, "", err
	}
	var (
		id      int64
		version int
	)
	err := s.pool.QueryRowContext(context.Background(),
		"SELECT id, token_version FROM users WHERE email = ?", email).Scan(&id, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, "", badRequest("邮箱未注册，请先注册")
	}
	if err != nil {
		return 0, 0, "", fmt.Errorf("查用户: %w", err)
	}
	if err := s.otps.verify(PurposeLogin, email, code); err != nil {
		return 0, 0, "", err
	}
	return id, version, email, nil
}

// ResetPassword 用验证码重置密码：校验通过即改 hash 并 **token_version+1**——
// 该账号全部已签发 token 当场失效（与改密/注销同一套吊销机制），不签发新 token，
// 让用户拿新密码回登录页登录。
func (s *Service) ResetPassword(rawEmail, code, newPassword string) error {
	email := normalizeEmail(rawEmail)
	if err := validateEmail(email); err != nil {
		return err
	}
	if err := validatePassword(newPassword); err != nil {
		return err
	}
	var uid int64
	err := s.pool.QueryRowContext(context.Background(),
		"SELECT id FROM users WHERE email = ?", email).Scan(&uid)
	if errors.Is(err, sql.ErrNoRows) {
		return badRequest("该邮箱尚未注册")
	}
	if err != nil {
		return fmt.Errorf("查用户: %w", err)
	}
	if err := s.otps.verify(PurposeReset, email, code); err != nil {
		return err
	}
	newHash, err := hash(newPassword)
	if err != nil {
		return err
	}
	return s.setPasswordAndRevoke(uid, newHash, 0)
}

// Logout 递增 token_version——**这是 token 层吊销的唯一机制**：所有已签发 token 的
// ver 都对不上了。同时把该用户全部会话行置 revoked_at：两层必须同进同退，
// 否则设备列表里留下的是一批「token 早死了、行还活着」的活死行，用户踢也踢不掉。
// 两个动作放一个事务——只成一半（token 死了行还挂着）就是上面那种半吊子状态。
func (s *Service) Logout(userID int64) error {
	ctx := context.Background()
	tx, err := s.pool.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		"UPDATE users SET token_version = token_version + 1 WHERE id = ?", userID); err != nil {
		return fmt.Errorf("吊销 token: %w", err)
	}
	if err := revokeUserSessions(ctx, tx, userID, 0); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交登出: %w", err)
	}
	return nil
}

// loadUserAuth 取改密族都要的两样：绑定邮箱（改密码码按它存取）与现口令散列
//（原密码比对用；验码路径不用）。uid 已过期（账号被删）按未授权处理。
func (s *Service) loadUserAuth(userID int64) (email, hashed string, err error) {
	var h sql.NullString
	err = s.pool.QueryRowContext(context.Background(),
		"SELECT email, password_hash FROM users WHERE id = ?", userID).Scan(&email, &h)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", unauthorized("登录已过期，请重新登录")
	}
	if err != nil {
		return "", "", fmt.Errorf("查用户: %w", err)
	}
	return email, h.String, nil
}

// setPasswordAndRevoke 写入新口令散列并 **token_version+1**：吊销该账号全部已签发 token
//（与 Logout/注销同一套机制）。改密的三条路——原密码、验证码、找回密码——共用这一处，
// 「改密必吊销」不会在某条路上漏掉。
//
// 同一事务里把全部会话行也置 revoked_at：token 层判死的那批设备，会话行若留着，
// 设备列表就是一列没有 token 的活死行（找回密码最明显——用户重登拿到新会话，
// 旧行永远挂着没人踢得掉）。换发的新会话由 reissueToken 另建（找回密码没有换发）。
// keepSID > 0 时该行保活：web 会话改密走这条（cookie 不换发，续用当前行）。
func (s *Service) setPasswordAndRevoke(userID int64, newHash string, keepSID int64) error {
	ctx := context.Background()
	tx, err := s.pool.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		"UPDATE users SET password_hash = ?, token_version = token_version + 1 WHERE id = ?",
		newHash, userID); err != nil {
		return fmt.Errorf("改密: %w", err)
	}
	if err := revokeUserSessions(ctx, tx, userID, keepSID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交改密: %w", err)
	}
	return nil
}

// reissueToken 读吊销后的新版本号并换发 token：当前设备拿它无缝续用，
// 其他设备的旧 ver 已对不上（被登出的只会是它们）。aud 沿用调用方现会话的 app。
//
// **web 会话（app='web'）不换发**：cookie 值即会话凭据本身，当前行已由
// setPasswordAndRevoke 的 keepSID 保活，cookie 继续有效；给它签 JWT 毫无意义
//（aud='web' 不在白名单，签出来就是一枚谁也不认的死 token）。回体形状保持
// {token,email}，token 恒空串——凭据只在 cookie 里。
//
// 邮箱从**库**取而不是沿用 token claim：改绑邮箱不 bump token_version，走到这里的
// token 其 email claim 可能还是旧值——把旧邮箱签回新 token，会让「验证码收与验
// 同源」在下一轮改密时再次断开（改绑后验证码改密失败的另一半就在这里）。
//
// 旧会话行已由 setPasswordAndRevoke 同批吊销（token 层与会话层一起走），
// 这里只给本设备建一行新会话，换发的 token 绑它。
func (s *Service) reissueToken(c Caller) (*Response, error) {
	var next int
	var email string
	if err := s.pool.QueryRowContext(context.Background(),
		"SELECT token_version, email FROM users WHERE id = ?", c.UID).Scan(&next, &email); err != nil {
		return nil, fmt.Errorf("读新版本号: %w", err)
	}
	if c.App == webAppLabel {
		return &Response{Token: "", Email: email}, nil
	}
	sid, err := s.createSession(c.UID, c.App, c.Meta)
	if err != nil {
		return nil, err
	}
	tok, err := s.createToken(c.UID, email, c.App, next, sid)
	if err != nil {
		return nil, err
	}
	return &Response{Token: tok, Email: email}, nil
}

// changeKeepSID 是改密时**保活**的会话行 id：web 会话保当前行（cookie 不换发，
// 续用；不留 app='web' 无 web_token_hash 的僵尸行）；App 会话回 0 = 全吊销后
// 由 reissueToken 另建新行换新 JWT。
func changeKeepSID(c Caller) int64 {
	if c.App == webAppLabel {
		return c.SID
	}
	return 0
}

// ChangePassword 校验旧密码、改密并**顺带吊销**（版本 +1），返回新 token 让当前设备继续用。
// App 会话换发新 JWT；web 会话不换发（token 恒空串、当前行保活，凭据只在 cookie，见 reissueToken）。
func (s *Service) ChangePassword(c Caller, oldPassword, newPassword string) (resp *Response, err error) {
	// 改密是安全敏感操作：成败必记（ASVS V16.3）。detail 不带任何口令字段。
	defer func() {
		s.Audit(AuditEvent{
			Action: AuditPasswordChange, OK: err == nil, ActorUID: uidPtr(c.UID),
			ActorEmail: maskEmail(c.Email), Meta: c.Meta,
		})
	}()
	if err := validatePassword(newPassword); err != nil {
		return nil, err
	}
	if len(oldPassword) > maxPasswordB {
		return nil, badRequest("原密码不正确")
	}
	_, hashed, err := s.loadUserAuth(c.UID)
	if err != nil {
		return nil, err
	}
	if !verify(oldPassword, hashed) {
		return nil, badRequest("原密码不正确")
	}
	newHash, err := hash(newPassword)
	if err != nil {
		return nil, err
	}
	// web 会话保活当前行、App 会话全吊销后换发（见 changeKeepSID / reissueToken）
	if err := s.setPasswordAndRevoke(c.UID, newHash, changeKeepSID(c)); err != nil {
		return nil, err
	}
	return s.reissueToken(c)
}

// ChangePasswordByCode 改密码的验证码版：码经 [SendChangeCode] 发进**账号当前绑定的
// 邮箱**，验证通过即改密并 token_version+1 吊销其他设备；当前设备拿返回的新 token
// 无缝续用（与 ChangePassword 同一契约）。
// 强度校验放在验码之前：先拒弱密码、不白烧一次码的试错次数。
func (s *Service) ChangePasswordByCode(c Caller, code, newPassword string) (resp *Response, err error) {
	defer func() {
		s.Audit(AuditEvent{
			Action: AuditPasswordChange, OK: err == nil, ActorUID: uidPtr(c.UID),
			ActorEmail: maskEmail(c.Email), Meta: c.Meta,
			Detail: map[string]string{"method": "code"},
		})
	}()
	if err := validatePassword(newPassword); err != nil {
		return nil, err
	}
	// 收与验都锚定 **uid 查库的当前邮箱**，不用 token claim：改绑邮箱不 bump
	// token_version，token 里的 email 停留旧值，而 SendChangeCode 的码是发进库里
	// 当前邮箱的——按 claim 验码会把「新邮箱收到的码」恒判成「验证码已过期」。
	email, _, err := s.loadUserAuth(c.UID)
	if err != nil {
		return nil, err
	}
	if err := s.otps.verify(PurposeChange, email, code); err != nil {
		return nil, err
	}
	newHash, err := hash(newPassword)
	if err != nil {
		return nil, err
	}
	if err := s.setPasswordAndRevoke(c.UID, newHash, changeKeepSID(c)); err != nil {
		return nil, err
	}
	return s.reissueToken(c)
}

// ChangeEmail 改绑邮箱：当前密码重验 → 新邮箱验证码 → 更新 users.email →
// 新旧邮箱各发一封通知信。报错顺序：邮箱格式 → 与当前相同 → 已被占用 → 密码 →
// 验证码——把有 5 次试错上限的验证码排在最后，别让一次手滑的密码错烧掉码的试错次数。
//
// **不 bump token_version**：改邮箱不是凭证变更，现会话保持登录（与改密相反）。
// 通知信失败只记日志——信没发出去不该把已经完成的改绑回滚成 500。
// 码信与两封通知信的品牌都取现会话的 app（见 brandFor），三封信同源不漂。
func (s *Service) ChangeEmail(c Caller, password, rawEmail, code string) (err error) {
	defer func() {
		// 改绑前后两个邮箱都在事件里（都掩码）：用户要能认出「哪次改绑发给了谁」
		s.Audit(AuditEvent{
			Action: AuditEmailChange, OK: err == nil, ActorUID: uidPtr(c.UID),
			ActorEmail: maskEmail(c.Email), Meta: c.Meta,
			Detail: map[string]string{"newEmail": maskEmail(normalizeEmail(rawEmail))},
		})
	}()
	email := normalizeEmail(rawEmail)
	if err := validateEmail(email); err != nil {
		return err
	}
	current, hashed, err := s.loadUserAuth(c.UID)
	if err != nil {
		return err
	}
	if email == current {
		return badRequest("新邮箱与当前邮箱相同")
	}
	exists, err := s.userExists(email)
	if err != nil {
		return err
	}
	if exists {
		return badRequest("该邮箱已被其他账号使用")
	}
	if len(password) > maxPasswordB {
		return badRequest("原密码不正确")
	}
	if !verify(password, hashed) {
		return badRequest("原密码不正确")
	}
	if err := s.otps.verify(PurposeChangeEmail, email, code); err != nil {
		return err
	}
	if _, err := s.pool.ExecContext(context.Background(),
		"UPDATE users SET email = ? WHERE id = ?", email, c.UID); err != nil {
		// 并发下另一个账号先占了这个邮箱：uq_users_email 挡住，翻译成同一句人话
		var me *mysql.MySQLError
		if errors.As(err, &me) && me.Number == 1062 {
			return badRequest("该邮箱已被其他账号使用")
		}
		return fmt.Errorf("改绑邮箱: %w", err)
	}
	s.notifyEmailChanged(c.App, current, email)
	return nil
}

// notifyEmailChanged 改绑后的两封通知信（旧、新邮箱各一封）：只报事实与「非本人怎么办」。
// 失败只记日志（邮箱脱敏）——通知是附带动作，不参与改绑成败。品牌由 app 现取
// （与同批的改密码码信同源）。
func (s *Service) notifyEmailChanged(app, oldEmail, newEmail string) {
	if s.mailer == nil {
		return
	}
	b := brandFor(app)
	for _, to := range []struct {
		addr  string
		toNew bool
	}{{oldEmail, false}, {newEmail, true}} {
		subject, body := changeEmailNoticeEmail(b, to.toNew, oldEmail, newEmail)
		if err := s.mailer.Send(context.Background(), b.name, to.addr, subject, body); err != nil {
			mailLog(err, "email_change_notice", to.addr)
		}
	}
}

// DeleteAccount 注销：先让两个日记服务清掉各自的业务数据，再删本服务持有的数据
// （账号行 + 验证码行）。
//
// **顺序不能反**：auth 侧的行删了，日记侧按 uid 关联的业务数据就成了查无账号的孤儿，
// 而且没有任何东西会再去清它们。所以钩子全成功才开本服务的事务；任一钩子失败整个
// 注销中止、auth 行一字不动（用户稍后重试即可）。钩子的配置与调用细节见 [Hooks]。
// 账号服务仍然不连别的库——跨库删数据是权限与耦合的双重坏味道，清理由 HTTP 钩子完成。
func (s *Service) DeleteAccount(userID int64, password string) error {
	if len(password) > maxPasswordB {
		return badRequest("密码不正确")
	}
	var email string
	var hashed sql.NullString
	err := s.pool.QueryRowContext(context.Background(),
		"SELECT email, password_hash FROM users WHERE id = ?", userID).Scan(&email, &hashed)
	if errors.Is(err, sql.ErrNoRows) {
		return unauthorized("登录已过期，请重新登录")
	}
	if err != nil {
		return fmt.Errorf("查用户: %w", err)
	}
	if !hashed.Valid || !verify(password, hashed.String) {
		return badRequest("密码不正确")
	}

	// 钩子排在密码校验之后：密码写错时**一个钩子都不该打**——否则随手一次输错密码
	// 就把用户在两个日记里的数据清了，而账号还在。
	if s.hooks != nil {
		if err := s.hooks.BeforeDelete(userID, email); err != nil {
			return err
		}
	}

	tx, err := s.pool.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("开事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// 验证码行按邮箱清：账号没了还留着验证码记录，既是隐私残留，
	// 也拦不住同邮箱重新注册后被旧计数误伤
	if _, err := tx.ExecContext(context.Background(),
		"DELETE FROM otp_codes WHERE email = ?", email); err != nil {
		return fmt.Errorf("清空验证码记录: %w", err)
	}
	// 会话行按 uid 清：账号都删了，设备列表的行只剩隐私残留，没人再踢得掉它们
	if _, err := tx.ExecContext(context.Background(),
		"DELETE FROM sessions WHERE user_id = ?", userID); err != nil {
		return fmt.Errorf("清空登录会话: %w", err)
	}
	// Web 管理台的四张按 uid 存行的表同批清（passkey / TOTP / 恢复码 / 仪式中间态），
	// 外加两步登录的中间态——它们是 5 分钟的在途凭证，账号没了还挂着就是一张废票。
	// user_profile 也在列：档案归身份提供方，账号删了还留着昵称/头像就是隐私残留
	//（日记侧的对应资料行由注销钩子清，本服务这行只能在这里删）。
	for _, table := range []string{"passkeys", "totp_factors", "recovery_codes", "webauthn_challenges", "login_states", "user_profile"} {
		if _, err := tx.ExecContext(context.Background(),
			"DELETE FROM "+table+" WHERE user_id = ?", userID); err != nil {
			return fmt.Errorf("清空 %s: %w", table, err)
		}
	}
	// 审计行**留着但匿名化**：删掉它等于给「注销自己账号就能抹掉操作痕迹」开后门，
	// 事件本身要继续对得起 ASVS V16；邮箱清空后行里只剩 uid，账号已不存在。
	if _, err := tx.ExecContext(context.Background(),
		"UPDATE audit_logs SET actor_email = '' WHERE actor_uid = ?", userID); err != nil {
		return fmt.Errorf("匿名化审计: %w", err)
	}
	if _, err := tx.ExecContext(context.Background(),
		"DELETE FROM users WHERE id = ?", userID); err != nil {
		return fmt.Errorf("删除账号: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交注销: %w", err)
	}
	slog.Info("账号已注销", "uid", userID, "email", maskEmail(email))
	return nil
}

// sha256Hex 是验证码的落库形态：库里不存明文码。
func sha256Hex(code string) string {
	sum := sha256.Sum256([]byte(code))
	return fmt.Sprintf("%x", sum)
}
