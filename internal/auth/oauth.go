package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OAuth 跳转授权（授权码 + PKCE，RFC 9700 业界序列）：
//
//	先校验参数 → 未登录托管登录页且原事务续跑 → 已登录轻确认 → 发码回跳 →
//	应用后端拿 code+secret 换 JWT（aud=app，与 /auth/login 同一种 token）。
//
// 授权码与授权事务都是**进程内内存态**（单实例部署假设，与 cmd/server 的滑动
// 限流同口径）：code 60 秒单次、tx 10 分钟单次；客户端登记（oauth_clients）落库。
// 分层口径同全仓：业务判定在本文件（可单测），HTTP 形状在 cmd/server/oauth.go。

const (
	// oauthCodeTTL 是授权码寿命：60 秒——业界 30s~10m 的中位，够应用后端往返，
	// 又把泄露窗口压到最小。
	oauthCodeTTL = 60 * time.Second
	// oauthTxTTL 是「参数已验、等用户登录/确认」的授权事务寿命：10 分钟。
	oauthTxTTL = 10 * time.Minute
	// oauthStoreMax 是两个内存 map 的惰性清扫阈值：超过才扫过期键（与限流器同款）。
	oauthStoreMax = 512
	// oauthClientIDBytes / oauthSecretBytes：client_id 16 位、secret 32 位（base64url）。
	oauthClientIDBytes = 12
	oauthSecretBytes   = 24
	// maxOAuthRedirectURIs / maxOAuthRedirectLen：登记面的上限（防 TEXT 列被当便签）。
	maxOAuthRedirectURIs = 10
	maxOAuthRedirectLen  = 2048
	// pkceMinLen / pkceMaxLen：RFC 7636 规定 verifier/challenge 43~128 字符。
	pkceMinLen = 43
	pkceMaxLen = 128
)

// OAuthAuthorizeRequest 是 GET /oauth/authorize 的原始查询参数（业务层只认这六个）。
type OAuthAuthorizeRequest struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// OAuthBeginAuthorize 是授权第一步的 fail-fast 校验（顺序钉死：response_type →
// state → PKCE → client 登记 → redirect 精确匹配），过了就落一条授权事务并回 tx。
// 错误一律 400 + 中文可执行文案；redirect 不匹配**不回显**请求里的完整地址
//（可能是恶意构造，回显等于给钓鱼页面当镜子）。
func (s *Service) OAuthBeginAuthorize(req OAuthAuthorizeRequest) (tx string, app string, err error) {
	if req.ResponseType != "code" {
		return "", "", badRequest("只支持 response_type=code 的授权请求，请让应用使用授权码模式")
	}
	if strings.TrimSpace(req.State) == "" {
		return "", "", badRequest("授权请求缺少 state 参数，请让应用补齐后重试")
	}
	challenge := strings.TrimSpace(req.CodeChallenge)
	if strings.TrimSpace(req.CodeChallengeMethod) != "S256" || challenge == "" {
		return "", "", badRequest("授权请求必须带 code_challenge（仅支持 S256），请让应用补齐 PKCE 后重试")
	}
	if !pkceValueOK(challenge) {
		return "", "", badRequest("授权请求的 code_challenge 格式不正确（应为 43~128 位 base64url）")
	}
	client, err := s.oauthClientByClientID(req.ClientID)
	if err != nil {
		return "", "", err
	}
	if !oauthRedirectAllowed(client.RedirectURIs, req.RedirectURI) {
		return "", "", badRequest("回跳地址未登记，请联系应用管理员在控制台登记后重试")
	}
	tx, err = randomToken(webTokenBytes)
	if err != nil {
		return "", "", err
	}
	s.oauthStore.putTx(tx, &oauthTx{
		ClientID: client.ClientID, App: client.App,
		RedirectURI: req.RedirectURI, State: req.State, Challenge: challenge,
	})
	return tx, client.App, nil
}

// OAuthView 是授权确认页（authorize.html）的渲染上下文：App/回跳域名取自
// 已验参数，Email 是当前登录账号。Error* 非空 = 同模板的错误页变体。
type OAuthView struct {
	Tx           string
	App          string
	AppName      string
	RedirectHost string
	Email        string
	ErrorTitle   string
	ErrorMessage string
}

// OAuthAuthorizeView 展开一条授权事务并渲染确认页：tx 必须活着，把它**绑定到当前
// 登录 uid**（谁确认就发谁的码），顺带过一遍 deny 复查（封禁 → 项目白名单，
// 文案逐字来自 gate.go）。未登录（uid=0）回 401 让路由层去托管登录。
func (s *Service) OAuthAuthorizeView(tx string, uid int64) (*OAuthView, error) {
	if strings.TrimSpace(tx) == "" {
		return nil, badRequest("登录请求已过期，请重新发起授权")
	}
	s.oauthStore.sweep()
	e := s.oauthStore.tx(tx)
	if e == nil {
		return nil, badRequest("登录请求已过期，请重新发起授权")
	}
	if uid <= 0 {
		return nil, unauthorized("请先登录")
	}
	if err := s.denyReason(uid, e.App); err != nil {
		return nil, err
	}
	// 绑定当前 uid（锁内写：map 值被并发 resume/confirm 读，裸改是数据竞争）
	s.oauthStore.bindTx(tx, uid)
	var email string
	if err := s.pool.QueryRowContext(context.Background(),
		"SELECT email FROM users WHERE id = ?", uid).Scan(&email); err != nil {
		return nil, unauthorized("登录已过期，请重新登录")
	}
	host := ""
	if u, uerr := url.Parse(e.RedirectURI); uerr == nil {
		host = u.Host
	}
	return &OAuthView{
		Tx: tx, App: e.App, AppName: appName(e.App),
		RedirectHost: host, Email: email,
	}, nil
}

// OAuthDecide 执行确认页的决定：allow → 发授权码、deny → access_denied 回跳。
// 两者都消耗 tx（单次）；tx 必须已绑定到本 uid（防登录甲确认乙的事务）。
// deny 复查在这里再过一次（确认期间被封禁的窗口）。回执是完整的回跳 URL，
// 302 是传输层的事。
func (s *Service) OAuthDecide(uid int64, tx, decision string, meta SessionMeta) (string, error) {
	e := s.oauthStore.takeTx(tx)
	if e == nil || e.UID != uid || uid <= 0 {
		return "", badRequest("登录请求已过期，请重新发起授权")
	}
	if err := s.denyReason(uid, e.App); err != nil {
		return "", err
	}
	if decision != "allow" {
		return buildOAuthRedirect(e.RedirectURI, url.Values{"error": {"access_denied"}, "state": {e.State}})
	}
	var email string
	if err := s.pool.QueryRowContext(context.Background(),
		"SELECT email FROM users WHERE id = ?", uid).Scan(&email); err != nil {
		return "", unauthorized("登录已过期，请重新登录")
	}
	code, err := randomToken(webTokenBytes)
	if err != nil {
		return "", err
	}
	s.oauthStore.putCode(code, &oauthCode{
		UID: uid, App: e.App, RedirectURI: e.RedirectURI,
		ClientID: e.ClientID, Challenge: e.Challenge,
		IP: meta.IP, UA: meta.UserAgent, Exp: time.Now().Add(oauthCodeTTL),
	})
	return buildOAuthRedirect(e.RedirectURI, url.Values{"code": {code}, "state": {e.State}})
}

// OAuthTokenRequest 是 POST /oauth/token 的请求体（RFC 6749 §4.1.3 + PKCE）。
type OAuthTokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	CodeVerifier string `json:"code_verifier"`
}

// OAuthTokenResult 是换码成功的回执（§5.1 精简子集）。
// ExpiresIn 是 tokenTTL 的真实秒数——回一个与 JWT exp 对不上的数是给集成方挖坑。
type OAuthTokenResult struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	UID         int64  `json:"uid"`
	Email       string `json:"email"`
}

// OAuthError 是 OAuth 端点的结构化失败（RFC 6749 §5.2 形状 {error,error_description}）。
// Status 是 HTTP 状态码；Code 是机器可读错误名，Description 是给集成方排障的中文。
type OAuthError struct {
	Status      int
	Code        string
	Description string
}

func (e *OAuthError) Error() string { return e.Code + ": " + e.Description }

func oauthErr(status int, code, desc string) error {
	return &OAuthError{Status: status, Code: code, Description: desc}
}

// OAuthExchangeToken 是换码端点的业务编排。校验顺序钉死（B4 契约）：
//
//	client_id+secret（sha256 恒时比对）→ code 取出即失效（单次，含过期/复用）→
//	redirect_uri/client_id 与 code 记录逐字一致 → S256(verifier)==challenge →
//	deny 复查（封禁/白名单在发 token 前兜底）→ 复用 App 流程发 token+session。
//
// 会话的设备名/UA/IP 用**浏览器确认那一刻**存下的现场（token 请求来自应用后端，
// 拿它的 UA/IP 会把设备列表写成一排 server-agent）。
func (s *Service) OAuthExchangeToken(req OAuthTokenRequest) (*OAuthTokenResult, error) {
	if req.GrantType != "authorization_code" {
		return nil, oauthErr(400, "unsupported_grant_type", "只支持 authorization_code 授权码换 token")
	}
	client, err := s.oauthClientByClientID(req.ClientID)
	if err != nil {
		// 「未登记 / 空 secret_hash / secret 不对」都是 invalid_client；DB 抖动
		// 原样上抛（路由层归 server_error）——把抖动报成凭据错会误导调用方
		var he *HTTPError
		if errors.As(err, &he) && he.Code == 400 {
			return nil, oauthErr(401, "invalid_client", "client_id 或 client_secret 不正确")
		}
		return nil, err
	}
	if client.SecretHash == "" || !oauthSecretMatches(client.SecretHash, req.ClientSecret) {
		return nil, oauthErr(401, "invalid_client", "client_id 或 client_secret 不正确")
	}
	code := s.oauthStore.takeCode(req.Code)
	if code == nil {
		return nil, oauthErr(400, "expired_token", "授权码已过期或已被使用，请重新发起授权")
	}
	if code.ClientID != client.ClientID || code.RedirectURI != req.RedirectURI {
		return nil, oauthErr(400, "invalid_grant", "授权码与 client_id / redirect_uri 不匹配")
	}
	if !pkceValueOK(req.CodeVerifier) || pkceS256(req.CodeVerifier) != code.Challenge {
		return nil, oauthErr(400, "invalid_grant", "PKCE 校验失败（code_verifier 与授权请求不匹配）")
	}
	if err := s.denyReason(code.UID, code.App); err != nil {
		var he *HTTPError
		// 只有 403（封禁/白名单）翻成 access_denied；503（DB 抖动）原样上抛，
		// 由路由层归成 server_error——把抖动报成 access_denied 会误导调用方重试姿势
		if errors.As(err, &he) && he.Code == 403 {
			return nil, oauthErr(403, "access_denied", he.Message)
		}
		return nil, err
	}
	var email string
	if err := s.pool.QueryRowContext(context.Background(),
		"SELECT email FROM users WHERE id = ?", code.UID).Scan(&email); err != nil {
		return nil, oauthErr(400, "invalid_grant", "授权账号已不可用，请重新发起授权")
	}
	// 与 App 流程的 completeLogin 同款落行：业务会话 + aud=app 的 90 天 JWT，
	// UA/IP 用浏览器那一刻的现场。
	sid, err := s.createSession(code.UID, code.App, SessionMeta{IP: code.IP, UserAgent: code.UA})
	if err != nil {
		return nil, err
	}
	ver, err := s.tokenVersion(code.UID)
	if err != nil {
		return nil, err
	}
	token, err := s.createToken(code.UID, email, code.App, ver, sid)
	if err != nil {
		return nil, err
	}
	_ = s.MarkReauth(sid)
	// 新设备登录提醒（W1）：OAuth 兑换同样建会话，接同一收口（best-effort）
	s.notifyNewLoginDevice(code.UID, sid, email, code.App, SessionMeta{IP: code.IP, UserAgent: code.UA})
	s.Audit(AuditEvent{
		Action: AuditLogin, OK: true, ActorUID: uidPtr(code.UID), ActorEmail: email,
		Meta:   SessionMeta{IP: code.IP, UserAgent: code.UA},
		Detail: map[string]string{"method": "oauth", "app": code.App},
	})
	return &OAuthTokenResult{
		AccessToken: token, TokenType: "Bearer",
		ExpiresIn: int(tokenTTL.Seconds()), UID: code.UID, Email: email,
	}, nil
}

// OAuthDenyCheck 是路由层在确认/续跑前调的 deny 复查（封禁 → 项目白名单），
// 文案逐字来自 denyReason；这里只是把非导出判定开一个受控窗口。
func (s *Service) OAuthDenyCheck(uid int64, app string) error { return s.denyReason(uid, app) }

// OAuthClientRow 是 oauth_clients 一行的读出形态（SecretHash 不进任何回执）。
type OAuthClientRow struct {
	App          string
	ClientID     string
	SecretHash   string
	RedirectURIs []string
}

// oauthClientByClientID 查 client_id 对应的登记行。查无回 400「应用未登记」——
// 不给「这个 client_id 存不存在」以外的存在性信息。
func (s *Service) oauthClientByClientID(clientID string) (*OAuthClientRow, error) {
	if strings.TrimSpace(clientID) == "" {
		return nil, badRequest("应用未登记，请联系应用管理员在控制台开通后再试")
	}
	var (
		row    OAuthClientRow
		rawURI string
	)
	err := s.pool.QueryRowContext(context.Background(),
		"SELECT app, client_id, secret_hash, redirect_uris FROM oauth_clients WHERE client_id = ?", clientID).
		Scan(&row.App, &row.ClientID, &row.SecretHash, &rawURI)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, badRequest("应用未登记，请联系应用管理员在控制台开通后再试")
	}
	if err != nil {
		return nil, fmt.Errorf("查 OAuth 客户端: %w", err)
	}
	if err := json.Unmarshal([]byte(rawURI), &row.RedirectURIs); err != nil {
		return nil, fmt.Errorf("解析回跳地址: %w", err)
	}
	return &row, nil
}

// AdminOAuthInput 是 POST /admin/projects/{app}/oauth 的入参。
type AdminOAuthInput struct {
	RedirectUris []string
	RotateSecret bool
}

// AdminOAuthResult 是管理端回执：secret 只在**新建或重置**那一刻非空（一次性）。
type AdminOAuthResult struct {
	App          string   `json:"app"`
	ClientID     string   `json:"clientId"`
	RedirectURIs []string `json:"redirectUris"`
	Secret       string   `json:"secret,omitempty"`
}

// AdminConfigureOAuth 开通 / 更新一个项目的 OAuth 客户端（首调自动建 client_id）：
// su 管全部项目、app-admin 只管 scopes 内项目（adminTargetScope）；redirect_uris
// 全量替换，逐条校验（绝对 http(s) URL、有 host、无 fragment、≤10 条）；
// rotateSecret=true 时换新 secret 并一次性回执，旧 secret 即刻失效。
// secret 只存 sha256；审计 admin.oauth_client.write（detail 不带 secret）。
func (s *Service) AdminConfigureOAuth(actor Caller, scope AdminScope, app string,
	in AdminOAuthInput) (res *AdminOAuthResult, err error) {
	defer func() {
		s.Audit(AuditEvent{
			Action: AuditOAuthClientWrite, OK: err == nil, ActorUID: uidPtr(actor.UID),
			ActorEmail: maskEmail(actor.Email), Meta: actor.Meta,
			Detail: map[string]string{"app": app, "rotateSecret": boolWord(in.RotateSecret)},
		})
	}()
	if !allowedApps[app] {
		return nil, badRequest("未知项目，请重新选择后重试")
	}
	if err = adminTargetScope(scope, app); err != nil {
		return nil, err
	}
	uris, err := validateOAuthRedirects(in.RedirectUris)
	if err != nil {
		return nil, err
	}
	uriJSON, err := json.Marshal(uris)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	var existing OAuthClientRow
	scanErr := s.pool.QueryRowContext(ctx,
		"SELECT client_id, secret_hash FROM oauth_clients WHERE app = ?", app).
		Scan(&existing.ClientID, &existing.SecretHash)
	switch {
	case errors.Is(scanErr, sql.ErrNoRows):
		clientID, cerr := randomToken(oauthClientIDBytes)
		if cerr != nil {
			return nil, cerr
		}
		secret, serr := randomToken(oauthSecretBytes)
		if serr != nil {
			return nil, serr
		}
		if _, err = s.pool.ExecContext(ctx,
			"INSERT INTO oauth_clients (app, client_id, secret_hash, redirect_uris, created_by, created_at)"+
				" VALUES (?,?,?,?,?,?)",
			app, clientID, sha256Hex(secret), uriJSON, actor.UID, time.Now().UnixMilli()); err != nil {
			return nil, fmt.Errorf("开通 OAuth 客户端: %w", err)
		}
		return &AdminOAuthResult{App: app, ClientID: clientID, RedirectURIs: uris, Secret: secret}, nil
	case scanErr != nil:
		return nil, fmt.Errorf("查 OAuth 客户端: %w", scanErr)
	}
	secret := ""
	newHash := existing.SecretHash
	if in.RotateSecret {
		if secret, err = randomToken(oauthSecretBytes); err != nil {
			return nil, err
		}
		newHash = sha256Hex(secret)
	}
	if _, err = s.pool.ExecContext(ctx,
		"UPDATE oauth_clients SET redirect_uris = ?, secret_hash = ? WHERE app = ?",
		uriJSON, newHash, app); err != nil {
		return nil, fmt.Errorf("更新 OAuth 客户端: %w", err)
	}
	return &AdminOAuthResult{App: app, ClientID: existing.ClientID, RedirectURIs: uris, Secret: secret}, nil
}

// OAuthClientIDFor 给 GET /admin/projects 回执补 clientId（空串=未开通，前端据此
// 渲染空态或已开通态）。
func (s *Service) OAuthClientIDFor(app string) (string, []string) {
	var (
		clientID string
		rawURIs  string
	)
	err := s.pool.QueryRowContext(context.Background(),
		"SELECT client_id, redirect_uris FROM oauth_clients WHERE app = ?", app).
		Scan(&clientID, &rawURIs)
	if err != nil {
		return "", nil
	}
	var uris []string
	_ = json.Unmarshal([]byte(rawURIs), &uris)
	return clientID, uris
}

// validateOAuthRedirects 校验并去重登记的回跳地址：≥1 条、≤10 条、每条是绝对
// http(s) URL（有 host、无 userinfo、无 fragment、长度 ≤2048）——精确串匹配
// （RFC 9700）意味着登记面就是全部防线，通配/前缀一律不支持也不允许。
func validateOAuthRedirects(raw []string) ([]string, error) {
	if len(raw) == 0 || len(raw) > maxOAuthRedirectURIs {
		return nil, badRequest("回跳地址需为 1~10 条，请检查后重试")
	}
	out := make([]string, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, item := range raw {
		u := strings.TrimSpace(item)
		if u == "" || len(u) > maxOAuthRedirectLen || seen[u] {
			continue
		}
		parsed, err := url.Parse(u)
		if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") ||
			parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return nil, badRequest("回跳地址必须是完整的 http(s) 地址（不含账号段与 #片段），请逐条检查后重试")
		}
		seen[u] = true
		out = append(out, u)
	}
	if len(out) == 0 {
		return nil, badRequest("回跳地址不能为空，请至少填写一条")
	}
	return out, nil
}

// buildOAuthRedirect 在**已登记**的回跳地址上追加 code/error 与 state 查询参数。
func buildOAuthRedirect(base string, params url.Values) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("解析回跳地址: %w", err)
	}
	q := u.Query()
	for k, vs := range params {
		for _, v := range vs {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// oauthRedirectAllowed 精确串匹配（RFC 9700）：登记表里有一字不差的条目才放行。
// 前缀/子域/带 query 的变体（`…/cb/../evil`、`sub.a.com`、`…/cb?x=1`）都天然被
// 逐字相等拒绝——这正是不做前缀/通配的全部意义。
func oauthRedirectAllowed(registered []string, got string) bool {
	return containsStr(registered, got)
}

// oauthSecretMatches 恒时比对 client_secret：两侧各自 sha256 后再 subtle 比
//（长度差被散列拉平，与 hook_token 同款口径）；空串登记（未签发过 secret）恒拒。
func oauthSecretMatches(storedHash, provided string) bool {
	if storedHash == "" || provided == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(storedHash), []byte(sha256Hex(provided))) == 1
}

// pkceS256 计算 S256 挑战：base64url(sha256(verifier))，无填充。
func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// pkceValueOK 判定 verifier/challenge 的格式：43~128 位 base64url 字符
//（RFC 7636 §4.1/§4.2 的 unreserved 集在 base64url 下的取值）。
func pkceValueOK(v string) bool {
	if len(v) < pkceMinLen || len(v) > pkceMaxLen {
		return false
	}
	for _, r := range v {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// ---- 进程内授权事务 / 授权码存储（单实例假设，与 cmd/server 限流同口径）----

type oauthTx struct {
	ClientID, App, RedirectURI, State, Challenge string
	UID                                          int64 // 0 = 尚未绑定（用户还没登录/确认）
	CreatedAt                                    time.Time
}

type oauthCode struct {
	UID                 int64
	App, RedirectURI    string
	ClientID, Challenge string
	IP, UA              string
	Exp                 time.Time
}

type oauthStore struct {
	mu    sync.Mutex
	txs   map[string]*oauthTx
	codes map[string]*oauthCode
}

func newOAuthStore() *oauthStore {
	return &oauthStore{txs: map[string]*oauthTx{}, codes: map[string]*oauthCode{}}
}

// sweep 惰性清过期键：只在写入前、map 攒大时跑一轮（与限流器同款，不引后台任务）。
func (o *oauthStore) sweep() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.txs)+len(o.codes) <= oauthStoreMax {
		return
	}
	now := time.Now()
	for k, e := range o.txs {
		if now.Sub(e.CreatedAt) > oauthTxTTL {
			delete(o.txs, k)
		}
	}
	for k, e := range o.codes {
		if now.After(e.Exp) {
			delete(o.codes, k)
		}
	}
}

func (o *oauthStore) putTx(tx string, e *oauthTx) {
	o.sweep()
	o.mu.Lock()
	defer o.mu.Unlock()
	e.CreatedAt = time.Now()
	o.txs[tx] = e
}

// tx 读事务（**不消耗**：确认页可能刷新重渲染）。
func (o *oauthStore) tx(tx string) *oauthTx {
	o.mu.Lock()
	defer o.mu.Unlock()
	e := o.txs[tx]
	if e == nil || time.Since(e.CreatedAt) > oauthTxTTL {
		delete(o.txs, tx)
		return nil
	}
	return e
}

// takeTx 取出即消耗（单次）：确认/取消二选一都走它。
func (o *oauthStore) takeTx(tx string) *oauthTx {
	o.mu.Lock()
	defer o.mu.Unlock()
	e := o.txs[tx]
	delete(o.txs, tx)
	if e == nil || time.Since(e.CreatedAt) > oauthTxTTL {
		return nil
	}
	return e
}

// bindTx 给事务绑定确认者 uid（登录续跑落到确认页那一刻）；行已不在即 no-op。
func (o *oauthStore) bindTx(tx string, uid int64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if e := o.txs[tx]; e != nil {
		e.UID = uid
	}
}

func (o *oauthStore) putCode(code string, e *oauthCode) {
	o.sweep()
	o.mu.Lock()
	defer o.mu.Unlock()
	o.codes[code] = e
}

// takeCode 取出即消耗（单次）：过期/不存在/复用统一回 nil，调用方给 expired_token。
func (o *oauthStore) takeCode(code string) *oauthCode {
	o.mu.Lock()
	defer o.mu.Unlock()
	e := o.codes[code]
	delete(o.codes, code)
	if e == nil || time.Now().After(e.Exp) {
		return nil
	}
	return e
}
