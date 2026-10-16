# 统一登录网关 · 项目接入适配文档

> 网关地址：`https://oauth.horatio.cn`（下称 `<gateway>`）
> 协议：OAuth 2.0 授权码 + PKCE + OpenID Connect Core 1.0

## 0. 数据契约（先读这个）

网关**只存基础身份数据**：`sub`（用户 ID）、姓名、头像、邮箱（含验证状态）、
认证凭证（密码哈希 / Passkey / TOTP）、以及每个项目的角色授权。

**各项目的业务用户数据（积分、设置、订单……）一律由项目自己的数据库存储**，
用 `sub` 作为外键自行关联：

```
你的 users 表： gateway_sub (BIGINT, 唯一索引) ← 对应网关 sub
```

网关**不会**向下游传递任何项目业务字段；你也**不需要**在网关里建用户——用户
首次经网关登录到你的项目时，你按下方 claims 建档即可（JIT provisioning）。

## 1. 三种接入方式

| 方式 | 适用 | 说明 |
|---|---|---|
| 管理后台手动创建 | 常规项目 | 在 `/admin` 的项目页创建 Client，保存一次性显示的 Client ID/Secret |
| 动态注册（RFC 7591） | 自动化/脚本 | `POST <gateway>/api/register`，见 §6 |
| 两者创建的 Client 完全等价 | | |

## 2. OIDC 端点

从 Discovery 自动发现（推荐）：

```
GET <gateway>/.well-known/openid-configuration
```

| 端点 | 路径 |
|---|---|
| Discovery | `/.well-known/openid-configuration` |
| JWKS | `/.well-known/jwks.json` |
| 授权 | `/oauth/authorize` |
| 令牌 | `/oauth/token` |
| UserInfo | `/oauth/userinfo` |
| 内省（RFC 7662） | `/oauth/introspect` |
| 吊销（RFC 7009） | `/oauth/revoke` |
| RP 发起登出 | `/oauth/logout` |
| 动态注册（RFC 7591/7592） | `/api/register` |

支持：`response_type=code`、PKCE（S256，**建议所有客户端携带**，机密客户端同时支持
client_secret 认证）、`client_secret_basic` / `client_secret_post`、refresh_token、
`prompt=login/none/consent`、`max_age`。

## 3. 标准登录流（授权码 + PKCE）

```
1. 生成 code_verifier（43-128 字符）与 code_challenge = BASE64URL(SHA256(verifier))
2. 跳转 <gateway>/oauth/authorize?
     response_type=code
     &client_id=你的ID
     &redirect_uri=你的回调地址
     &scope=openid profile email
     &state=随机串          ← 必带，防 CSRF
     &nonce=随机串          ← 必带，防重放
     &code_challenge=...&code_challenge_method=S256
3. 用户在网关完成登录（密码/Passkey/TOTP/GitHub/Google）并同意授权
4. 回调 redirect_uri?code=...&state=...
5. 后端用 code 换 token（同时校验 state 与 PKCE）：

   POST <gateway>/oauth/token
   Authorization: Basic base64(client_id:client_secret)
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code&code=...&redirect_uri=...&code_verifier=...

6. 响应：{ access_token, id_token, refresh_token, expires_in }
   用 JWKS 验证 id_token（RS256），校验 iss/aud/exp/nonce
7. 可选：GET <gateway>/oauth/userinfo，Authorization: Bearer <access_token>
```

## 4. Claims（id_token / userinfo 一致）

| Claim | 类型 | 说明 |
|---|---|---|
| `sub` | string | **网关用户唯一 ID**——下游唯一主键，勿解析勿自增 |
| `name` | string | 姓名 |
| `email` | string | 邮箱 |
| `email_verified` | bool | 邮箱是否已验证 |
| `picture` | string | 头像 URL |
| `auth_time` | number | 本次认证时间（Unix 秒） |
| `updated_at` | number | 资料最后更新时间 |

> 网关遵循数据最小化：白名单外的字段**永远不会**出现在令牌里。

## 5. 单点登出

**主动登出（RP 发起）**：重定向用户到
`<gateway>/oauth/logout?id_token_hint=<最近的id_token>&post_logout_redirect_uri=<已登记的地址>&state=...`

**被动登出（Back-Channel，推荐）**：在 Client 上登记 `backchannel_logout_uri`
（管理后台或 RFC 7592 更新）。网关在用户登出时向该地址 POST：

```
Content-Type: application/x-www-form-urlencoded

logout_token=<JWT>
```

`logout_token` 为 RS256 JWT，claims 含 `iss/aud/sub/jti/iat/exp` 及
`events: {"http://openid.net/specs/connect-1.0-event:logout_token": {}}`。
收到后应立刻销毁对应 `sub` 的本地会话（只信 `sub`，不解析业务数据）。

## 6. 动态客户端注册（RFC 7591/7592）

```bash
# 注册（initial access token 向网关管理员索取，未配置则不开放）
curl -X POST <gateway>/api/register \
  -H "Authorization: Bearer <initial-token>" -H "Content-Type: application/json" \
  -d '{"client_name":"My App","redirect_uris":["https://app.example.com/callback"]}'

# 响应含 client_id / client_secret / registration_access_token（仅此一次）
# 之后用 registration_access_token 管理（RFC 7592）：
#   GET/PUT/DELETE <gateway>/api/register/{client_id}
```

## 7. 项目角色（可选）

管理员可在网关为用户分配项目角色（`admin` / `member`），在管理后台的项目页管理。
当前角色仅在网关侧生效（决定谁能在网关管理该项目）；通过 `userinfo`/`id_token`
向下游 Client 下发 `roles` claim 属于规划能力，开放后本节会同步更新。
项目级权限判断建议：**能力建在项目内，网关角色只做入口分级**。

## 8. 各语言验签示例

### Node.js (openid-client)

```js
import { Issuer } from 'openid-client';
const iss = await Issuer.discover('https://oauth.horatio.cn');
const client = new iss.Client({ client_id, client_secret, redirect_uris });
// 授权码 + PKCE 全流程由库处理，id_token 自动验签
```

### PHP (league/oauth2-server 客户端侧 / jumbojett)

```php
$oidc = new Jumbojett\OpenIDConnectClient('https://oauth.horatio.cn', $clientId, $clientSecret);
$oidc->addScope(['openid', 'profile', 'email']);
$oidc->redirect_uri('https://app.example.com/callback');
$oidc->authenticate();
$sub = $oidc->getVerifiedClaims('sub');
```

### Python (Authlib)

```python
from authlib.integrations.flask_client import OAuth
oauth = OAuth(app)
oauth.register('gateway', server_metadata_url='https://oauth.horatio.cn/.well-known/openid-configuration',
               client_id=..., client_secret=..., client_kwargs={'scope': 'openid profile email'})
# oauth.gateway.authorize_redirect / parse_id_token 自动验签
```

### Go (coreos/go-oidc)

```go
provider, _ := oidc.NewProvider(ctx, "https://oauth.horatio.cn")
oauth2cfg := &oauth2.Config{ClientID: ..., ClientSecret: ..., Endpoint: provider.Endpoint(),
    RedirectURL: "https://app.example.com/callback", Scopes: []string{"openid", "profile", "email"}}
idToken, err := verifier.Verify(ctx, rawIDToken) // 自动查 JWKS 验签
```

## 9. 网关的社交账号绑定行为

网关对 GitHub/Google 返回的邮箱**不会自动合并**到已有账户：
外部邮箱命中已有网关账户时，会要求用户先登录原账户，登录成功后完成显式绑定；
已登录用户也可在「安全设置」中主动绑定社交账号。新邮箱则自动 JIT 建号
（Google 主邮箱标记为已验证；GitHub 邮箱不作验证标记）。

## 10. FAQ

**Q: 网关能帮我存项目的用户数据吗？**
不能，也不应该——见 §0 数据契约。

**Q: 同一个用户在不同项目是同一个 sub 吗？**
是。`sub` 全局唯一；是否允许某用户进入某项目由网关的项目成员关系控制。

**Q: 忘记 client_secret 怎么办？**
管理后台 → 项目 → 轮换 Secret（旧值即刻失效）。

**Q: 测试环境怎么调试？**
在管理后台注册一个 redirect_uri 指向开发机回调地址的开发 Client
（redirect_uri 需为绝对 URL）。
