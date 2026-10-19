# Horatio 统一账号服务

`auth.horatio.cn` 后端：Go + MySQL 的邮箱账号服务，为热量日记、记账等应用提供
注册 / 登录（密码与邮箱验证码）/ 找回密码 / 修改密码 / 修改邮箱 / 注销与 JWT
会话签发。与两个日记服务自带的 `/auth/*` 端点**一一对应、JSON 字段完全一致**，
客户端切换只需改 base URL 并在登录请求加 `app` 字段。

## 端点

| 端点 | 说明 |
|---|---|
| `POST /auth/register` | 注册（验证码必填，注册即登录） |
| `POST /auth/send-code` | 发注册 / 找回密码 / 登录验证码 |
| `POST /auth/reset-password` | 验证码找回密码 |
| `POST /auth/login` | 密码登录 |
| `POST /auth/login-code` | 邮箱验证码登录 |
| `POST /auth/logout` | 登出（token_version+1，吊销全部会话） |
| `POST /auth/change-password` | 原密码改密 |
| `POST /auth/send-change-code` | 绑定邮箱发改密验证码 |
| `POST /auth/change-password-code` | 验证码改密 |
| `POST /auth/send-change-email-code` | 新邮箱发改绑验证码 |
| `POST /auth/change-email` | 改绑邮箱 |
| `POST /auth/delete` | 注销账号（删本服务数据；业务数据清理由日记服务的 internal 钩子负责） |
| `POST /internal/verify` | 内部接口：日记服务的 withUID 中间件验 token + aud，回 `{uid,email,app}` |
| `GET /health` | 健康检查（碰数据库）；`mailConfigured` / `jwtConfigured` 自查位 |

登录 / 注册 / 验证码登录的请求体带 `app`（`calorie-diary` / `expense-diary` 白名单），
作为 JWT 的 aud——下游服务只接受为自己应用签发的 token。

## 本地命令

```bash
go build ./...        # 编译
go test ./...         # 测试（DB 相关用例需要 TEST_MYSQL_DSN，缺省自动 Skip）
go vet ./...          # 静态检查
ci/build-server.sh    # 测试 + 打包 dist/server.tar（CI 部署用的同一入口）
```

## 配置

| 来源 | 键 | 说明 |
|---|---|---|
| 环境变量 | `BIND_ADDR` | 监听地址，默认 `127.0.0.1:8868`（对外走 nginx TLS 反代） |
| 环境变量 | `MYSQL_DSN` | MySQL 连接串，密码绝不入库（模板见 `.env.example`） |
| 环境变量 | `JWT_SECRET` | HS256 密钥，**少于 32 字节拒启** |
| `app_config` 表 | `mail_tenant_id` / `mail_client_id` / `mail_client_secret` | Microsoft Graph 发信凭据，部署时人工灌，改库 10 秒内热生效 |

## 部署

GitHub Actions（self-hosted runner）→ `ci/deploy-server.sh`：上传 tar、原子切换
`current` symlink、supervisord 重启 `auth:*`、`/health` 检查失败自动回滚。
部署去向 `/www/wwwroot/auth.horatio.cn/server`（Actions secret `SERVER_BASE_DIR`），
进程监听 `127.0.0.1:8868`，由同机 nginx 对外提供 `https://auth.horatio.cn`。
