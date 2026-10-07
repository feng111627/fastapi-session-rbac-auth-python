# fastapi-session-rbac-auth

基于 FastAPI 的账号体系后端：账号口令登录、服务端会话、RBAC 角色/权限控制、
登录失败锁定与 CSRF 防护。

## 认证方式

`POST /auth/login` 提交 `{"username", "password"}`，验证通过后建立**服务端会话**，
同时下发两类凭证，对应两类客户端入口：

| 入口 | 凭证 | 适用场景 |
|------|------|----------|
| Cookie `sid`（`HttpOnly; SameSite=Lax; Path=/`，生产环境应开启 `Secure`） | 浏览器 | 浏览器会话 |
| 响应体中的 `token`，以 `Authorization: Bearer <token>` 携带 | 脚本 / 服务端调用 | 非浏览器客户端 |

两类入口解析到**同一个服务端会话对象**，后续权限判定走同一个
`app.rbac.check_permission`，因此对同一账号、同一资源的结论必然一致。

其他认证接口：`POST /auth/logout`（注销）、`GET /auth/me`（当前身份）。

## 权限模型

- **角色分级继承**：角色可声明 `parents`，权限沿继承链累积
  （内置 `viewer`（读） ← `editor`（写） ← `admin`（删），见 `app/main.py: seed`）。
- **显式授予/拒绝**：`PermissionGrant` 支持 `user:<名>` / `role:<名>` 主体、
  具体资源或 `*` 通配。**显式 DENY 永远优先于任何 ALLOW**（`app/rbac.py`）。
- **多入口一致**：直接入口 `GET /documents/{id}` 与间接入口 `GET /reports/{id}`
  复用同一判定函数。
- **不泄露存在性**：资源不存在与无权限返回完全相同的 `403 forbidden` 响应。
- 错误原因可区分（响应体 `detail.reason`）：

| reason | 状态码 | 含义 |
|--------|--------|------|
| `unauthenticated` | 401 | 未携带任何凭证 |
| `session_invalid` | 401 | 会话已注销 / 过期 / 被淘汰 / 令牌伪造 |
| `invalid_credentials` | 401 | 口令错误（未知用户返回相同结果） |
| `account_locked` | 423 | 连续失败触发锁定 |
| `csrf_failed` | 403 | Cookie 入口状态变更缺少/错误 CSRF 令牌 |
| `forbidden` | 403 | 已认证但无权限（不区分资源是否存在） |

## 会话与安全约束

- **滑动过期**：每次有效访问重置过期时间（`session_ttl_seconds`，默认 1800s），
  闲置超时即失效。
- **并发上限**：同一账号会话数超过 `max_sessions_per_user`（默认 3）时
  **淘汰最旧会话**；被淘汰/已注销的会话再请求一律判为 `session_invalid`。
- **失败锁定**：连续失败 `login_max_failures`（默认 5）次锁定
  `login_lockout_seconds`（默认 300s）；计数与锁定状态在锁内变更，
  并发请求不会丢失计数或绕过锁定；登录成功清零。
- **CSRF**：仅对 Cookie 承载的非安全方法（POST/PUT/PATCH/DELETE）校验
  `X-CSRF-Token` 头（登录响应中下发 `csrf_token`）；Bearer 客户端天然免疫
  CSRF，不做该校验，不会误伤脚本调用。
- **口令存储**：PBKDF2-HMAC-SHA256 + 随机盐，常量时间比较。
- 所有共享状态（用户/角色/授权、会话表、失败计数）均在锁内访问，
  并发与异常路径（过期清理、淘汰、注销）不会绕过安全约束。

## 本地验证

```bash
uv sync                 # 安装依赖
uv run pytest -v -s     # 运行测试；-s 可看到每个场景的中文结果日志
uv run python main.py   # 启动服务（127.0.0.1:8000，文档 /docs）
```

手动验证示例：

```bash
# 登录（演示账号：alice/alice-pw=editor, bob/bob-pw=viewer, carol/carol-pw=admin）
curl -i -c jar -X POST localhost:8000/auth/login \
  -H 'content-type: application/json' -d '{"username":"alice","password":"alice-pw"}'
# Cookie 入口读取
curl -b jar localhost:8000/documents/doc-1
# Bearer 入口写入（免 CSRF）
curl -X POST localhost:8000/documents/doc-1 \
  -H "Authorization: Bearer <token>" -H 'content-type: application/json' \
  -d '{"content":"hi"}'
```

## 目录结构

```
app/
  config.py     会话/锁定/Cookie 等参数
  models.py     User / Role / PermissionGrant / Session
  security.py   口令散列与令牌生成
  store.py      线程安全的用户/角色/授权存储
  sessions.py   会话管理（滑动过期、注销、超限淘汰）
  rbac.py       角色继承展开与权限判定（DENY 优先）
  ratelimit.py  登录失败计数与锁定
  auth.py       FastAPI 依赖：身份解析、CSRF、权限校验
  main.py       路由装配与种子数据
tests/          登录 / RBAC / 会话 / 锁定 / CSRF 关键路径测试
```
