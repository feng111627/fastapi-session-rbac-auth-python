# FastAPI 会话 + RBAC 认证后端

在 Web 骨架之上扩展的账号体系后端：账号口令登录、服务端会话、角色/权限分级继承、
显式拒绝、登录失败锁定、CSRF 防护。所有安全约束在并发与异常情况下均不可绕过。

## 认证方式

同一账号支持两类入口，二者解析到**同一个服务端会话**，权限结论必然一致：

| 入口 | 适用客户端 | 凭证形式 |
| --- | --- | --- |
| Cookie 会话 | 浏览器 | `session_id` Cookie（`HttpOnly; SameSite=Lax; Path=/`，可开 `Secure`） |
| Bearer 令牌 | 脚本 / 服务端调用 | `Authorization: Bearer <token>` |

- `POST /login`：JSON `{username, password}`。成功返回 `{token, csrf_token}` 并种下会话 Cookie。
- `POST /logout`：注销当前会话，Cookie 与对应 Bearer 令牌同时失效。
- `GET /me`：查看当前账号、角色与解析后的权限。

### 会话约束

- **滑动过期**：每次有效请求刷新空闲计时（默认 30 分钟，可配 `idle_timeout`）。
- **并发上限**：同一账号会话数超过上限（默认 3，可配 `max_sessions_per_user`）时
  **淘汰最旧会话**；被淘汰/已注销/过期的会话再发请求一律判为失效。
- 失败原因可区分：未携带凭证 → `401 unauthenticated`；凭证失效 → `401 session_invalid`。

## 权限模型

- **角色分级继承**：角色可声明父角色（如 `editor` 继承 `viewer`），用户权限为
  全部角色沿继承链的并集（`app/rbac.py`，带环保护）。
- **显式允许/拒绝**：`AccessRule` 可针对特定用户或 `role:<角色>`、特定资源生效；
  判定顺序为 **显式拒绝 > 显式允许 > 角色继承**。
- **多入口一致**：直接访问（`GET /documents/{id}`）与间接调用
  （`GET /documents/{id}/summary`）等所有受保护入口共用同一判定函数。
- **不泄露存在性**：先鉴权再查资源，未授权时无论资源是否存在都返回 `403 forbidden`。

内置示例账号：`alice/alice-pw`（editor，但被显式拒绝写 `doc-9`）、`bob/bob-pw`（viewer）。

## 安全约束

- **登录锁定**：连续失败达阈值（默认 5 次）锁定账号（默认 5 分钟），锁定期间返回
  `429 locked`；失败计数与锁定判定在同一把锁内完成，并发下不可被竞争绕过；
  登录成功清零计数。未知用户与口令错误返回相同的 `401 invalid_credentials`，不可枚举账号。
- **CSRF 防护**：Cookie 会话的状态变更请求（非 GET/HEAD/OPTIONS）必须携带
  `x-csrf-token` 头且与会话令牌匹配，否则 `403 csrf_failed`；
  Bearer 客户端豁免，不会被误伤。
- **口令存储**：PBKDF2-HMAC-SHA256 加盐散列，常数时间比较。

## 本地验证

```bash
uv sync                 # 安装依赖
uv run pytest -v -s     # 跑测试；-s 可看到每个场景的 [PASS] 说明
uv run python main.py   # 启动服务（或 uv run uvicorn main:app）
```

手动验证示例：

```bash
curl -i -c jar -X POST localhost:8000/login -H 'content-type: application/json' \
     -d '{"username":"alice","password":"alice-pw"}'
curl -b jar localhost:8000/me
```

## 代码结构

```
app/
  models.py     # User / Role / AccessRule / Session 数据模型
  security.py   # 口令散列、令牌生成
  rbac.py       # 角色继承解析与权限判定（拒绝优先）
  sessions.py   # 会话存储：滑动过期、并发上限淘汰、注销
  ratelimit.py  # 登录失败计数与锁定（线程安全）
  auth.py       # Cookie/Bearer 统一认证依赖 + CSRF 校验
  main.py       # 应用装配与路由（create_app 工厂，参数可配）
tests/test_auth.py  # 17 个关键路径测试
```
