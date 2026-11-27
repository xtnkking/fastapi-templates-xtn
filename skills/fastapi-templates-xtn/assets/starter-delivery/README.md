# {{PROJECT_NAME}}

Python 3.12，默认连接单机 PostgreSQL 17 和 Redis 7。数据库尚未初始化；
使用者自行生成、审核、执行迁移和准备基础数据，应用不在启动时建表或插入初始角色。

`pyproject.toml` 管理安装依赖和检查工具；`.env.example` 提供配置入口；`.gitignore` 避免提交密钥及缓存。

## 本机启动

1. 创建并启用虚拟环境：`python -m venv .venv`；Windows PowerShell 使用 `.venv/Scripts/Activate.ps1`。
2. 仅运行服务时安装 `python -m pip install -e .`。开发、检查和测试时安装 `python -m pip install -e ".[dev]"`。
3. 将 `.env.example` 复制为 `.env`，填入自己的连接参数。分别生成不同的 `JWT_SECRET`、
   `RATE_LIMIT_HMAC_KEY` 和 `LOG_HMAC_KEY`，不可使用示例占位值，不要将 `.env` 提交到仓库。
4. 完成下文的数据库准备；仅有空表仍不足以注册。
5. 执行 `python -B -m uvicorn app.main:app --host 127.0.0.1 --port 8000`。

默认不开放 Swagger、ReDoc 或 OpenAPI JSON。接口路径和请求模型直接查看
`app/api/v1/endpoints/` 与 `app/schemas/`；需要外部接口文档时由项目自行选择并配置。

默认不包含 `/health/live`、`/health/ready` 或健康检查模块。只有使用者明确要求时才按需添加，
并限制内网或受信探针访问；检查须有短超时，不暴露依赖细节，也不建表或初始化数据。

## 数据库准备

`from app.models.postgres import Base` 可得到完整 `Base.metadata`，导入不连接数据库。
精确字段和约束见 `app/models/postgres/`；使用者自行迁移，应用不执行 DDL 或初始化数据。
普通业务数据及关系软删除，审计只追加；删除后的用户名不能复用。

首次运行前由使用者准备以下内容：

| 数据 | 要求 |
| --- | --- |
| 系统角色 | 按 `app/core/access/roles.py` 的 `SYSTEM_ROLE_SPECS` 只创建 super_admin、user，等级 1000/0，保护属性与规格一致。不预置 admin；需要管理员时另建 1～999 级普通自定义角色并分配权限，500 不保留。 |
| 权限及授权 | 按 `app/core/access/permissions.py` 的 `PERMISSION_CATALOG` 创建权限；目录值为 `PermissionSpec`，名称、分组和说明供接口展示，数据库初始描述仍用 `get_permission_description(key)` 取得中文文本，不能直接存入文案键；严格使用 `app/core/access/roles.py` 中各系统角色显式 permissions 集合。user 只有 `account:read`（查看本人信息）、`account:change_password`（修改本人密码）两项基础权限，无管理权限；super_admin 的白名单也包含这两项，不自动授予全部新权限。自定义管理员的权限另行明确绑定。 |
| 全局状态 | `rbac_state` 只有 `scope` 字段，准备唯一 `scope=global` 行，供权限写入加锁。 |
| 第一位超级管理员 | 基础数据就绪后正常创建用户，再由开发人员在数据库手动建立唯一 super_admin 绑定，保留 user。禁止 API 自选初始角色。 |

角色模型只允许 super_admin、user 标为系统角色；这只限制角色定义，不能保证
`super_admin` 只绑定一名用户，也不能阻止有权限的直接 SQL 修改固定角色。
手动绑定或更换超级管理员时，在一个受控事务中先锁定同一 `rbac_state` 行，再检查最终唯一性、
完成绑定变更并写入审计；不能直接追加第二位超级管理员。全局状态、系统角色及授权须先于用户流量准备完成。
普通认证不读取这条全局锁记录，也不返回全局权限版本；仍实时查询当前用户、角色和权限。
更新已有项目时，修改权限常量不会自动补齐数据库。使用者需自行审核并准备上述权限记录和
角色授权，按已有系统角色保护规则执行受控数据变更；应用不会在请求或启动时修复授权。
更新源码不会自动删除旧库中的 admin。旧库如有对应系统角色、绑定、约束或不可变保护，
库所有者需自行审核迁移，决定转为普通自定义角色，或先解除绑定再处理；不会自动删除角色、权限或账号。

模型和自动生成的迁移不会自动安装自定义触发器。使用者需自行落实并验证数据库级保护：
有效用户必须保留 user、最多 10 个有效角色、唯一超级管理员、系统角色及内置授权不可改、
全局状态不可删除、审计不可改删及应用账号禁止硬删除。跨行和事务最终状态检查需相应约束触发器或权限配置。
Service 的校验与事务不能阻止有权限的直接 SQL；离线测试和模型导入也不能证明这些数据库保护已经安装。

## 已选择与可调整的参数

- 用户名大小写：`{{USERNAME_CASE}}`（sensitive 区分，insensitive 统一小写）；规则见请求模型。
- 注册、管理员新增、本人改密和管理员重置设置的新密码默认 8～32 位，必须同时包含大写字母、小写字母、数字和英文特殊符号；只允许可见 ASCII 字符，不允许空格、中文、emoji 或不可见字符，并检查弱密码及与用户名相同的情况。规则统一在 `app/core/security/password_rules.py` 维护，长度修改该文件的 `MIN_PASSWORD_CHARACTERS`、`MAX_PASSWORD_CHARACTERS` 后重启；请求约束、字段说明及中英文长度提示共用这些常量。登录密码和旧密码只要求非空、有效 UTF-8 且不超过独立的 `MAX_PASSWORD_INPUT_CHARACTERS`（默认 1024 位），不套用新密码强度规则。HTTP 输入长度不符时返回参数校验错误 `42201`。
- 每用户最多同时登录 `{{MAX_SESSIONS}}` 次，超出时退出最早的旧登录。记录的是登录会话，不识别物理设备。
- 管理员新增用户或重置密码时直接设置可登录的密码，并通过可信渠道私下交给用户；用户无需再完成一次密码设置。
- Token 默认 24 小时，在 `.env` 的 `JWT_ACCESS_TOKEN_TTL_SECONDS` 按业务调整。
  默认没有 `iss`/`aud`；只有使用者同意后才同时配置两者。
- 所有限流强制启用，没有关闭开关；默认值在 `.env.example` 的 `RATE_LIMIT_*`
  中，修改自己的 `.env` 后重启生效。
- 单个请求体默认不超过 1 MiB，由 `REQUEST_BODY_MAX_BYTES` 调整；普通响应和
  413 错误都会统一带基础安全响应头。
- 接口及验证码字段见 `app/api/v1/endpoints/` 与 `app/schemas/`。登录后携带
  `Authorization: Bearer <token>`；不记录密码、Token 或验证码答案。
- 验证码用途统一在 `app/core/captcha.py` 的 `CaptchaScene` 维护，允许值和登录要求不再分散填写。
  新增用途默认要求登录；确需未登录使用时同步该类的 `requires_login` 属性。
  三份用途名单自动生成；对应业务接口使用该枚举的 `.value` 校验验证码，前端仍传原有用途字符串。
- `Accept-Language: en` 返回英文，不传默认中文；文案位于 `app/assets/locales/`。
  源码中的字段和查询参数说明保持中文，不随这个请求头切换。

每个用户的 Redis 登录状态只用两个键：`login:sessions:<user_id>` 保存
JTI 字段到规范会话 JSON 的映射和 `_version`，`login:sequence:<user_id>` 保存严格登录顺序。
键名直接使用规范 `U` + 14 位字符的 `user_id`，共 15 位，例如
`login:sessions:UABCDEFGHIJKLMN` 和 `login:sequence:UABCDEFGHIJKLMN`。
Hash 字段和排序成员使用 JTI 的 `UUID.hex`，即 32 位小写十六进制字符；
JWT 中的 `jti` 仍是标准带连字符的 UUID 字符串，用户 ID 和 JTI 都不再取摘要。
键名不带版本、大括号、服务名或环境名。到期时间直接读取 JSON 的 `exp`。
登录和在线会话列表遍历该用户的顺序索引清理过期记录，代价为该用户会话数的 O(n)，
适合每用户少量登录；普通鉴权只在一次 Lua 往返中检查当前记录、版本和顺序索引成员。
登录仍原子保持版本不倒退、容器最晚到期时间，以及超限时淘汰最早登录；不会按最早到期淘汰。
把这套布局用于已有项目时，原登录需要重新登录；旧键按已有 TTL 自然过期，无双读或主动清理。

## 代码从哪里看

先看 `app/main.py`：上半部分的 `lifespan` 按顺序准备日志和共享客户端，
`yield` 表示启动完成，退出时按登记的反向顺序关闭资源；下半部分创建应用、
登记统一异常、添加中间件、挂载业务路由。这里只做组装，具体实现到下面查找：

| 要找的功能 | 文件 |
| --- | --- |
| 参数不合法、权限不足等错误怎样返回 | `app/core/exception_handlers.py` |
| 哪些业务码代表成功或失败 | `app/core/codes.py`，前三位对应 HTTP 状态，后两位区分结果 |
| 在业务中怎样抛出未登录、无权限等错误 | `app/core/exceptions.py` |
| 请求 ID、语言响应头、耗时及未捕获错误日志 | `app/core/middleware/request_logging.py` |
| 请求体大小限制与统一 413 响应 | `app/core/middleware/request_body_limit.py` |
| 所有 HTTP 响应的基础安全头 | `app/core/middleware/security_headers.py` |
| 统一响应字段、分页结构与响应组装 | `app/core/response.py`；`api_response` 默认普通成功码 20000，创建和错误仍显式指定 |
| 日志脱敏和 JSON 格式 | `app/core/logging/events.py` |
| 请求/响应摘要、被操作人和新密码指纹 | `app/core/logging/details.py`；只旁观已有收发，不额外读取请求 |
| 请求日志的 `request_id` 关联 | `app/core/logging/context.py` |
| 日志同时写控制台和文件 | `app/core/logging/output.py`；`logs/北京时间日期/app.log`，跨天换目录，重启追加；默认单文件 100 MB，`.env` 的 `LOG_FILE_MAX_MB` 修改后重启，超出前切换 `app.1.log`、`app.2.log`；保存位置修改 `LOG_ROOT_DIR`，旧文件保留 |
| 注册、改密、用户与角色管理有哪些固定审计动作 | `app/core/audit.py` 的 `AccountAuditAction`、`RbacAuditAction`；Service 向 `audit_success`／`audit_denied` 直接传枚举成员 |
| 账号、权限操作审计在哪里 | `app/models/postgres/operation_audit.py` 定义统一表，`app/services/audit_service.py` 写入，默认不附带订单等业务审计 |
| 用户名配置：长度、允许字符、保留名称及首尾空白处理 | `app/core/security/user_name.py`（请求、查询、模型和提示共用） |
| JWT 字段、签名和验签 | `app/core/security/jwt_tokens.py` |
| Redis 两键登录记录、顺序、到期清理和撤销 | `app/repositories/redis/login_session_repository.py` 的 `login_session_repository` |
| 生成 Token 并登记登录，成功后才返回 | `app/services/auth_service.py` 的 `AuthService.issue_access_token`；登录内部调用 |
| 启动时检查业务接口登录与限流接线 | `app/api/v1/route_validation.py` 声明本版规则，`app/core/route_validation.py` 执行通用检查 |
| 登录及账号检查 | `app/dependencies/auth.py` 的 `get_current_user` 依赖 `check_token`，执行普通额度限流，再读取账号和角色权限；不检查指定权限 |
| 本人信息及改密权限 | `app/dependencies/permission.py` 的 `require_permission` 分别检查 `ACCOUNT_READ`、`ACCOUNT_CHANGE_PASSWORD`，默认使用普通用户额度 |
| 管理接口权限检查 | `app/dependencies/permission.py` 的 `require_permission` 内部依赖 `check_token`，执行管理额度限流，再调用共用账号读取、检查指定权限 |
| 退出当前登录 | 路由直接使用 `Depends(check_token)` 验证 JWT 和 Redis 活跃登录，再精确删除本次登录；不限流、不读取限流客户端、不查询数据库或检查业务权限 |

文件和控制台使用相同的单行 JSON；保留请求 ID、接口、状态码、耗时、操作人
`user_id`、被操作人 `target_user_id`、目标角色 `target_role_id`、动作和脱敏后的
`request_data`/`response_data`，没有信息的固定字段为 `null`。不附加服务名称、
版本、环境或重复的泛化目标字段。`SERVICE_NAME`/`SERVICE_VERSION` 仅用于
FastAPI 应用信息，无需填写 `APP_ENVIRONMENT`。

注册、新增用户、本人改密和管理员重置时，`password_fingerprint` 用独立
`LOG_HMAC_KEY` 对待设置的新密码计算 HMAC-SHA256，保留前 32 个十六进制字符。
同密钥下同密码得到同指纹，便于排查重复提交；无法从指纹解密密码，不使用 MD5，
不记录登录密码或旧密码指纹。原密码字段、验证码答案、Token、用户名及自由文本
均脱敏；未知字段只计数。每侧仅旁观最多 16 KiB，脱敏摘要最多 4 KiB，超大、
非 JSON 或未读完的正文只记省略原因。业务未读取请求时不为日志额外读取。
换日志密钥后新旧指纹不能直接比较；修改 `.env` 后重启生效。

API：`app/api/v1/endpoints/`；业务：`app/services/*_service.py`；
PostgreSQL 查询：`app/repositories/postgres/*_repository.py`；模型：`app/models/postgres/`；
Redis 登录记录访问：`app/repositories/redis/login_session_repository.py`；
请求响应：`app/schemas/`；依赖：`app/dependencies/`；应用配置：`app/core/config.py`；
数据库入口：`app/db/postgres_db.py`、`app/db/redis_db.py`；
PostgreSQL 的连接池、借连接检查、会话及连接故障分类都在 `postgres_db.py`；
该文件的 `get_constraint_name` 只负责从驱动异常读取约束名，不决定业务怎么报错或重试。
新增用户和角色仍在各自 Service 中判断具体约束；自动生成 ID 的主键碰撞最多尝试三次，
调用方指定的用户 ID 不会被自动更换，其他完整性错误沿原流程交给调用方处理。
“无权限”等业务错误仍在 `core/exceptions.py`。Redis 只连接单机 URL。
查询接口中的 `db: Annotated[AsyncSession, Depends(get_postgres_session)]` 表示 FastAPI 从
`postgres_db.py` 为本次请求借一个 PostgreSQL 会话，请求结束自动关闭；接口不手动提交。
`Depends(...)` 是注入写法，不是额外的数据库或权限检查。注册、改密、角色变更等写入由
Service 自己开启事务，并把业务变更和审计一起提交；认证读取账号时也只短暂借用会话，
读完先关闭，再做后续 Redis 检查或写入。不要给写接口额外加一个未使用的请求会话。
接口按五类归档：`auth.py` 负责认证，`me.py` 负责本人账号，`users.py` 负责用户管理，
`roles.py` 负责角色管理，`permissions.py` 负责权限目录。

请求响应模型也按用途查找：`schemas/auth.py` 放注册、登录、本人改密请求和令牌结果；
`schemas/captcha.py` 放验证码申请、答案和图片结果；`schemas/user.py` 放用户管理及会话统计。
请求基类、用户名校验和公共密码字段类型在 `schemas/common.py`。
登录密码和旧密码使用 `Password`；注册、新增用户和改密、重置的新密码使用 `NewPassword`。
两者以 `SecretStr` 和 `Field` 直接检查各自长度；新密码的字符、强度和弱密码检查统一调用
`core/security/password_rules.py` 的 `validate_new_password`。这个文件和 `user_name.py`
一样负责输入规则；`passwords.py` 负责 Argon2 哈希、密码比对和计算排队。

内置审计动作在 `core/audit.py` 按账号安全和授权管理分组，每个成员都有中文说明。
例如管理员重置密码向 `audit_success` 传入 `AccountAuditAction.ADMIN_RESET_PASSWORD`。
动作说明“做什么”，成功、拒绝或失败由记录的结果字段说明，不需要再造一个动作名。
新增固定事件时先明确触发时机和安全字段，再维护所属枚举及业务调用；动态接口拒绝仍按原规则记录。

默认只用 `operation_audit_events` 一张表，由 `AuditService` 记录账号及权限操作。
业务只调用 `audit_success` 添加当前事务的成功记录，或在回滚后调用 `audit_denied`
记录原异常；分类、操作人、来源及关联 ID 自动取自枚举和可信上下文。
注册和管理员新增各写一条记录，普通查询只写文件日志。表中保留脱敏请求参数、业务响应
快照、新密码比较指纹和必要的变更前后状态；密码、验证码答案和令牌不保存原文。
摘要复用文件日志规则，每侧最多采集 16 KiB、保存 4 KiB；未知字段默认隐藏。
成功审计与业务修改一起提交，响应快照不代表客户端已经收到；HTTP 实际结果看文件日志。
订单、余额等通用业务审计默认不生成，有实际需求时再明确动作及安全字段后接入。

以权限查询为例，按 `endpoints/permissions.py` → `services/permission_service.py` →
`repositories/postgres/permission_repository.py` 阅读；模型和公开字段分别在
`models/postgres/permission.py`、`schemas/permission.py`。接口收参数，Service 处理分页、
缺失提示和结果，Repository 写查询。用户、角色业务沿用相同归属；管理员新增和重置密码在
`user_service.py`，注册、登录和本人改密在 `auth_service.py`。
注册与登录的接口先通过 `dependencies/rate_limit.py` 中的显式依赖按业务限流，再验证并一次性作废验证码，
最后进入 `AuthService`；登录成功后才签发 Token。验证码存储、签发和一次性消费在
`captcha_service.py`，
多个入口共用的建账号流程在 `user_service.py` 的 `create_user()`；
管理员新增入口为同一类中的 `admin_create_user()`。按这个顺序可以直接读懂请求经过哪些检查。
API 版本前缀只在 `api/v1/router.py` 声明；权限策略和限流规则分别在
`core/access/authorization_policy.py`、`dependencies/rate_limit.py`。

刚开始学习时，先看接口函数中的“访问条件”，再沿调用进入 Service 和 Repository。
例如 `permissions:read` 表示允许查看权限目录；它是程序检查的权限标识，不是角色名称。
全部内置权限及其用途在 `core/access/permissions.py` 的 `PermissionKey` 中逐项说明；
`PERMISSION_CATALOG` 集中记录名称、分组和说明；新增业务权限需同时补齐中英文文案。
权限列表和详情返回 `id`、`key`、`name`、`group_key`、`group_name`、`description` 和
`api_routes`。关联接口从实际路由的权限依赖在启动时收集，查询时读取内存，不手工维护路径。
`api_routes` 为空只表示没有明确要求该权限的 HTTP 入口，不表示权限无效。
拥有某项管理权限后，仍需通过目标等级和可见范围检查，不能据此操作所有用户或角色。
模型与请求响应字段旁说明取值含义；Service 注释说明检查和修改的顺序；Repository
注释说明查哪些数据、查不到意味着什么，以及由谁提交事务。
配置用途、默认值和单位见 `core/config.py`，部署时在自己的 `.env` 修改对应大写配置项。
公开字段通过 Schema 中的 `Field(description=...)` 和接口中的 `Query(description=...)`
说明其业务含义；默认不开放 `/docs`、`/redoc` 或 `/openapi.json`。多个参数的类方法逐行对齐，
长接口签名和较多的响应、审计字段也分别换行，方便逐项阅读。
遇到函数里又定义函数时，先找它在哪里被调用；定义回调本身不会执行校验或数据库写入。

业务接口只用 GET、POST。查询列表和详情分别以 `/list`、`/detail` 结尾，例如
`GET /api/v1/roles/detail?role_id=...`；修改操作通过 JSON 请求体传 ID，例如
`POST /api/v1/users/disable` 提交 `{"user_id":"..."}`。这些操作都要通过服务端权限与目标检查。
ID 放在哪个位置不等于是否安全；密码、Token 等敏感值不能放进查询字符串。

`GET /api/v1/roles/list` 支持以下查询筛选，已传条件按 AND 组合：

| 参数 | 含义与默认值 |
| --- | --- |
| `role_id` | 可选，角色 ID 精确匹配 |
| `key` | 可选，角色标识精确匹配 |
| `name` | 可选，角色名称包含匹配；`%`、`_` 按字面字符匹配，不是通配符 |
| `is_active` | 可选，`true` 只查启用、`false` 只查禁用；不传时两者都查 |
| `is_system` | 可选，`true` 只查系统角色、`false` 只查非系统角色；不传时两者都查 |
| `is_deleted` | 默认 `false`，只查未删除角色；`true` 只查已软删除角色 |

例如 `GET /api/v1/roles/list?name=审计&is_active=true&is_system=false` 查询名称含“审计”的
启用非系统角色，`GET /api/v1/roles/list?is_deleted=true` 查询已删除角色。列表和 `total`
共用 SQL 筛选与可见范围：仍需 `roles:read`，普通调用者只能查看低于自己、未受保护且非
`super_admin` 的角色，超级管理员可查看所选删除状态的全部角色。已删除角色只展示基本信息，
`permissions=[]`，不读取旧授权；角色详情仍排除已删除角色。这些筛选不新增恢复或删除接口。

新增受保护接口时，参考现有 `me.py` 和 `roles.py`：本人信息使用
`Depends(require_permission(PermissionKey.ACCOUNT_READ))`，本人改密使用
`Depends(require_permission(PermissionKey.ACCOUNT_CHANGE_PASSWORD))`；只要求登录的业务可用
`Depends(get_current_user)`。管理接口使用 `require_permission(具体权限, management=True)`。
权限依赖先经身份与限流检查，
再查具体权限；目标是否可见仍由对应 Service 判断。拒绝写操作的审计由授权事务服务统一处理。
权限依赖默认按 GET/POST 使用普通用户读取或写入额度，只有显式传 `management=True` 才使用
管理额度；不根据角色或是否检查权限推断。限流始终执行，不需要额外装饰器、`operation_id` 或全局路由登记表。
处理函数名会成为服务端内部的独立业务计数名称，因此名称必须稳定且不能重复。
启动时会检查认证依赖、路由名称、HTTP 方法和参数位置，漏接保护会直接启动失败。

## 检查代码

以下测试离线运行，不读 `.env`、不连接 PostgreSQL/Redis、不生成迁移。增加业务后按风险补相关测试。

```text
python -B -m pytest
python -B -m autopep8 --diff --exit-code --recursive app tests
python -B -m ruff check --no-cache app tests
python -B -m mypy app
```

格式修正将 `--diff --exit-code` 替换为 `--in-place`。pytest/Ruff 禁用磁盘缓存，mypy 缓存位于项目外；
`-B` 防止本次 Python 进程写 `__pycache__`。修改源码时维护原有 History 和函数说明。
