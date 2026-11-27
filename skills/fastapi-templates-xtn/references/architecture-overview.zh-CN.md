# fastapi-templates-xtn 中文架构总览

本文帮助维护者和下载使用者快速理解各模块如何配合，不替代英文详细规范。
实现或修改具体功能时，仍以 `SKILL.md` 路由到的英文 reference 和随附测试为
唯一详细执行标准；不要把本文复制成第二套独立规范。

## 适用范围

从零搭建时，默认按职责建目录，并在文件名中说明业务：

- API：`api/v1/endpoints/<业务名>.py`，由 `api/v1/router.py` 汇总。
- 业务逻辑：`services/<业务名>_service.py`。
- 数据访问：`repositories/postgres/<业务名>_repository.py`，其他数据库按需分类。
- 模型：`models/postgres/<业务名>.py`；数据库连接放在 `db/postgres_db.py`、`db/redis_db.py`。
- 请求和响应模型：`schemas/<业务名>.py`。

每个 Python 函数都有中文多行说明，写清用途、`:param 参数名:` 和非空的
`:return:`／`:yield:`。具体规则见[函数注释](python-comments.md)，完整目录边界见
[项目结构](project-structure.md)。已有成熟项目沿用原框架；目录分类不要求增加
纯转发函数，也不默认创建 MongoDB 或后台任务模块。

目录和代码要能按同一个业务顺着找到：

| 要看什么 | 接口文件 | 业务文件 | 数据访问文件 |
| --- | --- | --- | --- |
| 注册、登录、公开验证码和退出当前登录 | `endpoints/auth.py` | `auth_service.py`；验证码和退出复用安全依赖 | 按实际业务复用用户仓储与 Redis 工具 |
| 本人信息、权限、改密、登录后验证码和会话列表 | `endpoints/me.py` | `auth_service.py`；其余复用安全依赖和投影 | 按实际业务复用现有仓储与 Redis 工具 |
| 角色查询、创建、启停、权限绑定 | `endpoints/roles.py` | `role_service.py` | `role_repository.py` |
| 管理员查询、新增、重置密码、状态、角色绑定和强制下线 | `endpoints/users.py` | `user_service.py` | `user_repository.py`、`user_role_repository.py` |
| 权限目录列表和详情 | `endpoints/permissions.py` | `permission_service.py`，负责分页、详情缺失和结果组装 | `permission_repository.py` |

上表接口文件位于 `api/v1/`，业务文件位于 `services/`，数据访问文件位于
`repositories/postgres/`。用户查询、当前账号与权限读取、可见用户列表放在
`user_repository.py`；角色可见范围和角色权限查询放在 `role_repository.py`，
不再另拆一个权限查询仓储。
单个用户统一用 `get_user` 查询，可传用户 ID、用户名、启用状态和软删除状态；
同时传 ID 和用户名时，两者都必须匹配。默认只查未删除账号；登录和检查用户名
是否被占用时明确包含已删除账号，已删除账号仍不能登录，用户名仍不能重用。
默认接口按认证、本人、用户管理、角色管理、权限目录这五组放置；验证码、
密码和会话操作跟随所属业务，不再单独拆成三个接口文件。底层共享的安全工具、
事务和 Service 仍保留各自职责，放到同一个接口文件不等于放宽权限。

Service 和 Repository 使用明确的业务类和实例，例如 `RoleService`、
`role_repository`；共享实例不保存当前用户或数据库会话。接口负责收参数、
调用业务、返回响应，不直接写 SQL；SQL 查询和有实际含义的持久化操作在 Repository。
Service 决定查询时机和事务边界，已锁定模型的简单字段赋值可留在业务方法中，
不为每个字段增加 setter。业务方法按执行顺序展开：开启事务、
加锁读取、检查权限、修改、写审计、提交后返回；共同事务只封装资源和审计边界，
不再把整段业务藏进通用回调。详见随附示例的[角色业务](../assets/postgresql-rbac/app/services/role_service.py)。

模型与 Schema 也按用户、角色、权限归组；用户角色绑定放在用户模型文件，
角色权限绑定放在角色模型文件。授权状态、授权审计分别有明确命名的文件。
`core/access/authorization_policy.py` 只放角色和用户共用的授权条件；同目录的
`role_policy.py` 管角色管理决策，`user_policy.py` 管用户管理和用户角色绑定决策。
`dependencies/rate_limit.py` 直接写明业务限流次数、时间窗口和 IP/用户 ID 维度；
`core/rate_limit/limiter.py` 负责 Redis 计数，429 响应头由异常处理模块组装。
[`core/access/permissions.py`](../assets/postgresql-rbac/app/core/access/permissions.py) 按业务分组定义
`PermissionKey` 和 `PERMISSION_CATALOG`；目录的值是 `PermissionSpec`，集中记录
名称文案键、明确的 `PermissionGroup` 分组和描述文案键，分组名称由 `PERMISSION_GROUP_NAMES` 维护。
[`core/access/roles.py`](../assets/postgresql-rbac/app/core/access/roles.py) 独立定义系统角色、等级、
角色数量上限和明确授权白名单；`core/access/authorization.py` 只定义身份与授权数据类型。
`api/v1/router.py` 统一添加 `/api/v1`，业务 Router 只声明 `/users` 等业务前缀。

这是一个单项目 FastAPI 后端基线，核心范围是：

- PostgreSQL 用户、角色和权限；
- 用户名和密码认证；
- 五种固定图形验证码；
- Redis 固定窗口限流；
- JWT Access Token 加 Redis 活跃 JTI；
- 统一响应、结构化运行日志和分层审计。

它只服务一个项目和一套授权边界，也不默认加入第二套 Token 刷新凭据、
PostgreSQL Token/会话表、邮箱或短信验证码、MFA、匿名忘记密码、在线超级
管理员交接、全站共享限流、国家表或代理检测。

## 一次请求如何通过系统

普通受保护请求依次经过：

```text
解析并限制 Bearer Token 大小
-> 校验 JWT 签名、固定 claims 和时间
-> Redis 确认该 JTI 仍然活跃
-> 原子增加“业务 + 当前用户 ID”计数，超过额度直接返回 429 且不查数据库
-> PostgreSQL 读取当前用户、token_version 和完整角色权限
-> 校验账号状态和 token_version
-> 校验精确权限、严格管理层级和资源可见性
-> 执行业务
-> 返回统一响应，并写一条请求完成日志
```

代码中的入口按用途直接命名，不再通过多层身份别名跳转：

| 入口 | 做什么 |
| --- | --- |
| `check_token` | 验证 JWT 和 Redis 登录记录，返回 `LoginInfo`；退出当前登录直接使用它 |
| `get_current_user` | 依赖 `check_token`，执行本人接口限流，再读取账号和角色权限，返回 `AuthorizationContext` |
| `require_permission` | 内部依赖 `check_token`，按接口选择限流，再读取账号和角色权限，最后检查指定权限；默认使用普通用户额度，管理业务显式传 `management=True` |
| `get_captcha_user` | 登录后验证码按用途限流，再读取当前账号和角色权限 |

只要求登录及账号可用的业务可用 `Depends(get_current_user)`，返回的是上下文，不是数据库的 `User` 对象。
本人信息接口使用 `Depends(require_permission(PermissionKey.ACCOUNT_READ))`，
本人改密使用 `Depends(require_permission(PermissionKey.ACCOUNT_CHANGE_PASSWORD))`。
有权限要求的普通业务使用 `Depends(require_permission(...))`，默认使用普通用户额度。
用户、角色和权限目录等管理业务显式写 `require_permission(..., management=True)`，
才选择管理额度；有接口权限不代表是管理员，不按角色名称选择限流。
其内部直接调用一次限流和账号读取，不再经过管理上下文依赖，
也不调用会再次计数的 `get_current_user`。
`context.login_info` 是已验证的登录信息，`context.user_info` 是数据库中的当前用户信息，
包含账号状态、有效角色、角色等级和权限。
本人、管理和登录后验证码三个入口共用 `check_token` 和 `_load_current_user`，
一次请求只限流一次、读取一次账号。
Service 在写操作持锁后仍会复查权限和目标状态。

退出当前登录是刻意保留的窄例外：路由直接使用 `Depends(check_token)`，
JWT 和 Redis 活跃 JTI 通过后立即原子删除当前 JTI，不限流、不读取限流客户端，
也不查询 PostgreSQL 或检查业务权限。这样账号
刚被禁用或 token_version 刚变化时，持有者仍能清理当前 Token。

登录和公开注册的顺序不同，但同样是失败关闭：

```text
可信来源 IP 和该业务的固定窗口限流
-> 校验并一次性消费对应图形验证码
-> 密码校验或注册事务
-> 仅登录成功时签发 JWT 并登记 Redis 活跃 JTI
```

无效、随机、过期或用途错误的验证码也已经消耗登录或注册额度；限流先拒绝
时不消费验证码，也不执行密码哈希、数据库写入或 Token 签发。
登录和注册验证码不绑定领取时的 IP，避免 VPN 或移动网络出口变化导致正常
用户无法继续；领取和提交仍分别按各自请求当时的可信 IP 限流。验证码仍严格
绑定业务场景、五分钟过期且只能消费一次，因此它只是防自动化措施，不是身份
归属证明。

## 账号和密码

新项目默认只使用 `user_name` 和密码。用户名强制去掉首尾空白，只允许
3 到 32 位 ASCII 英文字母、数字或下划线，并拒绝固定敏感名称。删除账号
使用软删除，原用户名永久保留，不分配给另一个人。用户名是否区分大小写是
生成具体项目时集中询问的一项产品决定。

密码哈希直接保存在 `users`，不额外创建凭据表，使用 Argon2id。新密码默认
8 到 32 位可见 ASCII 字符，必须同时有大写字母、小写字母、数字和英文特殊符号；
另外拒绝整串顺序、整串同一字符和与用户名完全相同的密码。规则统一在
`app/core/security/password_rules.py` 维护，注册、新增用户、本人改密和管理员重置
共用；`passwords.py` 负责哈希、比对和计算排队。登录和验证旧密码不检查新密码强度，
只限制输入非空、有效 UTF-8 且不超过独立的 1024 位上限。

公开注册不提供运行时开关。公开注册和管理员新增用户都只能绑定最低级 `user`
角色，客户端不能指定初始角色。

基础 Skill 没有匿名“忘记密码”接口。忘记密码时由有权限的管理员在线下核实身份，
再通过受保护接口重置。管理员直接设置可登录的新密码，并私下交付用户；接口和审计
不回显密码。重置仍撤销旧 Token，并与账号安全审计一起提交。管理员新增用户和唯一
`super_admin` 的可信主机线下恢复也直接设置可登录的密码，不要求第二次改密。

## 五种图形验证码

新项目固定要求以下五种用途，不能跨用途复用：

| 用途 | 保护的操作 | 验证码归属 |
| --- | --- | --- |
| `login` | 用户名密码登录 | 只绑定用途，不绑定 IP |
| `register` | 公开注册 | 只绑定用途，不绑定 IP |
| `admin_create_user` | 管理员新增用户 | 当前登录用户 ID |
| `admin_reset_user_password` | 管理员重置下级用户密码 | 当前登录用户 ID |
| `user_change_password` | 当前用户修改自己的密码 | 当前登录用户 ID |

每张图五分钟有效，只允许提交一次；答案正确、错误、用途错误或用户绑定错误
都必须原子删除该验证码。每次领取独立签发新图，不会因新图作废旧图；默认每个限流主体
10 次/5 分钟：未登录时按可信来源 IP，已登录时按当前用户 ID。领取时的 IP
限流不等于把验证码绑定到该 IP。邮箱验证码、短信验证码和 MFA 只有项目明确提出时才另行设计。

## JWT 和登录会话

用户标识统一叫 `user_id`：模型字段、请求与响应字段、JWT 和 Redis 会话记录
使用同一个名字。`current_user` 表示已经加载出来的当前用户对象；管理其他用户时，
用 `target_user_id` 区分被操作用户。审计也直接使用这两个字段：`user_id` 是
操作人，`target_user_id` 是被操作人；本人操作时可以相同。通用业务审计用
`source_type` 区分用户、服务、系统、任务和维护来源，非用户来源的稳定标识放在
`source_id`；`entrypoint` 单独说明从 HTTP、任务或线下命令等哪个入口执行。
`target_type`、`target_id` 说明被操作对象，例如退款或角色；对象是用户时，
`target_id` 必须与 `target_user_id` 相同，不再套一层身份对象。

默认 JWT 只包含 `user_id`、`jti`、`iat`、`exp`、`token_type`。`user_id` 是不可变
用户 ID，不是用户名；默认有效期 24 小时，生成项目时必须提醒使用者按业务
风险调整，高风险管理后台通常应缩短。Redis 活跃 JTI 可以提前撤销，但无法阻止
仍然活跃的被盗 Token 在到期前重放。`iss` 和 `aud` 只有使用者了解作用并明确
同意后才成对加入。

签名正确还不够。每个新 JTI 必须先登记到 Redis，后续请求也必须命中内容
完全匹配的活跃记录。退出当前登录会删除该 JTI；改密、管理员重置、禁用
账号或管理员强制下线通过增加 `users.token_version` 让该账号旧 Token 失效。

Redis 另外维护有效登录的 JTI 和登录时间，用于显示在线会话数量并在达到
项目选定上限时原子淘汰最早登录。这里记录的是登录会话，不代表物理设备。
每用户只用 `login:sessions:<user_id>` 和 `login:sequence:<user_id>` 两个键，
分别保存 JTI 字段对应的规范 JSON 与 `_version`，以及严格登录顺序。
键名直接使用规范 `U` + 14 位字符的 `user_id`，共 15 位；Hash 字段和排序成员
使用 JTI 的 `UUID.hex`，即 32 位小写十六进制字符，不对用户 ID 或 JTI 取摘要。
JWT 中的 `jti` 仍是标准带连字符的 UUID 字符串。
键名不带版本、大括号、服务名或环境名。到期时间直接读取记录的 `exp`：登录与在线
会话列表遍历该用户队列清理，代价为 O(n)，适合每用户少量登录；普通鉴权只在一次
Lua 往返中检查当前记录、版本和顺序索引成员。原子登录保留版本防倒退和容器最晚
到期时间，超限时按最早登录淘汰，不按最早到期淘汰。完整契约见
[JWT 实现](jwt-session-implementation.md)。
`core/security/jwt_tokens.py` 负责 JWT 字段、签名与验签，不访问 Redis；
`repositories/redis/login_session_repository.py` 负责 Redis 登录记录、
登录顺序、到期清理、检查和撤销；`AuthService.issue_access_token` 调用 JWT
签名和仓储登记，只有 Redis 原子登记确认成功后才返回 Token。
普通用户只能退出当前登录；只有有权限的管理员才能强制退出严格低级用户的
全部登录。系统只签发 Access Token；过期后重新登录，不增加 PostgreSQL
Token 或会话表。

## 角色和权限

系统角色固定为：

| 角色 | 等级 | 主要边界 |
| --- | ---: | --- |
| `super_admin` | 1000 | 唯一持有人；系统角色与权限结构不可在线修改 |
| `user` | 0 | 每个正常用户必须持有；包含查看本人信息、修改本人密码两项基础权限，无管理权限 |

不预置 `admin`。需要管理员时，创建 1～999 级普通自定义角色并按需绑定权限；
500 级不保留，`admin` 也只是可选的自定义角色标识，名称本身不授予能力。
一个用户最多有 10 个未解绑角色。多个角色的权限取并集、管理等级取最高值。
基础权限分别是 `account:read`、`account:change_password`；超级管理员的显式白名单也包含它们。
本人接口检查这些权限时仍使用普通用户额度，登录后验证码申请只要求登录和账号可用。
系统只使用明确的正向 `resource:action` 权限，不默认加入 deny、通配符、角色
继承或独立委派系统。

权限通过并不等于可以操作任何目标。普通管理员不能查看或修改自己、同级、
更高级或受保护用户，也不能授予自己没有的权限，不能直接或间接给自己提权。
隐藏目标与不存在目标使用相同的 `404` 行为，列表的行和总数也必须使用同一
可见性条件。

首位 `super_admin` 不是第一位注册者自动获得。目标用户先正常注册为
`user`，再由开发或运维人员使用不可变用户 ID，自行准备、审核并在可信环境执行
受保护的 PostgreSQL 事务完成绑定。以后交接同样在线下处理，没有在线交接接口。
Skill 说明必须满足的锁、权限和审计条件，不替使用者生成或执行初始化 SQL。

## 原子一致性和软删除

权限写入先锁定唯一 `rbac_state(scope='global')` 行，再按固定顺序锁定用户、
角色和关系，重新读取当前权限后才决定是否写入。业务变更、版本号和必须的
审计成功事件在一个 PostgreSQL 事务中提交；任一失败则全部回滚。Redis 和
外部 HTTP 不放进这个事务。

用户、自定义角色、业务实体以及角色/权限绑定关系的运行时删除使用软删除。
解绑关系保留旧 episode，再次绑定创建新 ID。审计表只追加，不能软删除；
`rbac_state` 是固定控制行，也不能删除。

## 限流

限流使用 Redis Lua 固定窗口，每个业务和主体只有自己的计数键，没有全站、
全用户或跨业务共享额度：

- 未登录认证入口：固定业务加可信来源 IP；
- 已登录接口：固定业务加服务端认证的当前用户 ID；
- 不使用请求体里的用户名、邮箱或目标用户作为匿名限流主体。

Redis 专供本服务使用。计数键固定为
`rate_limit:<业务名>:<主体类型>:<64 位 HMAC 摘要>`：`rate_limit` 是限流记录
的固定前缀；业务名来自服务端策略或稳定的接口处理函数名；主体类型只允许
`ip` 或 `user_id`；最后一段是完整的 64 个小写十六进制字符，不是原始 IP 或用户 ID。
例如 `rate_limit:login:ip:<摘要>` 表示某个可信 IP 的登录计数，
已登录接口的 `user_id` 指当前操作者，不是请求里选中的目标用户。

摘要使用 `RATE_LIMIT_HMAC_KEY` 作为 HMAC-SHA256 密钥；输入依次是
业务名、主体类型、规范化的可信 IP 或已认证的当前 `user_id`，三个 UTF-8 字符串
之间各放一个零字节（`\x00`），也就是
`业务名 + "\x00" + 主体类型 + "\x00" + 主体值`。输入不含键前缀、
应用名、环境名或额外命名空间，摘要不截断；构键和限流函数也不接收命名空间参数。
改用此键格式时，新键开始新的计数窗口，旧计数键按原 TTL 自然过期，
不兼容读取旧键，也不主动清理 Redis。验证码记录仍为 `captcha:<UUID>`；
额度、原子计数脚本和下述请求检查顺序不变。完整规则见[限流规范](rate-limiting.md)。

已登录接口先完成 JWT 验签和 Redis 活跃 JTI 校验，再原子增加该业务与用户的
窗口计数一次；超过额度直接返回 `429`，不访问 PostgreSQL。额度放行后才读取
PostgreSQL 当前账号与权限，并确认账号启用且 token_version 一致，再进入业务。
到达限流步骤的请求都计数，包括超限请求以及随后发现账号禁用或版本失效的请求，
本次次数不退回，也不会在账号校验后再次增加。伪造、过期或 Redis 已撤销的 Token
不计数、不查数据库；仍活跃的被盗 Token 在额度用满后不能反复压数据库。
数据库发现仍登记的旧 JTI 已经失效时，会尽力原子删除这一枚 JTI，让后续请求
直接在 Redis 层拒绝。如果该请求计数后已超限，本次会先得到 `429` 并跳过数据库
身份检查。已登录验证码领取也遵守这个顺序：按合法用途或无效用途窗口计数一次。

基线默认值包括：登录 20 次/5 分钟、注册 5 次/小时、每种验证码领取
10 次/5 分钟；已登录普通查询
600 次/分钟、普通写入 120 次/分钟、管理查询 300 次/分钟、管理变更
60 次/分钟。具体项目生成时要集中展示这些参数和修改位置，让使用者确认或
调整。Redis 无法可信判断时返回 `503`，不能静默放行。

## 响应、日志和审计

所有 API 使用真实 HTTP 状态和统一四字段 JSON：`code`、`message`、`data`、
`request_id`。`code` 是数字业务码；`request_id` 由服务端生成，并在响应头、
响应体和运行日志中一致。

运行时给用户看的接口文案默认支持简体中文和英文。不传语言时返回 `zh-CN`；
客户端可用标准 `Accept-Language: en` 请求英文。响应会返回规范化的
`Content-Language`，并设置 `Vary: Accept-Language`，避免缓存串语言。成功、
业务错误、参数校验、认证、权限、验证码、限流和健康探针的 `message` 都从稳定
消息键翻译；HTTP 状态、数字业务码、字段名、`data` 中的机器值、权限键、日志
事件名、审计动作和内部原因码不翻译。增加第三种语言只需登记固定语言代码、补一份
完整资源文件和测试，不增加数据库字段，也不能把请求头直接拼成文件路径。
数据库中由业务人员维护的内容和源码里的静态 Schema 说明也不由运行时消息模块翻译。
权限目录的 `name`、`group_name` 和内置 `description` 使用请求语言：权限列表和详情
将 `locale_for_request(request)` 传入 `PermissionService`，从同一元数据目录和两份语言资源
组装结果；`key` 和 `group_key` 始终保持原值。
初始化描述调用 `get_permission_description(key)`，默认得到中文，不把目录里的文案键
直接存成描述。新增业务权限必须同时补齐中英文名称、说明和相应分组名称；非内置权限
以原权限键作为名称，归入 `other`（其他）组，数据库自定义描述原样返回。

权限目录条目还返回 `api_routes`，每项只有 `method` 和完整 `path`。启动时沿实际路由
和权限依赖收集一次，去重排序后保存到 `app.state.permission_api_routes`；查询只读内存。
关联表示接口入口明确要求该权限，后续仍须检查目标等级、保护和状态。没有对应 HTTP
入口时返回空数组，不代表权限无效；这些展示信息不增加数据库字段。

这不是只有文档的约定，随附资产已经包含完整调用链：

- [`app/core/i18n/messages.py`](../assets/postgresql-rbac/app/core/i18n/messages.py)：消息键、目录校验与翻译；
  `translate_for_locale(locale, key)` 支持显式语言翻译；
- [`app/core/i18n/language.py`](../assets/postgresql-rbac/app/core/i18n/language.py)：请求语言选择和响应语言头；
  [`app/core/i18n/validation_messages.py`](../assets/postgresql-rbac/app/core/i18n/validation_messages.py)：安全的参数错误提示与字段位置；
- [`app/assets/locales/zh-CN.json`](../assets/postgresql-rbac/app/assets/locales/zh-CN.json) 和
  [`app/assets/locales/en.json`](../assets/postgresql-rbac/app/assets/locales/en.json)：两份等键资源；
- [`app/core/response.py`](../assets/postgresql-rbac/app/core/response.py)：统一响应；
  [`app/core/codes.py`](../assets/postgresql-rbac/app/core/codes.py)：五位业务码；
  [`app/core/exceptions.py`](../assets/postgresql-rbac/app/core/exceptions.py)：业务异常；
  [`app/core/exception_handlers.py`](../assets/postgresql-rbac/app/core/exception_handlers.py)：异常响应；
  [`app/core/middleware/request_logging.py`](../assets/postgresql-rbac/app/core/middleware/request_logging.py)：请求语言和响应头；
  [`app/core/middleware/request_body_limit.py`](../assets/postgresql-rbac/app/core/middleware/request_body_limit.py)：进入路由前限制请求体实际字节数；
  [`app/core/middleware/security_headers.py`](../assets/postgresql-rbac/app/core/middleware/security_headers.py)：统一基础安全响应头；
  [`app/main.py`](../assets/postgresql-rbac/app/main.py)：生命周期与以上模块的装配；
- [`tests/test_i18n.py`](../assets/postgresql-rbac/tests/test_i18n.py)：语言协商、成功与
  失败响应、参数错误、响应头和并发隔离测试。

调用顺序是 `Accept-Language -> request.state.locale -> MessageKey -> translate()`，
最后把翻译后的 `message`、`Content-Language` 和 `Vary: Accept-Language` 返回给客户端。
详细扩展步骤以 [API 多语言](api-internationalization.md) 为唯一规范。

运行日志是同时输出到控制台和文件的单行结构化 JSON，用来排查请求、依赖、耗时和
未捕获异常。`core/logging/details.py` 旁观有限收发，提供脱敏请求/响应摘要、
操作人、被操作人、目标角色和动作；无信息的固定字段为 `null`。
它不是数据库审计记录，不能包含密码明文或数据库哈希、Token、JTI、验证码答案、
未脱敏正文、数据库/Redis URL 或代理凭据。四种设置新密码操作额外记录独立
`LOG_HMAC_KEY` 计算的 HMAC-SHA256 前 32 个十六进制字符，不指纹登录或旧密码。
文件日志没有 `target_type`/`target_id`、服务名、服务版本或环境字段；
数据库审计的目标字段仍然保留。详细字段及带注释案例见[日志规范](operational-logging.md)。

文件保存在项目根目录 `logs/北京时间日期/app.log`，首次写入时自动创建，跨天
自动换文件，重启后追加。修改 `app/core/logging/output.py` 的 `LOG_ROOT_DIR`
可更换位置；`LOG_LEVEL` 同时控制控制台和文件，正常成功请求使用 INFO。
`.env` 的 `LOG_FILE_MAX_MB=100` 控制单文件大小，1 MB 按 1024 × 1024 字节计算，
修改后重启。下一条日志将超出大小前切换到当天的 `app.1.log`、`app.2.log`，
重启继续使用最新序号，跨天重新编号；切分不覆盖或删除旧日志。
两处输出都安全格式化并限制单条最多 16 KiB；文件写入失败不影响控制台和接口结果。
默认直接写入并刷新，没有后台队列或自动删除历史文件；慢速磁盘或控制台可能延迟
当前请求。文件日志不代替数据库审计，审计仍遵守原来的事务要求。完整行为见
[运行日志](operational-logging.md)。

默认审计只有一张 `operation_audit_events`，由 `AuditService` 统一写入。
`category=account` 记录注册、管理员新增、改密和密码重置；
`category=permission` 记录角色、权限、用户状态等管理操作。
注册及管理员新增各写一条账号审计，包含默认角色绑定结果，不重复写创建审计。
普通查询仅写文件日志；订单、余额等业务审计按真实需求另行接入。

内置授权与账号安全动作在 `app/core/audit.py` 的 `RbacAuditAction`、
`AccountAuditAction` 分组维护，成员附中文说明，业务调用 `audit_success` 或
`audit_denied` 时直接传枚举成员。写入器自动判断分类、当前用户、来源和关联 ID，
业务只填写动作、目标、响应及必要的前后状态，不再逐项拼装审计对象。
动作值保持稳定且不翻译；动态接口拒绝和项目自定义业务动作仍沿用各自的校验边界。

统一表保留脱敏后的 `request_data`、`response_data`、新密码比较指纹及必要的
变更前后状态。摘要复用文件日志白名单，最多采集 16 KiB、保存 4 KiB；敏感值
替换为 `[REDACTED]`。响应是提交前的业务结果快照，不保证客户端已收到。
完整字段见[操作审计](audit-module.md)。

`business_audit_events` 的模型和写入工具是可选 Skill 资源，默认不注册、不生成。
只有项目先确认动作目录、允许字段、结果和保留策略后才接入。
基础设计没有审计投递 outbox、Worker、
租约、重试或死信系统。

## 主要 PostgreSQL 表

| 表 | 作用 |
| --- | --- |
| `users` | 用户名、密码哈希、账号状态、软删除和 Token 撤销版本 |
| `roles` | 系统角色和自定义角色定义、等级、状态、版本和软删除 |
| `permissions` | 稳定权限目录 |
| `user_roles` | 用户角色绑定 episode、绑定信息和解绑墓碑 |
| `role_permissions` | 角色权限绑定 episode、绑定信息和解绑墓碑 |
| `rbac_state` | 权限写入共用的唯一全局行锁 |
| `operation_audit_events` | 只追加的账号安全及权限管理审计，共 16 个字段 |

当前 `rbac_state` 只有一个非空字段 `scope`，固定记录为 `global`。
权限写操作先锁住这行再复查当前权限；普通认证不读取它，也不返回全局权限版本。
验证码、限流计数和活跃 JTI 存在 Redis，
不为它们创建 PostgreSQL 表。

## 可选健康探针

默认项目不包含 `/health/live`、`/health/ready` 或健康检查模块。只有使用者明确
要求时才按需添加，并限制内网或受信探针访问。

按需添加时，liveness 只检查进程是否能响应，readiness 根据实际部署依赖判断
是否可接收流量。依赖检查须有短超时，只返回整体结果，不暴露组件状态、连接地址、
凭据、Redis Key 或内部异常；不得创建表、补种数据或修复数据库。数据库结构与
初始化仍由使用者完成，探针结果不能代替数据库约束和触发器验收。

## 主要接口组

- 认证：图形验证码、注册、登录；退出当前登录也归此组，但必须认证；
- 当前用户：本人信息、登录后验证码、本人改密、当前权限、会话列表；
- 用户管理：列表、详情、新增、启用/禁用、密码重置、强制下线、绑定/解绑角色；
- 角色管理：列表、详情、创建、更新、启用/禁用、软删除、绑定/解绑权限；
- 权限：列表和详情。

除明确列出的公开认证入口外，普通业务查询、业务
修改和管理接口默认都必须登录。公开路径和响应字段不使用 `rbac` 名称，避免
把内部授权实现暴露成外部 API 设计。

新业务接口只使用 GET 和 POST。GET 列表以 `/list` 结尾，详情以 `/detail`
结尾，ID、筛选、分页放在查询参数中，例如
`GET /api/v1/roles/detail?role_id=<id>`。POST 用动作路径，ID 与其他字段放在
同一个严格 JSON 请求模型中，例如 `POST /api/v1/users/disable` 的请求体是
`{"user_id": "<id>"}`，不再把 ID 放在路径段里。未知 JSON 字段会被拒绝。

角色列表 `GET /api/v1/roles/list` 可按 `role_id`、`key` 精确匹配，按 `name` 包含匹配
（`%`、`_` 是字面字符），并按 `is_active`、`is_system` 筛选；后两项不传时包含两种状态。
`is_deleted` 默认 `false` 只查未删，`true` 只查已删。所有条件与权限、等级和保护范围按 AND
用于列表及 `total`；普通调用者仍只看低于自己、未受保护的非超级管理员角色，超级管理员
可看所选删除状态全部角色。已删条目只有基本信息和空 `permissions`，不加载旧授权；详情
仍排除已删角色，不新增恢复或删除接口。具体契约见
[角色列表规范](postgresql-rbac-implementation.md#minimum-public-api)。

这是便于使用和维护的约定，并不代表 ID 放在 JSON 里就能防攻击。攻击者仍能
修改查询参数和请求体，所以登录验证、精确权限、目标可见范围、严格管理层级、
参数化 SQL 和敏感信息脱敏都必须保留。密码、Token、验证码答案不能放入 URL。
健康探针不是列表或详情，保留原路径；已有项目未授权改接口时保留原契约。

## 项目目录与代码复用

先区分项目情况：空目录且尚无既定框架时，可以采用下方默认方案；使用者另有
目录方案时尊重其选择。已有项目（包括已经搭了一部分的项目）沿用原框架、目录、
调用方式和基础设施，只接入本次需要的功能。已有仓库里的空业务目录仍属于原项目，
不能当成全新服务。调用 Skill 或要求新增功能、修复、优化，不等于同意整体重构；
只有使用者明确要求时，才在约定范围内调整架构，也不能直接用随附模板覆盖原项目。

采用默认方案的新项目先按职责分目录：接口放 `api`，配置、安全和日志等放 `core`，数据库连接
放 `db`，FastAPI 依赖放 `dependencies`，表模型放 `models`，查询放
`repositories`，输入输出契约放 `schemas`，业务与事务放 `services`。
`app` 顶层只保留 `main.py` 和 `__init__.py` 两个 Python 文件。业务变多后，
接口在 `api/v1/endpoints/` 内按业务命名；业务逻辑文件使用 `_service.py` 后缀，
查询文件放在数据库子目录内并使用 `_repository.py` 后缀。模型也按数据库分类。

这些目录负责归类实际代码，不预建没有职责的文件。默认业务链是 API → Service → Repository：
权限目录这样的小业务也由 Service 负责分页和不存在处理，Repository 负责 SQL。
认证依赖和健康探针属于基础设施，不强行绕进业务 Service；已有框架仍保留原调用约定。
Service 保留事务和查询时机，可以直接给已锁定模型的字段赋值，无需逐字段包装；
列表与计数共用同一筛选范围。模型不依赖 Service。随附多语言资源确实使用
`app/assets/locales`；维护资产中的线下恢复命令不复制进新项目。没有任务
就不建 `workers`，没有合适的通用行为就不建 `utils`。
小项目与多业务示意见[项目目录规范](project-structure.md)。

新增函数前先找现有实现。两处代码如果代表同一条规则、以后改规则时必须一起改，
就优先通过少量有意义的参数共用实现。例如启用和禁用角色保留各自接口，但直接调用
同一个 Service 方法，不再增加一层只转发参数的函数。

只有一次使用的简单转换通常直接写在调用处。安全校验、事务、资源清理、复杂算法
和 FastAPI 依赖适配即使只有一个调用者，也可以保留独立函数。权限、审计或失败
处理不同的流程不能只因为代码长得像就硬合并，也不提前为假想需求建立万能工具类。
具体判断与验证方式见[复用与抽象规范](reuse-and-abstraction.md)。

## 代码可靠性与部署边界

本 Skill 重点规范代码组织、复用、校验、权限、安全、事务、异常、日志审计及测试。
不停机发布、生产容量、集群运维、监控平台和恢复演练由使用者按项目需要决定，
不作为普通功能开发的前置条件，也不把未实现这些能力当作 Skill 的默认缺陷。

新项目默认一个单机 PostgreSQL 和一个单机 Redis，只填两个连接地址；登录状态、
验证码和限流共用 Redis。内置代码只实现单入口 PostgreSQL 和单机 Redis，
不生成 Sentinel、Cluster、读写分离或节点发现配置；已有项目保留原拓扑。
使用者以后要接集群时，需要在具体项目中自行设计和验证客户端适配。
代码保持
连接池、有限等待、坏连接清理和正确的事务错误处理，断线后不能盲目重试写入。
不默认增加读写分离；需要独立限流 Redis 时只能额外填写一个单机 URL。
单机连接示例见[Redis 连接配置](redis-connections.md)。会话登记和验证码替换
仍通过 Redis 原子脚本执行；这不是全站限流额度。

连接数按进程累计，参数在 `app/core/config.py` 和 `.env.example`。多进程共用
数据库、Redis、密钥和会话规则；Token 活跃状态不能缓存到单个进程里。授权写锁
只保护对应业务，不能把无关写入都挂上去。已有有界日志输出和资源清理继续保留。

验证针对修改的代码边界开展；已有独立进程、数据库超时和并发测试继续保留。
GET 压测工具只在实际性能任务中按需使用，不能用短样本承诺生产吞吐或高可用。
调整连接池、超时或共享状态时再读[容量与可用性](application-capacity-and-availability.md)。

## 按需扩展

国家目录和代理可用性检测只是在项目已经使用本 Skill 时可选择的扩展。普通
地区字段、代理 CRUD 或无权限系统的通用 FastAPI 项目不会自动加载或实现它们。
需要时分别读取 [国家目录](country-catalog.md) 或
[代理可用性检测](proxy-availability-detection.md)。

## 版本和验证边界

当前新项目交付遵循[精选生成与交接](new-project-delivery.md)：模型由 Skill 负责，
迁移文件由使用者自己生成、审核和执行，基础数据也由使用者自行准备。
不复制维护仓库的迁移历史、SQL、初始化命令、整套回归测试或缓存；不会在启动时建表。
`from app.models.postgres import Base` 可得到全部模型 metadata，但不会自动安装触发器。
具体数据库保护和初始角色/权限要求见[模型与数据库交接](migrations.md)。

官方验证环境是 Python 3.12、PostgreSQL 17、Redis 7。其他版本可以由具体
项目自行验证，但不能描述为本 Skill 已验证。新项目先做离线验证；真实集成验证使用
使用者已准备且明确授权的测试环境，不为通过测试而代建或迁移数据库。
维护仓库历史测试需要的空白隔离环境不属于新项目自动交付流程。

已发布的 `v0.7.0` 当时未改变数据库结构；当前模型已移除用户权限计数
`authz_version`。`v0.5.0` 已发布的 `0001` 到 `0004` 属于维护仓库的不可变
历史，保留原有列和更新语句，不代表当前模型仍使用它，也不是新项目的迁移文件。
已有数据库结构变化由使用者维护自己的向前迁移；本次不生成或执行迁移，
不得改写其已执行的历史。

单纯更新 Skill 不会更改已有网站。只有把当前未发布的两键会话实现部署到已有
项目时，原登录才会失效，需要用户重新登录一次；旧键按已有 TTL 自然过期，
不双读旧布局或主动清理旧键。变更后的限流键重新开始计数。
这是 Redis 记录布局调整，不会删除账号、角色、权限或审计数据。默认仍是单机
PostgreSQL 加一台共用的单机 Redis，不要求使用者启用集群。

需要实施细节时按任务读取：

- [PostgreSQL RBAC](postgresql-rbac-implementation.md)
- [本地密码认证](local-password-authentication.md)
- [JWT/JTI 安全](jwt-session-security.md)
- [图形验证码](verification-and-abuse-defense.md)
- [限流](rate-limiting.md)
- [容量与可用性](application-capacity-and-availability.md)
- [API 多语言](api-internationalization.md)
- [运行日志](operational-logging.md)
- [RBAC 审计](audit-module.md)
- [业务审计](business-audit-module.md)
- [测试](testing.md)
