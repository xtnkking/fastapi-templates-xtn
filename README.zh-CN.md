# fastapi-templates-xtn

[English](README.md) | **简体中文**

`fastapi-templates-xtn` 是一个具有明确安全基线的 Codex Skill（技能），用于构建
和加固 FastAPI 服务。它涵盖单项目范围的 PostgreSQL 基于角色的访问控制
（RBAC）、严格的管理权限层级、非顺序标识符、由 Redis 活跃 JTI 门禁保护的
最小化 Access Token、具备事务一致性的授权写入，以及可配置的 API 限流、登录/注册
防滥用；只有使用者明确选择时才加入验证码等可选增强能力。

## 当前状态

`v0.4.0` 是当前正式版本。它在 `v0.3.0` 单项目 RBAC 基线之上，加入 Redis 门禁
认证及下述安全和应用契约。`v0.1.0` 仍是历史上的第一个公开预览版。本版在可运行
资产中加入仅使用 Redis 的活跃 JTI 门禁，且
没有逐 Token 的 PostgreSQL 表，同时将首位超级管理员的 Python 引导替换为由
操作者执行的 SQL 事务，并把带业务前缀的随机 ID 作为新项目首选、继续兼容
UUIDv4；同时增加数字业务码统一响应、服务端必填请求 ID、简单页码分页和请求体
资源版本并发控制、安全的结构化运行日志、强化的只追加 RBAC 审计模块，以及相互
独立且可复用的业务审计规范和 PostgreSQL 资产；还要求绿地项目先明确 `users`
存储邮箱、`user_name` 或两者，再分别确定各创建流程的必填规则、登录输入、规范化、
唯一性、跨字段歧义和删除后复用。所有允许运行时移除的可变数据，包括用户、自定义
角色、业务实体和关系解绑，都统一写入软删除墓碑，恢复时不复活旧权限。
当前默认 Access Token 只包含 `sub`、`jti`、`iat`、`exp` 和 `token_type`；
`iss` 与 `aud` 只能成对启用。新项目必须先用大白话说明它们可防止 Token 被错误的
服务接受，但会增加签发方与验证方的配置协调，并取得使用者明确同意；未回复不算同意。
存量项目已经配置这两个声明时默认保留。每个用户同时最多只能有 10 个未解绑角色，
`user`、`super_admin` 和已禁用角色都计数，软删除历史不计数；服务层与 PostgreSQL
都会在并发下强制该上限。普通管理员现在只能列出或查看有效权限层级严格低于自己的
未删除用户和角色，`super_admin` 可以读取全部未删除条目；列表通过批量查询装配，
用户响应区分已分配角色与生效角色，禁用角色保留分配但不产生当前权限。认证启动会
拒绝公开示例和明显薄弱的 JWT 密钥，Bearer Token 的输入与生成输出都限制为 4096 个
UTF-8 字节，并新增 `POST /api/v1/auth/logout-all`，通过递增 `users.token_version`
使该账户的全部 Token 在后续认证时失效。本版还加入全局 API 入口限流、认证后
用户限流，以及可以直接接入的 Argon2id 用户名密码注册、登录、本人改密、管理员找回和
临时密码完成流程；一次性邮箱/短信验证码服务仍默认关闭。
登录失败只形成会过期的私有风险信号，不能单独锁住账号；真正阻止登录请求的只有 IP、
IP+规范化账号和系统总量限制。生成某项控制前，Skill 必须展示该项目实际会用到的完整
默认次数，并让使用者接受默认值或列出需要修改的值。CAPTCHA、邮箱/短信验证码和 MFA
只有在使用者明确选择后才会加入。生成认证代码前，Skill 会一次性询问身份与登录字段、
注册方式、找回凭据、多设备登录和已有账号接入这几项会改变产品行为的问题，并附上默认
答案；密码算法、事务和撤销安全细节不会丢给使用者选择。公开契约统一使用
`super_admin`，不暴露
`is_super_admin` 或 ownership 术语，并移除两个未使用的权限键。项目初始化会询问是否分离
PostgreSQL 迁移与运行时角色，但这只是有专业运维支持时的可选生产加固，不会阻挡
小型或学习项目。在验证目标部署的身份提供方假设和 PostgreSQL/Redis 集成行为前，
不得将经过适配的服务描述为生产就绪。

## 上游来源与署名

本项目是在 [`wshobson/agents`](https://github.com/wshobson/agents) 项目的
[`fastapi-templates`](https://github.com/wshobson/agents/tree/47a5dbc3f9c2661c6afb13638f80d4a4d4449040/plugins/api-scaffolding/skills/fastapi-templates)
Skill 基础上独立维护的扩展，所依据的上游提交为
`47a5dbc3f9c2661c6afb13638f80d4a4d4449040`。

上游作品 Copyright (c) 2024 Seth Hobson，并按 MIT License 使用。XTN 的改动
增加了 PostgreSQL RBAC 模型、应用级管理权限层级与防止自我提权的规则、
原子授权写入、非顺序标识符策略、最小化且可撤销的 JWT 指南、结构化请求日志和
相互独立的持久 RBAC 与业务审计控制，以及可配置的限流、登录/注册防滥用和可选验证码
基础能力。本项目与上游
项目之间不存在从属、赞助或背书关系。完整署名和许可信息请参阅英文法律原文
[NOTICE](NOTICE) 和 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## 提供的能力

- 面向 PostgreSQL 的单项目正向授予 RBAC。
- 严格的管理权限级别，拒绝同级、向上、受保护身份，以及直接或间接
  自我提权操作。
- 普通管理员只能列出、查看或操作有效权限严格低于自己的未删除用户与角色，
  `super_admin` 可以查看全部未删除用户与角色。缺少操作能力时先返回 `403001`；能力
  通过后，被隐藏的目标或请求中的隐藏角色 ID 与未知 ID 一样返回 `404001`；目标可见
  但不满足委派或影响范围规则时仍返回 `403001`。
- 角色和用户列表使用批量查询装配，查询数量不会随页面大小增长。用户响应分别公开
  已分配角色和生效角色；禁用角色仍处于已分配状态，但不贡献任何当前权限。
- 每个用户最多 10 个未解绑角色：必需的 `user`、可能持有的 `super_admin` 和已禁用
  角色都计数，软删除历史不计数；服务层在权威锁内校验最终集合，PostgreSQL 还会
  阻止直接 SQL 和并发写入绕过上限。数据库防线直接属于全新的 `0001` Schema，
  `0004_password_auth` 是唯一迁移 head。
- 绿地项目必须先明确 `users` 存储邮箱、`user_name` 或两者，再分别确定各创建流程的
  必填规则、登录输入、规范化、唯一性、命名空间歧义和删除后复用策略；存量项目默认
  保留既有身份契约。JWT `sub` 与首位超级管理员引导始终只使用不可变的 `users.id`。
- 所有允许运行时移除的可变数据都采用软删除，包括用户、自定义角色、业务实体和关系
  解绑；父对象与活跃关系原子写入墓碑，重新绑定创建新的关系记录，恢复不会复活旧
  权限。系统角色和固定权限目录没有运行时删除命令，审计记录保持只追加，
  `rbac_state` 永不可删除。
  这是产品每个实际开放生命周期操作都必须遵守的规范。随附资产直接实现自定义角色
  软删除、用户角色解绑和角色权限解绑；用户、权限目录及业务实体的删除/恢复仍是需要
  产品明确接入的适配点。
- 初始化时询问是否分离 PostgreSQL 迁移角色与运行时角色。有专业运维支持时可将分离
  作为生产加固；缺少这类支持的小型或学习项目不得因此被阻断。PostgreSQL owner 或
  superuser 直接执行 SQL 仍可绕过应用软删除，不属于应用能够保证的范围。
- 使用非顺序标识符代替容易枚举的自增 ID。新项目优先采用“已登记的业务前缀 +
  按生命周期体量选择长度的随机大写后缀”，例如低体量用户命名空间可采用 `U` +
  10 位；已有 UUIDv4 方案和随附的 UUIDv4 资产仍然受支持。Access Token JTI
  继续使用 UUIDv4。
- 首位 `super_admin` 使用由操作者执行的 PostgreSQL 脚本：先通过正常流程创建目标
  账户，再由使用者本人从可信主机运行带全局锁、审计和完整回滚的角色绑定事务。
- JWT 默认只携带 `sub`、`jti`、`iat`、`exp`、`token_type`，不携带角色或资料字段；
  `iss` 与 `aud` 是成对的可选加强项，只有先用大白话解释利弊并取得使用者明确同意
  后才可加入，未回复不算同意，存量项目已配置时默认保留。Access Token 默认有效期
  可配置且为一小时。启动时拒绝公开示例和明显薄弱的 JWT 密钥，接收的 Bearer Token
  与生成的 Token 都不得超过 4096 个 UTF-8 字节。每个请求先经过必需的 Redis 活跃
  JTI 门禁，再复用现有 PostgreSQL 用户与 RBAC 查询，不增加逐 Token 的数据库表或
  查询。`POST /api/v1/auth/logout-all` 会递增 `users.token_version`，使该账户的全部
  Token 在后续认证时失效。
- 两层 API 限流：最外层 ASGI 先按系统总量和可信客户端 IP 做保护，认证后再按稳定的
  操作分类限制当前用户。一个请求涉及的多个桶会在 Redis 中原子判断；真正超限返回
  HTTP `429`、业务码 `429001` 和 `Retry-After`，限流 Redis 无法可靠判断时关闭放行并
  返回 `503001`。Redis Key 使用 HMAC，不包含原始 IP 或用户 ID。参考资产和 CI 使用
  独立的限流 Redis，把高基数限流和已启用的验证码状态与活跃 JTI 隔离；小型部署可以明确接受
  风险后共用一个 Redis。`APP_ENVIRONMENT` 是没有代码默认值的必填项，遗漏时启动直接
  失败。只有明确标记为本地或测试的环境才允许设置 `RATE_LIMIT_ENABLED=false`；其他
  环境启动时直接拒绝，因为关闭它也会绕过认证防滥用流程，不能把它当作部署模式。
- 完整的本地密码认证和可复用防滥用 Service。资产提供在线程外执行的 Argon2id、软删除
  的密码凭据事件、真实或 dummy 校验、按需开放的注册与登录、本人改密、只能针对严格低层用户的
  管理员重置、一次性临时密码完成流程，以及唯一 `super_admin` 的离线找回。每次成功
  轮换密码都会递增 `users.token_version`，并与账号安全审计在一个 PostgreSQL 事务中
  提交，使旧 Access Token 在下次请求时失效。用户名本身不能证明账号归属。系统只使用
  一个短期 Access Token，到期后用户重新登录，不增加逐 Token 的 PostgreSQL 表。登录只用 IP、IP+规范化账号和系统
  总量作为硬限制。
  登录失败次数会原子写入一个自动过期的私有风险信号，但它本身不能拒绝请求，也不能
  阻止系统校验正确密码。
  公开注册默认不会出现在 API 和 OpenAPI 中；只有产品负责人明确选择后，才启用
  `PUBLIC_REGISTRATION_ENABLED`。
  注册使用独立的 IP、目标、组合及系统额度，并且绝不接受调用方指定角色。随附的
  `IdentityAbuseFlow` 会固定“先检查准入、再执行真实或假密码校验、随后记录失败或清理
  成功状态”的登录顺序，并保证注册业务动作只在限流通过后运行，避免产品路由漏掉关键步骤。
- 默认关闭、按需启用的邮箱/短信验证码流程：使用 `secrets` 生成六位验证码，绑定用途、渠道和目标，
  Redis 只保存 HMAC，默认 5 分钟失效、最多输错 5 次，重发会原子替换旧验证码，并保证
  成功验证码只能消费一次。资产提供编排 Service 和发送适配器接口，不会在尚未明确用户
  身份契约时擅自选择供应商或伪造公开登录/注册接口。纯用户名密码项目不需要它的身份
  字段、密钥、路由或供应商。完整资产会以 `VERIFICATION_ENABLED=false` 保留这套已测试
  但休眠的代码，不要求使用者决定是否删除文件，也不会因此暴露验证码 API；CAPTCHA 和
  MFA 同样必须由使用者明确选择并单独接入。
- 面向高权限写入的事务、锁顺序、审计、撤销和乐观并发
  控制要求；拒绝审计写入失败时，仍保留原始 HTTP `403`、`404` 或 `409` 结果。
- 统一的 JSON API 契约：真实 HTTP 状态码、六位数字业务码、服务端生成的必填请求
  ID，以及刻意保持简单的页码分页。公开响应与 OpenAPI 统一使用 `super_admin` 术语，
  不暴露 `is_super_admin` 或 ownership，并从固定权限目录移除未使用的
  `roles:permissions:update` 与 `system_owner:transfer`。
- 安全的单行 JSON 运行日志：包含请求关联、稳定事件字段、有界序列化、敏感信息
  防御性脱敏，并且每个请求只产生一个规范的完成事件。
- 专用且只追加的 `rbac_audit_events` 契约：包含可信事件来源、载荷版本、有界白名单
  前后状态、数据库约束、事务规则、归档策略，以及 PostgreSQL 更新/删除/清空防护，
  不提供软删除路径。
- 独立且按需读取的
  [业务审计契约](skills/fastapi-templates-xtn/references/business-audit-module.md)，以及可复用的
  `business_audit_events` PostgreSQL 模型、迁移和写入器：只记录事件目录明确列出的
  重要动作，区分成功、失败和拒绝，并由调用方在同一事务中提交成功的业务修改及其
  审计证据。
- 按需读取的
  [本地密码认证规范](skills/fastapi-templates-xtn/references/local-password-authentication.md)，
  包含少量关键业务问题、密码与凭据模型、完整接口流程、人工及离线找回边界、原子
  账号安全审计、限流和验证矩阵。
- 面向现有代理管理模块的
  [可选代理可用性检测实现指南](skills/fastapi-templates-xtn/references/proxy-availability-detection.md)，
  涵盖 Redis 最近结果回显，以及受控并发的单个和批量检测。它是按需读取的指南，
  不是 RBAC 参考资产内置的功能。该指南已包含在 `v0.2.0` 中，但不属于
  `v0.1.0`。
- 按需读取的
  [国家/地区目录规范](skills/fastapi-templates-xtn/references/country-catalog.md)、
  [PostgreSQL 实现示例](skills/fastapi-templates-xtn/references/country-catalog-postgresql.md)
  和只读 CSV 校验器。该规范明确使用 alpha-2 国家码自然主键、字符串国际区号、
  PostgreSQL 类型化时间、软删除、不会暗中恢复数据的原子导入、仅返回有效数据的
  读取接口，以及可选管理边界。默认 RBAC 资产不会创建该表，仓库也不捆绑第三方
  国家数据集。正式导入只要存在非空 `flag_url`，就必须显式提供经批准的 ASCII DNS
  主机名白名单；`--structure-only` 会报告 `membership_checked=false`，绝不代表数据
  已获准导入。
- 可运行的 FastAPI、SQLAlchemy、Alembic 和 PostgreSQL 参考资产，并配有聚焦
  于策略与集成行为的测试。

## 默认安全次数

完整且权威的初始配置表位于
[rate-limiting.md](skills/fastapi-templates-xtn/references/rate-limiting.md)。开始实现前，
Skill 必须展示当前所选功能适用的完整表格，并且只问一个问题：接受全部默认值，还是只
列出需要修改的值；未回复不能当作同意。可选验证码只有在使用者主动选择后才展示相关
次数。主要默认值如下：

| 范围 | 初始值 |
| --- | --- |
| API 入口 | 系统总量 `6000/分钟`、突发 `1000`；每个可信 IP `1200/分钟`、突发 `200` |
| 读写接口 | 匿名读取 `120/分钟`；认证读取 `300/分钟`；管理读取 `120/分钟`；普通写入 `60/分钟`；权限写入 `30/分钟` |
| 高风险账户操作 | `super_admin` 移交 `3/小时`；全部退出 `5/10分钟` |
| 登录 | IP `20/5分钟`；IP+账号 `5/15分钟`；系统突发 `200`、按 `1000/5分钟` 补充；失败风险信号最多保留 `24小时`，但不能单独拒绝登录 |
| 注册 | IP `5/小时`；规范化目标 `3/小时`；IP+目标 `3/小时` |
| 可选发送验证码 | 启用后，`verification_target_average`：同一目标 `60秒` 一次，初始有 5 次额度，之后平均每 24 小时持续补充 5 次；IP `20/小时`；IP+目标 `5/小时` |
| 可选校验验证码 | 启用后，IP `120/小时`；目标 `20/小时`；IP+目标 `10/小时` |
| 可选验证码 | 默认关闭；启用后为六位、有效期 5 分钟、输错 5 次后立即失效 |

这些值只是安全起点，并不是所有生产环境都必须一样。使用者可以根据正常流量、风险、
共享网络用户数量和供应商额度调高或调低；系统总量和供应商总量必须结合真实部署再次
确认，不能不沟通就直接照搬。目标平均桶不会在每天零点清零，也不承诺任意连续 24 小时
内绝对不超过 5 次。纯用户名密码服务不需要 CAPTCHA、邮箱/短信渠道、MFA 供应商或
验证码 HMAC 密钥。

## 安装

仓库中的 Skill 位于 `skills/fastapi-templates-xtn`。若要安装当前稳定的单项目
版本，请向 Codex 输入：

```text
Use $skill-installer to install the skill from
https://github.com/xtnkking/fastapi-templates-xtn/tree/v0.4.0/skills/fastapi-templates-xtn
```

若要安装历史 `v0.1.0` 预览版，请改用其不可变标签：

```text
Use $skill-installer to install the skill from
https://github.com/xtnkking/fastapi-templates-xtn/tree/v0.1.0/skills/fastapi-templates-xtn
```

安装器会将目录放入已配置的用户 Skill 位置；若同名目录已经存在，安装器会停止，
不会覆盖。Codex 通常会自动检测新安装的 Skill；若没有显示，请重启 Codex。
需要可复现安装时，请使用不可变的 `v0.4.0` 标签；`main` 分支在下次发布前仍
可能发生变化。

若只希望在某个仓库内使用，请将 `skills/fastapi-templates-xtn` 复制到目标仓库的
`.agents/skills/fastapi-templates-xtn`。

### 更新或卸载

安装器不会覆盖现有 Skill。更新前应先保留本地修改，并将已安装的
`fastapi-templates-xtn` 目录移动到已配置 Skill 目录之外作为备份，然后安装
指定标签。验证新版本后再删除备份。卸载时，删除已安装的 Skill 目录并重启
Codex；此操作不会影响规范仓库或任何独立维护的派生仓库。

## 使用

当任务需要完整安全基线时，可以显式调用：

```text
Use $fastapi-templates-xtn to build a single-project PostgreSQL FastAPI service
with strict RBAC and Redis-gated revocable Access Tokens.
```

如果只处理代理可用性功能而不涉及更广泛的 RBAC 请求，请显式调用该 Skill；
它的自动发现范围仍有意聚焦于 RBAC：

```text
Use $fastapi-templates-xtn to add proxy availability checks, Redis-backed latest
results, and single/batch detection to this existing proxy management module.
```

如果项目需要可选国家目录，请显式调用该 Skill，并在已有信息中提供产品认可的
国家码范围和具有使用授权的数据源：

```text
Use $fastapi-templates-xtn to add an optional PostgreSQL country catalog with
Chinese and English names, calling codes, soft deletion, and read-only APIs.
```

当请求与 `SKILL.md` 中的描述匹配时，Codex 也可能自动选择此 Skill。

## 环境要求

- 支持 Agent Skills 的 Codex 运行环境。
- 运行随附 FastAPI 资产需要 Python 3.12 或更高版本。
- 锁、约束、迁移和集成行为需要 PostgreSQL。
- 随附资产中的活跃 JTI 门禁需要 Redis；参考部署还为限流和登录/注册防滥用配置
  独立 Redis。明确启用的验证码可以使用该限流 Redis。
- 运行随附的本地 PostgreSQL 和两个 Redis 服务需要 Docker Compose v2。

## 本地验证

在仓库根目录运行：

```powershell
python -B -m pip install "skills/fastapi-templates-xtn/assets/postgresql-rbac[test]"
ruff check --no-cache skills/fastapi-templates-xtn/assets/postgresql-rbac
mypy --no-incremental --cache-dir "$env:TEMP\fastapi-templates-xtn-mypy-cache" --config-file skills/fastapi-templates-xtn/assets/postgresql-rbac/pyproject.toml skills/fastapi-templates-xtn/assets/postgresql-rbac/app skills/fastapi-templates-xtn/assets/postgresql-rbac/tests
python -B -m pytest -p no:cacheprovider -m "not postgresql" skills/fastapi-templates-xtn/assets/postgresql-rbac/tests
python -B skills/fastapi-templates-xtn/scripts/test_validate_country_csv.py
python -B scripts/validate_release.py
```

带有 PostgreSQL 标记的测试需要使用 `compose.dev.yaml` 配置的服务和测试数据库。
CI 会同时使用 PostgreSQL、活跃 JTI Redis 和独立的限流 Redis 运行检查，也会验证可选
验证码组件，但这不代表业务默认必须启用验证码。
`v0.4.0` 资产包含这些 Redis 集成和相关测试。生成的服务仍需完成自己的配置、
身份契约和目标部署验证，才能称为生产就绪。

发布标签前请参阅[发布检查清单](RELEASE_CHECKLIST.zh-CN.md)。

## 治理方式

规范仓库（canonical repository）为
[`xtnkking/fastapi-templates-xtn`](https://github.com/xtnkking/fastapi-templates-xtn)，
仅由 XTN 维护。欢迎提交 Issue 和私密安全报告，但不接受外部 Pull Request。
任何人都可以在适用许可证允许的范围内下载、创建派生仓库、修改和再分发；这些
副本均为非官方版本，不得暗示得到 XTN 或上游项目的认可。详情请参阅
[贡献说明](CONTRIBUTING.zh-CN.md)和[安全策略](SECURITY.zh-CN.md)。

## 许可证

除已标明的第三方部分外，XTN 的新增内容采用 Apache License 2.0。上游
`fastapi-templates` 和改编自 Alembic 模板的材料继续适用各自的 MIT 声明。
再分发时必须保留相应的许可证和署名文件。具有法律效力的完整条款以英文原文
[LICENSE](LICENSE)、[NOTICE](NOTICE) 和
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) 为准；本中文文档仅用于帮助
理解，不修改任何许可条件。
