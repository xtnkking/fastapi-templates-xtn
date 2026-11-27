# fastapi-templates-xtn

[English](README.md) | **简体中文**

这是由 XTN 维护的 Codex Skill，用于构建单项目 FastAPI 服务：PostgreSQL
角色权限、严格的管理员层级、用户名密码登录、图形验证码、Redis 活跃 JTI、按业务限流、
结构化日志，以及分别存储的权限和业务审计。

## 当前状态

`v0.7.0` 是最新正式标签；唯一权威版本值位于
[`skills/fastapi-templates-xtn/VERSION`](skills/fastapi-templates-xtn/VERSION)。
需要当前不可变基线时应安装此标签。

本地未发布改动正在优化新项目交付：通过
[精选生成入口](skills/fastapi-templates-xtn/references/new-project-delivery.md)
输出代码、ORM 模型、一份简明中文 README 和少量离线测试，排除整套维护测试、缓存、迁移历史及 SQL 初始化工具。
**迁移文件由使用者自己生成、审核、执行，基础数据也由使用者准备。**
不额外生成来源清单、数据库交接文件或独立许可文件；数据库准备要点并入 README，必要的
模板版权和许可文字放入其折叠附录，不替使用者的整个业务项目选择开源许可。保留实际需要的
依赖配置，也不会自动删除已有项目的文档。
Skill 不自动建表或初始化数据库，已有项目不会被覆盖。交付约定见
[新项目交付](skills/fastapi-templates-xtn/references/new-project-delivery.md)；这些改动尚未进入正式下载版。

未发布模板也在按已认可的 auth_pay 写法整理入口：`main.py` 只展示生命周期、
异常处理、中间件和路由装配；请求日志、异常响应放在各自模块。
职责归属和调用方式见[复用与抽象规范](skills/fastapi-templates-xtn/references/reuse-and-abstraction.md)。

当前源码把认证接口、Schema、依赖和 AuthService 统一为 auth 词根，响应、日志、用户名、
路由检查等模块也按实际工作命名；生成项目的 README 可以直接查到对应文件。认证接口依次
声明限流或身份权限依赖，再声明固定业务场景的验证码依赖，最后直接调用业务 Service。
验证码依赖只读取验证码参数和前面已验证的用户，不再次调用限流或权限检查，完整响应仍由路由组装。
服务端路由名称直接使用清晰的处理函数名；
密码规则直接接收一个可选用户名，不再为单用户名场景包装身份值集合。生成命令的帮助会在
写文件前说明每个必填选项和允许格式。这些仍是 Unreleased 改动，尚未进入 v0.7.0 下载。

`v0.7.0` 保持新项目简单：默认一台单机 PostgreSQL 和一台共用的单机 Redis。
Sentinel、Cluster、读写分离和独立 Redis 都按需启用。本版增加职责分目录、
有界连接和超时、更可靠的并发与日志处理，以及经过测试的 Redis 客户端和脚本适配；
集群部署维护仍由运维负责。详情见[更新日志](CHANGELOG.zh-CN.md)，发布证据记录在
`RELEASE_CHECKLIST.zh-CN.md`；此前的
[`v0.6.1 优化计划`](V0.6.1_OPTIMIZATION_PLAN.zh-CN.md)保留为历史修复记录。

只更新 Skill 不会影响正在运行的网站。只有把新版会话代码部署到已有项目时，
原来已登录的用户才需要重新登录，变更后的限流键也会重新开始一个计数窗口。
用户账号数据和 PostgreSQL 表结构不变，不需要新增 Alembic 迁移。

管理员新增、重置密码和唯一 `super_admin` 线下恢复都直接设置可登录的密码。
管理员须通过可信渠道私下交付；验证码、准确权限、严格低级目标、旧 Token
撤销、原子审计和密码不进入响应／日志的要求不变。

`v0.6.0` 还增加了请求级 API 多语言。所有面向客户端的运行时响应文案，包括
安全的参数校验明细，默认支持 `zh-CN`，也可通过 `Accept-Language: en` 请求英文。
响应会声明 `Content-Language` 和 `Vary: Accept-Language`；HTTP 状态、数字业务码、
数据、请求 ID、日志、审计字段和内部原因码不随语言变化。其他语言由具体项目按需
扩展。数据库中由业务人员维护的内容和源码中的静态 Schema 说明不属于本模块的翻译范围。

## 上游来源与署名

本 Skill 基于 [`wshobson/agents`](https://github.com/wshobson/agents) 的
[`fastapi-templates`](https://github.com/wshobson/agents/tree/47a5dbc3f9c2661c6afb13638f80d4a4d4449040/plugins/api-scaffolding/skills/fastapi-templates)
独立扩展，依据的上游提交为 `47a5dbc3f9c2661c6afb13638f80d4a4d4449040`。
原作品 Copyright (c) 2024 Seth Hobson，采用 MIT 许可。XTN 独立维护新增部分，
与上游项目不存在从属或背书关系；再分发时须保留 [NOTICE](NOTICE) 和
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## 当前基础规范

- 新项目只用 `user_name` 和密码，不默认提供邮箱登录或“忘记密码”自助接口。用户名
  去首尾空白，限制为 3～32 位 ASCII 英文字母、数字、下划线；12 个完整敏感名称禁止
  使用，软删除后名字也不能给别人。生成项目时询问用户名是否区分大小写；已有项目
  的其他身份规则不能擅自改。新密码默认 8～32 位可见 ASCII 字符，必须同时包含
  大写字母、小写字母、数字和英文特殊符号。规则统一在
  `app/core/security/password_rules.py` 维护；登录和验证旧密码使用独立的输入长度
  限制，不套用新密码强度规则。
- 自行注册不提供开关或注册状态查询接口，注册始终可用，但仍需通过图形验证码和
  按 IP 限流。有权限的管理员也可新增用户，两种创建方式都只绑定 `user` 角色。
  普通业务的查询和操作
  默认均须登录，不能因为是 `GET` 就匿名开放。
- 新项目业务接口只用 GET、POST 和固定路径。列表、详情查询分别以 `/list`、`/detail`
  结尾，GET 参数放查询字符串；POST 的目标 ID 及其他输入放经过校验的 JSON 请求体。
  接口按认证、本人账户、用户管理、角色、权限归类；参数放哪里都必须校验身份及目标权限。
  已有项目的接口约定沿用原样，除非使用者要求修改。
- 登录、注册、管理员新增用户、管理员重置别人密码、本人修改密码，共五种场景
  必须使用各自的图形验证码，对应的用途名是 `login`、`register`、
  `admin_create`、`admin_reset`、`self_change`。前两种由公开的
  `POST /api/v1/auth/captcha` 领取，后三种由需登录的
  `POST /api/v1/me/captcha` 领取。每张图有效期五分钟；不论答案对错，
  提交时都原子地消费一次，必须重新领取。刷新仅替换指定的仍有效旧图；登录后的验证码绑定
  服务端认证的操作者 ID。领取与刷新默认每个场景、每个主体五分钟最多十张。
  合法场景发错领取入口时拒绝生成图片，并使用独立的按主体限流额度，不占正常场景额度。
  基础模板不附带邮箱/短信发送模块或 MFA；实际项目需要时再单独开发。
- 普通用户只能退出当前登录；有权限的管理员可以在重新校验层级与审计后，强制
  比自己等级低的目标用户全部退出。生成项目时询问一个账号最多同时登录几次；
  必须填写正整数，随附配置不支持“不限制登录数”。Redis 记录活跃 JTI 与
  登录时间，新登录成功并达到上限时原子地退出最早一条。
  这只记录登录会话，不识别物理设备。修改或重置密码也会使旧 Token 失效。
- 首位 `super_admin` 由开发人员手工在数据库中建立角色绑定，以后更换也由
  授权人员在可信环境自行处理，不开放在线转移接口。新项目交付模型及必要说明，
  不生成或执行迁移、初始化、交接脚本。系统内始终只
  有一位超级管理员。固定系统角色只保留 `super_admin`、`user`，不预置 `admin`；
  管理员按需创建普通自定义角色并明确分配权限，500 级不保留。每人最多十个活跃角色、只能
  管理严格低于自己等级的对象、不能自行提权、软删除以及数据库写入和审计同事务
  都保留。授予者只能授予自己已拥有的权限；不另设 `can_delegate` 管理子系统。
- JWT 默认 24 小时，只包含 `sub`、`jti`、`iat`、`exp` 和 `token_type`；其中 `sub`
  是不可变、非自增的用户 ID。只有向实际项目使用者解释并获得明确同意后，才
  成对增加 `iss` 和 `aud`。每次使用 Token 都查 Redis 活跃 JTI，并读取当前的
  PostgreSQL 用户与权限。被盗 Token 在 JTI 仍活跃时仍可重放，所以高风险或管理
  后台应缩短 24 小时默认值。不提供第二种续签凭证或逐 Token 数据库表。
- Redis 限流使用简单固定窗口；每个接口／业务独立计数。未登录的认证入口按
  可信 IP，登录后的接口按操作者用户 ID；**没有全站总额度、跨业务共享额度、
  匿名用户名额度或覆盖整个 `/api/` 的 IP 总桶**。真实超限返回 `42901` 和
  `Retry-After`；Redis 或可信 IP 无法判断时拒绝操作并返回 `50301`。次数在
  `app/core/config.py` 和 `.env.example` 中集中配置；生成具体项目时展示默认值，
  让使用者按业务需要调整。
- 普通 JSON 响应统一有数字 `code`、`message`、`data`、服务端生成的
  `request_id`，响应头也带同一个 `X-Request-ID`。运行日志、只追加的
  `operation_audit_events` 分开：统一表记录账号及权限操作、脱敏请求和业务响应快照，
  新密码只留独立密钥生成的比较指纹。通用业务审计按需接入、默认不生成；不保存密码
  原文、JWT、JTI 或原始请求体。

| 独立业务 | 默认次数 |
| --- | ---: |
| 领取或刷新图形验证码，每个场景单独统计 | 10 次／5 分钟 |
| 合法验证码场景发错领取入口，按可信 IP 或已登录操作者单独统计 | 10 次／5 分钟 |
| 登录，每个可信 IP | 20 次／5 分钟 |
| 注册，每个可信 IP | 5 次／小时 |
| 已登录普通查询／写入，每个接口和操作者 | 600 次／分钟；120 次／分钟 |
| 管理查询／变更，每个接口和操作者 | 300 次／分钟；60 次／分钟 |

具体 Lua 原子计数、响应和故障行为见[限流规范](skills/fastapi-templates-xtn/references/rate-limiting.md)。
这些是起点而非所有网站通用的安全强度。修改实际部署的 `.env` 后重启即可使用
新的配置。同一公网 IP 后有多位真实用户时，未登录额度会由他们共享；不能为了
规避这个问题而信任未经验证的转发请求头。

[代理可用性检测](skills/fastapi-templates-xtn/references/proxy-availability-detection.md)
和[国家目录](skills/fastapi-templates-xtn/references/country-catalog.md) 是按需使用
的可选指南，不默认创建代理或国家表，也不能借此开放匿名普通业务接口或全站额度。
仓库不捆绑第三方国家数据集。

## 安装

首次安装到不存在的目标目录时，使用目前正式发布的不变标签：

```text
Use $skill-installer to install the skill from
https://github.com/xtnkking/fastapi-templates-xtn/tree/v0.7.0/skills/fastapi-templates-xtn
```

安装器不会覆盖已经安装的 Skill，不能把它描述成更新工具。已有安装请按照
[安装与更新](INSTALL.zh-CN.md)使用先暂存、逐文件哈希核对、失败可回滚的脚本；脚本
会把完整旧目录保留为带时间戳的备份。仓库级安装也使用同一脚本，准确目标为
`.agents/skills/fastapi-templates-xtn`。

## 使用和验证

FastAPI PostgreSQL 权限项目可以显式使用 `$fastapi-templates-xtn`；不相关的
FastAPI 请求不会自动选中它。维护者和下载使用者可以先看
[中文架构总览](skills/fastapi-templates-xtn/references/architecture-overview.zh-CN.md)，
了解模块边界、请求流程、数据表和接口；Skill 执行时仍按任务需要读取各份英文详细规范。

权限定义集中在按业务分组的
[`app/core/access/permissions.py`](skills/fastapi-templates-xtn/assets/postgresql-rbac/app/core/access/permissions.py)，
系统角色、等级和授权白名单集中在
[`app/core/access/roles.py`](skills/fastapi-templates-xtn/assets/postgresql-rbac/app/core/access/roles.py)。
`PERMISSION_CATALOG` 的值是 `PermissionSpec`，集中记录名称文案键、明确的
`PermissionGroup` 分组和描述文案键；分组名称由 `PERMISSION_GROUP_NAMES` 维护。
名称、分组名称和内置描述跟随请求语言，权限标识和分组标识保持固定。
初始化数据库描述仍用 `get_permission_description(key)` 获取，默认中文。
权限列表和详情还返回 `api_routes`：启动时从实际路由的权限依赖收集一次，查询时读取应用内存。
新增权限和分组文案时，按
[API 多语言规范](skills/fastapi-templates-xtn/references/api-internationalization.md) 同时补齐中英文文案。

新增或整理代码时，遵循[复用与抽象规范](skills/fastapi-templates-xtn/references/reuse-and-abstraction.md)：
同一条规则通过有意义的参数共用实现；简单的单次操作保持内联；安全、事务、资源清理
和框架适配需要的独立函数仍然保留，避免重复代码和无意义封装。

空目录从零搭建、尚无既定框架时，可默认[先按职责分目录](skills/fastapi-templates-xtn/references/project-structure.md)：
`api`、`core`、`db`、`dependencies`、`models`、`repositories`、`schemas`、
`services`；业务增加时，在这些目录内再按用户、订单等业务分文件或包。
API 默认 `api/v1/endpoints/<业务名>.py`，Service 使用 `<业务名>_service.py`，
Repository 使用 `repositories/postgres/<业务名>_repository.py`，模型使用
`models/postgres/<业务名>.py`；其他数据库按实际需要分类。
每个交付的 Python 函数都有[中文多行注释](skills/fastapi-templates-xtn/references/python-comments.md)，
明确用途、各参数及返回／生成内容。
同一规范还规定类方法参数对齐、长接口签名逐项换行、响应和审计字段清晰排列。
注释要说明真实权限、字段含义和执行顺序；定义回调函数不等于已经执行其中的检查。
公开字段通过 `Field`、查询参数通过 `Query` 提供中文说明，方便直接阅读源码和校验定义。
新项目默认关闭 `/docs`、`/redoc` 和 `/openapi.json`；`Accept-Language` 切换中英运行时提示和内置权限描述。
只有实际需要时才增加 Worker、工具模块。业务接口调用明确的 Service，由它负责分页、
缺失处理和结果组装，Repository 负责 SQL；不增加只转发到另一个 Service 的门面，
也不为已锁定模型的每个字段增加 setter。
这是一种可选默认方案。已有项目沿用自己的框架、目录、调用约定和基础设施，
把所需功能接入原有位置；不能因为调用本 Skill 就大改架构或用模板覆盖项目。
只有使用者明确要求重构时，才在约定范围内调整。

本 Skill 以代码规范和正确实现为核心。不停机更新、集群运维、生产容量和恢复演练
由使用者按项目需要决定，不作为普通编码任务或交付前置条件。调整连接池、超时、
多进程共享状态或排查实际性能问题时，再读
[容量与可用性规范](skills/fastapi-templates-xtn/references/application-capacity-and-availability.md)：
新项目默认使用一个单机 PostgreSQL 和一个单机 Redis，分别填写 `DATABASE_URL`
和 `REDIS_URL`；登录状态、验证码、限流默认共用该 Redis。Skill 只内置
单入口 PostgreSQL 和单机 Redis，不提供 Sentinel／Cluster、读写分离或
节点发现配置；需要集群的项目由使用者自行开发和验证客户端接入。
已有项目保留原拓扑。独立限流 Redis 仍可按需使用另一台单机，见
[连接配置](skills/fastapi-templates-xtn/references/redis-connections.md)。已有可靠性代码、并发测试和可选 GET 压测工具
继续保留，不因此要求使用者搭建生产平台。

官方验证环境固定为 Python 3.12、PostgreSQL 17、Redis 7。具体项目可以自行验证
其他版本，但本仓库不会把未测试的组合写成已经验证。默认项目不包含
`/health/live` 或 `/health/ready`，只有使用者明确要求时才按需添加部署探针，
并限制内网或受信探针访问。按需实现的检查必须有短超时，不暴露依赖细节，
也不创建或修复数据库状态。仓库内的
Compose 与独立测试数据库检查用于集成验证。复制使用前请先看
[资产配置与限流说明](skills/fastapi-templates-xtn/assets/postgresql-rbac/README.md)。
维护本仓库时遵循 [Skill 主规范](skills/fastapi-templates-xtn/SKILL.md)和
[复用与抽象规范](skills/fastapi-templates-xtn/references/reuse-and-abstraction.md)。
本地代理配置与私有维护记录不上传，也不输出到生成的应用项目。

在仓库根目录运行：

```powershell
python -B -m pip install --upgrade "pip==26.2.1" "setuptools==84.0.0"
python -B -m pip install -c skills/fastapi-templates-xtn/assets/postgresql-rbac/constraints-ci-py312.txt "skills/fastapi-templates-xtn/assets/postgresql-rbac[test]"
python -B -m autopep8 --diff --exit-code --recursive skills/fastapi-templates-xtn/assets/postgresql-rbac
ruff check --no-cache skills/fastapi-templates-xtn/assets/postgresql-rbac
mypy --no-incremental --cache-dir "$env:TEMP\fastapi-templates-xtn-mypy-cache" --config-file skills/fastapi-templates-xtn/assets/postgresql-rbac/pyproject.toml skills/fastapi-templates-xtn/assets/postgresql-rbac/app skills/fastapi-templates-xtn/assets/postgresql-rbac/tests
python -B -m pytest -p no:cacheprovider -m "not postgresql" skills/fastapi-templates-xtn/assets/postgresql-rbac/tests
pip-audit --local --skip-editable --progress-spinner off
python -B skills/fastapi-templates-xtn/scripts/test_validate_country_csv.py
python -B scripts/test_update_installed_skill.py
python -B scripts/test_validate_ci_environment.py
python -B scripts/validate_asset_wheel.py skills/fastapi-templates-xtn/assets/postgresql-rbac skills/fastapi-templates-xtn/VERSION
python -B scripts/validate_release.py
```

项目元数据继续保留有上下界的依赖范围，方便使用者适配项目。官方 Python 3.12/Linux
验证额外使用 `constraints-ci-py312.txt`，避免同一仓库提交日后自动解析到另一组依赖。
这些精确版本只能有意重新生成；修改后必须重新运行依赖漏洞扫描和完整测试。

只可对**全新且确认可丢弃**的 PostgreSQL/Redis 测试目标运行迁移及并发测试，
绝不能用装着实际业务数据的库。如实报告代码验证结果，生产部署验收由使用者
负责。发布新标签前参阅 [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md)。

## 维护与许可

[XTN 官方仓库](https://github.com/xtnkking/fastapi-templates-xtn) 仅由 XTN 维护，
接受 Issue 和私密安全报告，不接受外部 PR。下载和 Fork 后可以按相应许可修改、
再分发，但不是官方版本。除已注明的第三方部分，XTN 增加的内容使用
Apache-2.0，上游及改编 Alembic 模板材料仍保留 MIT 声明。参阅
[LICENSE](LICENSE)、[CONTRIBUTING.zh-CN.md](CONTRIBUTING.zh-CN.md)、
[SECURITY.zh-CN.md](SECURITY.zh-CN.md)。
