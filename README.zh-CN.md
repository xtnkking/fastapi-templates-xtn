# fastapi-templates-xtn

[English](README.md) | **简体中文**

这是由 XTN 维护的 Codex Skill，用于构建单项目 FastAPI 服务：PostgreSQL
角色权限、严格的管理员层级、用户名密码登录、图形验证码、Redis 活跃 JTI、按业务限流、
结构化日志，以及分别存储的权限和业务审计。

## 当前状态

仓库工作区正在准备 `v0.6.1`；唯一权威版本值位于
[`skills/fastapi-templates-xtn/VERSION`](skills/fastapi-templates-xtn/VERSION)。
在真正创建 `v0.6.1` Release 之前，最新正式标签仍是 `v0.6.0`。需要不可变基线时
应安装已经发布的标签。

本次修复范围和逐项验收状态记录在
[`V0.6.1_OPTIMIZATION_PLAN.zh-CN.md`](V0.6.1_OPTIMIZATION_PLAN.zh-CN.md)；
发布前仍以 `RELEASE_CHECKLIST.zh-CN.md` 的 `DRAFT` 门槛为准。

`v0.6.0` 增加了项目级“管理员重置密码模式”。默认 `direct`：管理员设置的
新密码立即成为正式密码，用户拿到后可以直接登录；可选 `temporary`：用户必须先
用临时密码完成一次正式密码设置。生成项目时必须解释两者并询问使用者，不能让
接口调用者按单次请求切换。`direct` 更简单，但管理员会知道并需要私下交付最终
密码；`temporary` 多一步，但最终密码由用户自己设置。两种模式都保留验证码、
准确权限、严格低级目标、旧 Token
撤销、原子审计和密码不进入响应／日志的要求。管理员新增用户和唯一
`super_admin` 线下恢复仍固定使用临时密码。

`v0.6.0` 还增加了请求级 API 多语言。所有面向客户端的运行时响应文案，包括
安全的参数校验明细，默认支持 `zh-CN`，也可通过 `Accept-Language: en` 请求英文。
响应会声明 `Content-Language` 和 `Vary: Accept-Language`；HTTP 状态、数字业务码、
数据、请求 ID、日志、审计字段和内部原因码不随语言变化。其他语言由具体项目按需
扩展。数据库中由业务人员维护的内容和面向开发者的 OpenAPI 元数据不属于本模块的
翻译范围。

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
  的其他身份规则不能擅自改。新密码默认 8～60 字符，拦截三种明显简单模式；是否
  强制大写、小写、数字或特殊字符，要与实际项目的使用者确认。
- 公开注册初始开启，但 `super_admin` 可以更改数据库中的注册开关。未登录的注册
  状态接口 `GET /api/v1/auth/registration/status` 只返回
  `registration_enabled`；只有当前 `super_admin` 可以对同一路径发 `POST`
  修改开关。关闭注册后，老用户仍可登录，有权限的管理员仍能新增用户。
  两种创建方式都只绑定 `user` 角色。普通业务的查询和操作
  默认均须登录，不能因为是 `GET` 就匿名开放。
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
- 首位 `super_admin` 由操作者运行受保护 SQL 脚本初始化，以后更换也只能由
  授权人员在可信环境运行受保护的交接脚本，不开放在线转移接口。系统内始终只
  有一位超级管理员。`admin`、`user` 固定系统角色、每人最多十个活跃角色、只能
  管理严格低于自己等级的对象、不能自行提权、软删除以及数据库写入和审计同事务
  都保留。授予者只能授予自己已拥有的权限；不另设 `can_delegate` 管理子系统。
- JWT 默认 24 小时，只包含 `sub`、`jti`、`iat`、`exp` 和 `token_type`；其中 `sub`
  是不可变、非自增的用户 ID。只有向实际项目使用者解释并获得明确同意后，才
  成对增加 `iss` 和 `aud`。每次使用 Token 都查 Redis 活跃 JTI，并读取当前的
  PostgreSQL 用户与权限。被盗 Token 在 JTI 仍活跃时仍可重放，所以高风险或管理
  后台应缩短 24 小时默认值。不提供第二种续签凭证或逐 Token 数据库表。
- Redis 限流使用简单固定窗口；每个接口／业务独立计数。未登录的认证入口按
  可信 IP，登录后的接口按操作者用户 ID；**没有全站总额度、跨业务共享额度、
  匿名用户名额度或覆盖整个 `/api/` 的 IP 总桶**。真实超限返回 `429001` 和
  `Retry-After`；Redis 或可信 IP 无法判断时拒绝操作并返回 `503001`。次数在
  `app/settings.py` 和 `.env.example` 中集中配置；生成具体项目时展示默认值，
  让使用者按业务需要调整。
- 普通 JSON 响应统一有数字 `code`、`message`、`data`、服务端生成的
  `request_id`，响应头也带同一个 `X-Request-ID`。运行日志、只追加的
  `rbac_audit_events`、账号安全审计和按需的业务审计各司其职，不记录密码、JWT、
  JTI 或原始请求体。

| 独立业务 | 默认次数 |
| --- | ---: |
| 领取或刷新图形验证码，每个场景单独统计 | 10 次／5 分钟 |
| 合法验证码场景发错领取入口，按可信 IP 或已登录操作者单独统计 | 10 次／5 分钟 |
| 登录，每个可信 IP | 20 次／5 分钟 |
| 注册，每个可信 IP | 5 次／小时 |
| 完成管理员新增用户或可选临时重置产生的临时密码，每个可信 IP | 20 次／5 分钟 |
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
https://github.com/xtnkking/fastapi-templates-xtn/tree/v0.6.0/skills/fastapi-templates-xtn
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

官方验证环境固定为 Python 3.12、PostgreSQL 17、Redis 7。具体项目可以自行验证
其他版本，但本仓库不会把未测试的组合写成已经验证。`GET /health/live` 只表示程序
进程还活着；`GET /health/ready` 要求 PostgreSQL 只有一个 Alembic head 且为
`0004_password_auth`，并能读取 `rbac_state(scope='global')`。活跃 JTI Redis 和
限流 Redis 都必须通过 `PING` 以及 Lua 写入、读取、删除探测；探测使用随机的非敏感
Key，并设置五秒兜底 TTL。所有检查都有短超时，对外只返回整体就绪或不可用，带
`Cache-Control: no-store`，不暴露组件状态、Key、连接地址或内部异常。应由 readiness
而不是 liveness 决定部署是否接收流量。仓库内的
Compose 与独立测试数据库检查用于集成验证。复制使用前请先看
[资产配置与限流说明](skills/fastapi-templates-xtn/assets/postgresql-rbac/README.md)。
在仓库根目录运行：

```powershell
python -B -m pip install --upgrade "pip==26.2.1" "setuptools==84.0.0"
python -B -m pip install -c skills/fastapi-templates-xtn/assets/postgresql-rbac/constraints-ci-py312.txt "skills/fastapi-templates-xtn/assets/postgresql-rbac[test]"
ruff format --check --no-cache skills/fastapi-templates-xtn/assets/postgresql-rbac
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
绝不能用装着实际业务数据的库。生成的项目要在目标部署环境完成检查，才能称为
生产就绪。发布新标签前参阅 [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md)。

## 维护与许可

[XTN 官方仓库](https://github.com/xtnkking/fastapi-templates-xtn) 仅由 XTN 维护，
接受 Issue 和私密安全报告，不接受外部 PR。下载和 Fork 后可以按相应许可修改、
再分发，但不是官方版本。除已注明的第三方部分，XTN 增加的内容使用
Apache-2.0，上游及改编 Alembic 模板材料仍保留 MIT 声明。参阅
[LICENSE](LICENSE)、[CONTRIBUTING.zh-CN.md](CONTRIBUTING.zh-CN.md)、
[SECURITY.zh-CN.md](SECURITY.zh-CN.md)。
