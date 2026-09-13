# fastapi-templates-xtn

[English](README.md) | **简体中文**

这是由 XTN 维护的 Codex Skill，用于构建单项目 FastAPI 服务：PostgreSQL
角色权限、严格的管理员层级、用户名密码登录、图形验证码、Redis 活跃 JTI、按业务限流、
结构化日志，以及分别存储的权限和业务审计。

## 当前状态

`v0.5.0` 是最近一次正式发布的标签。需要可复现安装时使用该标签；后续
`main` 的改动可能尚未发布。

## 上游来源与署名

本 Skill 基于 [`wshobson/agents`](https://github.com/wshobson/agents) 的
[`fastapi-templates`](https://github.com/wshobson/agents/tree/47a5dbc3f9c2661c6afb13638f80d4a4d4449040/plugins/api-scaffolding/skills/fastapi-templates)
独立扩展，依据的上游提交为 `47a5dbc3f9c2661c6afb13638f80d4a4d4449040`。
原作品 Copyright (c) 2024 Seth Hobson，采用 MIT 许可。XTN 独立维护新增部分，
与上游项目不存在从属或背书关系；再分发时须保留 [NOTICE](NOTICE) 和
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## v0.5.0 的基础规范

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
- JWT 默认一小时，只包含 `sub`、`jti`、`iat`、`exp` 和 `token_type`；其中 `sub`
  是不可变、非自增的用户 ID。只有向实际项目使用者解释并获得明确同意后，才
  成对增加 `iss` 和 `aud`。每次使用 Token 都查 Redis 活跃 JTI，并读取当前的
  PostgreSQL 用户与权限。不提供第二种续签凭证或逐 Token 数据库表。
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
| 完成临时密码，每个可信 IP | 20 次／5 分钟 |
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

安装目前正式发布的不变标签：

```text
Use $skill-installer to install the skill from
https://github.com/xtnkking/fastapi-templates-xtn/tree/v0.5.0/skills/fastapi-templates-xtn
```

安装器不会覆盖已经安装的 Skill；替换前先备份本地修改。仓库级安装也可将
`skills/fastapi-templates-xtn` 放入目标仓库的 `.agents/skills/fastapi-templates-xtn`。

## 使用和验证

FastAPI PostgreSQL 权限项目可以显式使用 `$fastapi-templates-xtn`；不相关的
FastAPI 请求不会自动选中它。随附代码需要 Python 3.12+、PostgreSQL 和 Redis。
仓库内的 Compose 与独立测试数据库检查用于集成验证。复制使用前请先看
[资产配置与限流说明](skills/fastapi-templates-xtn/assets/postgresql-rbac/README.md)。
在仓库根目录运行：

```powershell
python -B -m pip install "skills/fastapi-templates-xtn/assets/postgresql-rbac[test]"
ruff check --no-cache skills/fastapi-templates-xtn/assets/postgresql-rbac
mypy --no-incremental --cache-dir "$env:TEMP\fastapi-templates-xtn-mypy-cache" --config-file skills/fastapi-templates-xtn/assets/postgresql-rbac/pyproject.toml skills/fastapi-templates-xtn/assets/postgresql-rbac/app skills/fastapi-templates-xtn/assets/postgresql-rbac/tests
python -B -m pytest -p no:cacheprovider -m "not postgresql" skills/fastapi-templates-xtn/assets/postgresql-rbac/tests
python -B skills/fastapi-templates-xtn/scripts/test_validate_country_csv.py
python -B scripts/validate_release.py
```

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
