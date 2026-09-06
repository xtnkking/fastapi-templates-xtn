# fastapi-templates-xtn

[English](README.md) | **简体中文**

`fastapi-templates-xtn` 是一个具有明确安全基线的 Codex Skill（技能），用于构建
和加固 FastAPI 服务。它涵盖单项目范围的 PostgreSQL 基于角色的访问控制
（RBAC）、严格的管理权限层级、非顺序标识符、最小化且可撤销的 JWT 会话，
以及具备事务一致性的授权写入。

## 当前状态

`v0.2.0` 是当前正式发布的单项目 RBAC 版本。`v0.1.0` 是历史上的第一个公开
预览版，不包含本次重构。策略规范和可运行的 PostgreSQL RBAC 参考资产已经较为
完整，但该资产尚未实现 Skill 所描述的完整 PostgreSQL 会话与 Redis 活跃 JTI
适配器。在目标部署完成文档列出的身份提供方假设验证，以及 PostgreSQL/Redis
集成测试之前，不得将该资产描述为生产就绪。

## 上游来源与署名

本项目是在 [`wshobson/agents`](https://github.com/wshobson/agents) 项目的
[`fastapi-templates`](https://github.com/wshobson/agents/tree/47a5dbc3f9c2661c6afb13638f80d4a4d4449040/plugins/api-scaffolding/skills/fastapi-templates)
Skill 基础上独立维护的扩展，所依据的上游提交为
`47a5dbc3f9c2661c6afb13638f80d4a4d4449040`。

上游作品 Copyright (c) 2024 Seth Hobson，并按 MIT License 使用。XTN 的改动
增加了 PostgreSQL RBAC 模型、应用级管理权限层级与防止自我提权的规则、
原子授权写入、UUID 标识符策略，以及最小化且可撤销的 JWT 指南。本项目与上游
项目之间不存在从属、赞助或背书关系。完整署名和许可信息请参阅英文法律原文
[NOTICE](NOTICE) 和 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## 提供的能力

- 面向 PostgreSQL 的单项目正向授予 RBAC。
- 严格的管理权限级别，拒绝同级、向上、受保护身份，以及直接或间接
  自我提权操作。
- 用户、RBAC 记录、会话、审计记录和业务实体统一采用 UUIDv4，避免使用
  容易枚举的自增标识符。
- 不携带角色或资料字段的最小化 JWT 声明，以及“以 PostgreSQL 为权威状态源、Redis 辅助”
  的活跃 JTI 会话设计。
- 面向高权限写入的事务、锁顺序、审计、outbox（发件箱模式）、撤销和乐观并发
  控制要求。
- 面向现有代理管理模块的
  [可选代理可用性检测实现指南](skills/fastapi-templates-xtn/references/proxy-availability-detection.md)，
  涵盖 Redis 最近结果回显，以及受控并发的单个和批量检测。它是按需读取的指南，
  不是 RBAC 参考资产内置的功能。该指南已包含在 `v0.2.0` 中，但不属于
  `v0.1.0`。
- 可运行的 FastAPI、SQLAlchemy、Alembic 和 PostgreSQL 参考资产，并配有聚焦
  于策略与集成行为的测试。

## 安装

仓库中的 Skill 位于 `skills/fastapi-templates-xtn`。若要安装当前稳定的单项目
版本，请向 Codex 输入：

```text
Use $skill-installer to install the skill from
https://github.com/xtnkking/fastapi-templates-xtn/tree/v0.2.0/skills/fastapi-templates-xtn
```

若要安装历史 `v0.1.0` 预览版，请改用其不可变标签：

```text
Use $skill-installer to install the skill from
https://github.com/xtnkking/fastapi-templates-xtn/tree/v0.1.0/skills/fastapi-templates-xtn
```

安装器会将目录放入已配置的用户 Skill 位置；若同名目录已经存在，安装器会停止，
不会覆盖。Codex 通常会自动检测新安装的 Skill；若没有显示，请重启 Codex。
需要可复现安装时，请使用不可变的 `v0.2.0` 标签；`main` 分支在下次发布前仍
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
with strict RBAC and revocable JWT sessions.
```

如果只处理代理可用性功能而不涉及更广泛的 RBAC 请求，请显式调用该 Skill；
它的自动发现范围仍有意聚焦于 RBAC：

```text
Use $fastapi-templates-xtn to add proxy availability checks, Redis-backed latest
results, and single/batch detection to this existing proxy management module.
```

当请求与 `SKILL.md` 中的描述匹配时，Codex 也可能自动选择此 Skill。

## 环境要求

- 支持 Agent Skills 的 Codex 运行环境。
- 运行随附 FastAPI 资产需要 Python 3.12 或更高版本。
- 锁、约束、迁移和集成行为需要 PostgreSQL。
- 运行随附的本地 PostgreSQL 服务需要 Docker Compose v2。

## 本地验证

在仓库根目录运行：

```powershell
python -m pip install "skills/fastapi-templates-xtn/assets/postgresql-rbac[test]"
ruff check --no-cache skills/fastapi-templates-xtn/assets/postgresql-rbac
mypy --no-incremental --cache-dir "$env:TEMP\fastapi-templates-xtn-mypy-cache" --config-file skills/fastapi-templates-xtn/assets/postgresql-rbac/pyproject.toml skills/fastapi-templates-xtn/assets/postgresql-rbac/app skills/fastapi-templates-xtn/assets/postgresql-rbac/tests
python -B -m pytest -p no:cacheprovider -m "not postgresql" skills/fastapi-templates-xtn/assets/postgresql-rbac/tests
python -B scripts/validate_release.py
```

带有 PostgreSQL 标记的测试需要使用 `compose.dev.yaml` 配置的服务和测试数据库。
CI 会使用 PostgreSQL 运行这些检查。Redis 活跃 JTI 支持及其集成测试仍在规划中，
未包含在 `v0.2.0` 中。

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
