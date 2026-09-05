# 发布检查清单

[English](RELEASE_CHECKLIST.md) | **简体中文**

本清单用于首次公开预览版及后续发布。命令、版本、标签和 URL 应与英文清单保持
一致。

## 本地发布包

- [ ] 随附 Skill 通过当前 `skill-creator` 快速验证器。
- [ ] Ruff、严格 mypy 和非 PostgreSQL 测试全部通过。
- [ ] 带 PostgreSQL 标记的测试在 PostgreSQL 17 上通过。
- [ ] 发布树中不存在 `.env`、Token、凭据、私钥、缓存、数据库或构建产物。
- [ ] 仓库、Skill 和复制资产的边界均包含 `LICENSE`、`NOTICE` 和
  `THIRD_PARTY_NOTICES.md`。
- [ ] README 描述的限制与资产实际实现保持一致。
- [ ] 完成所有本地检查后，从最终干净工作树运行
  `python -B scripts/validate_release.py` 并通过。

## GitHub 仓库

- [ ] 在 `https://github.com/xtnkking/fastapi-templates-xtn` 创建公开规范仓库，
  默认分支为 `main`。
- [ ] 不向外部用户、团队、GitHub App 或部署密钥授予 write、maintain 或
  administrator 权限。
- [ ] 为维护者账号启用双重身份验证（2FA），并检查个人访问令牌和已授权应用。
- [ ] 启用私密漏洞报告。
- [ ] 为 `main` 启用规则集，禁止删除和强制推送、要求 CI，并且只允许 XTN
  绕过规则。
- [ ] 保护 `v*` 标签，禁止删除或替换。
- [ ] 保持 Issues 开启；按照[贡献说明](CONTRIBUTING.zh-CN.md)关闭外部 Pull
  Request。

## 预览版发布

- [ ] 审查暂存差异，并确认 XTN 版权年份和上游提交。
- [ ] 仅在 CI 通过后创建 `v0.1.0` 标签。建立了可迁移的密钥管理流程时，建议
  对标签进行密码学签名，但预览版发布不强制要求签名。
- [ ] 将 `v0.1.0` 发布为 GitHub Prerelease，并明确活跃 JTI 适配器仍在规划中、
  尚未实现。
- [ ] 如果手动上传发布归档，请附加 SHA-256 校验和。
- [ ] 在干净的 Codex 环境中，通过公开 GitHub 标签树 URL 验证安装。

## 后续分发

- [ ] 当独立 Codex Skill 工作流之外还需要更广泛的公开安装能力时，将 Skill
  打包为 Plugin。
