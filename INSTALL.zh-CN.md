# 安装与更新

[English](INSTALL.md) | **简体中文**

安装后的 Skill 可通过 `VERSION` 查看版本。仓库中的
`skills/fastapi-templates-xtn/VERSION` 是唯一权威版本来源；发布校验会拒绝资产或
文档中的版本与它不一致。

## 首次安装

只有目标目录不存在时才使用 `$skill-installer`。应安装不可变的正式标签，而不是
持续变化的分支。目前最新正式版是 `v0.6.2`：

```text
Use $skill-installer to install the skill from
https://github.com/xtnkking/fastapi-templates-xtn/tree/v0.6.2/skills/fastapi-templates-xtn
```

`$skill-installer` 会主动拒绝覆盖已有目录，它不是更新工具。

## 从已检出的正式版本安全更新

先把准确的正式标签检出到独立仓库目录。在该仓库根目录确认安装目标，先执行
`--dry-run`，确认显示的源和目标都正确后再正式更新。

PowerShell：

```powershell
$skillTarget = Join-Path $env:USERPROFILE ".codex\skills\fastapi-templates-xtn"
python -B scripts/update_installed_skill.py --target $skillTarget --dry-run
python -B scripts/update_installed_skill.py --target $skillTarget
Get-Content (Join-Path $skillTarget "VERSION")
```

POSIX shell：

```bash
skill_target="/absolute/path/to/.codex/skills/fastapi-templates-xtn"
python -B scripts/update_installed_skill.py \
  --target "$skill_target" \
  --dry-run
python -B scripts/update_installed_skill.py \
  --target "$skill_target"
cat "$skill_target/VERSION"
```

只有正式版本 Skill 不在本仓库默认的 `skills/fastapi-templates-xtn` 目录时，才需要
通过 `--source PATH` 指定来源。源目录和目标目录都必须以准确的 Skill 名称结尾。
脚本会拒绝符号链接、Windows junction/reparse 目录和互相包含的路径，排除测试缓存及
构建元数据，再复制到与目标同一磁盘的暂存目录，检查版本并逐文件核对 SHA-256，然后
才改名替换。已有安装会完整保留
到同盘且位于 `skills` 外面的 `skill-backups` 目录，避免备份被识别成重复 Skill；脚本
不会自动删除备份。只有需要改用另一个同文件系统位置时才传 `--backup-dir`，该位置的
父目录必须存在，并且不能位于 Skill 发现目录中。

如果已安装目录的 `VERSION` 和纳入更新的文件清单都与来源相同，脚本会直接结束，不会
替换目录，也不会重复生成完整备份。

正常替换失败时，脚本会自动恢复旧目录。如果电脑恰好在两次改名之间断电，可以使用
输出中显示的备份目录手动恢复。确认 Codex 已加载并正常使用新版本之前不要删除
备份。更新后应重启 Codex 或新建任务，避免当前上下文继续使用已经加载的旧 Skill
说明。

仓库级安装使用相同命令，只需把准确目标改成该仓库中的
`.agents/skills/fastapi-templates-xtn`。不要把 `.codex`、`.agents`、用户目录或
工作区根目录作为目标；目标必须是最终的 `fastapi-templates-xtn` 目录。
