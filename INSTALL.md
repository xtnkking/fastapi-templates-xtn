# Install And Update

**English** | [简体中文](INSTALL.zh-CN.md)

The installed Skill reports its version in `VERSION`. The repository copy at
`skills/fastapi-templates-xtn/VERSION` is the only authoritative version source;
release validation rejects inconsistent asset or documentation versions.

## First Installation

Use `$skill-installer` only when the destination does not already exist. Install
an immutable published tag, not a moving branch. The latest published release is
currently `v0.6.1`:

```text
Use $skill-installer to install the skill from
https://github.com/xtnkking/fastapi-templates-xtn/tree/v0.6.1/skills/fastapi-templates-xtn
```

`$skill-installer` intentionally refuses to overwrite an existing directory. It
is not the update mechanism.

## Safe Update From A Checked-Out Release

Check out the exact release tag in a separate repository directory. From that
repository root, resolve the exact installed target and run a dry run first.

PowerShell:

```powershell
$skillTarget = Join-Path $env:USERPROFILE ".codex\skills\fastapi-templates-xtn"
python -B scripts/update_installed_skill.py --target $skillTarget --dry-run
python -B scripts/update_installed_skill.py --target $skillTarget
Get-Content (Join-Path $skillTarget "VERSION")
```

POSIX shell:

```bash
skill_target="/absolute/path/to/.codex/skills/fastapi-templates-xtn"
python -B scripts/update_installed_skill.py \
  --target "$skill_target" \
  --dry-run
python -B scripts/update_installed_skill.py \
  --target "$skill_target"
cat "$skill_target/VERSION"
```

Use `--source PATH` only when the release Skill is somewhere other than this
repository's `skills/fastapi-templates-xtn` directory. Both source and target
must end in the exact Skill name. The script rejects symlinks, Windows
junction/reparse directories, and overlapping paths; excludes generated caches/build metadata; copies the source into a
same-volume staging directory, validates its version and byte-for-byte release
manifest, then renames directories. An existing installation is retained in the
same-volume `skill-backups` directory outside `skills`, where it cannot be
discovered as a duplicate Skill. It is never deleted automatically. Use
`--backup-dir` only for another existing-parent, same-filesystem location outside
the Skill discovery directory.

If the installed `VERSION` and included file manifest already match the source,
the script exits without replacing the directory or creating another backup.

If normal replacement fails, the script restores the previous directory. If the
machine loses power between renames, use the printed backup path to
restore the old directory manually. Keep a backup until Codex has loaded and
successfully used the new version. Restart or open a new Codex task after an
update so no already-loaded Skill instructions remain in the current context.

Repository-scoped installations use the same command with the exact target
`.agents/skills/fastapi-templates-xtn` inside that repository. Do not point the
script at `.codex`, `.agents`, a home directory, or a workspace root; the target
must be the final `fastapi-templates-xtn` directory.
