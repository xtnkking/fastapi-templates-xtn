#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    精选导出新项目代码和交接说明，不连接数据库，也不生成迁移或初始化脚本。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        精简默认交付，移除旁路清单并合并必要说明
# 2026/09/23    XTN       V1.002        对齐业务模型拆分后的用户名约束生成位置
# 2026/09/26    XTN       V1.003        跟随 authorization 与 user_name 新模块导出权限目录和用户名策略
# 2026/09/26    XTN       V1.004        命令帮助提前说明每个生成参数的格式和作用
# 2026/09/29    XTN       V1.005        从独立权限目录与系统角色配置中分别排除示例业务权限
# 2026/09/30    Codex     V1.006        跟随 core 职责目录更新示例权限导出位置
# 2026/09/30    Codex     V1.007        移除生成项目的管理员密码模式选择
# 2026/10/08    XTN       V1.008        新项目只记录当天新建，文件职责统一使用说明注释
# 2026/10/13    XTN       V1.009        补齐项目导出函数的通俗步骤注释
# 2026/10/13    XTN       V1.010        导出配置不再替换已删除的限流命名空间
# 2026/10/16    XTN       V1.011        默认仅导出统一操作审计，通用业务审计按需接入
# 2026/11/26    XTN       V1.012        生成时整体重建 History，清除错放在首条横线前的旧记录
# --------------------------------------------------------------------------------------------------

from __future__ import annotations

import argparse
import ast
import re
import shutil
import tempfile
import unicodedata
from datetime import date
from pathlib import Path

# 路径始终相对于当前 Skill，避免生成项目时读取使用者工作目录的同名文件。
SKILL_ROOT = Path(__file__).resolve().parents[1]
ASSET_ROOT = SKILL_ROOT / "assets" / "postgresql-rbac"
DELIVERY_ROOT = SKILL_ROOT / "assets" / "starter-delivery"
# 维护命令和工具缓存不属于默认交付，防止带入初始化工具或本机生成物。
EXCLUDED_PARTS = frozenset({"__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", "commands"})
# 订单、余额等业务审计是可选资源；没有实际需求时不带入新项目或注册表。
OPTIONAL_RUNTIME_FILES = frozenset({
    "app/core/business_audit.py",
    "app/models/postgres/business_audit.py",
    "app/services/business_audit_service.py",
})
# 明确列出配套文件；新增文件必须先审核用途，不能整目录复制进使用者项目。
DELIVERY_FILES = (
    ".env.example", ".gitignore", "README.md",
    "tests/test_user_name.py", "tests/test_authorization.py",
)
# History 行使用生成当天的日期、项目署名、V1.000 和新建；不复制模板维护记录。
HISTORY_SEPARATOR = "# " + "-" * 98
FILE_DESCRIPTIONS = {
    "pyproject.toml": "应用依赖、打包和开发工具配置",
    ".env.example": "本机连接、密钥占位和可调整业务参数示例",
    ".gitignore": "排除本机密钥、缓存和构建产物的版本控制规则",
    "README.md": "应用启动、接口使用和开发检查说明",
}


def source_files() -> list[Path]:
    """
        枚举可进入新项目的运行代码、语言资源和安装配置，排除维护工具与辅助清单。

    :return: 以相对路径排序的文件清单，不含迁移、SQL、完整维护测试或命令行恢复工具。
    """
    # 只收集运行包中的 Python 和语言资源，再补上安装配置，避免整份维护资产被复制。
    files = [
        path for path in (ASSET_ROOT / "app").rglob("*")
        if path.is_file() and path.suffix in {".py", ".json"}
        and not EXCLUDED_PARTS.intersection(path.relative_to(ASSET_ROOT).parts)
        and path.relative_to(ASSET_ROOT).as_posix() not in OPTIONAL_RUNTIME_FILES
    ]
    files.append(ASSET_ROOT / "pyproject.toml")
    return sorted(files)


def replace_once(content: str, old: str, new: str) -> str:
    """
        替换已经核验的模板片段；源结构变化时拒绝悄悄生成未正确配置的项目。

    :param content: 原文件文本。
    :param old: 必须且只能出现一次的原始片段。
    :param new: 新项目需要的替换片段。
    :return: 完成唯一替换后的文本。
    :raises ValueError: 模板片段缺失或重复，需维护者更新生成逻辑。
    """
    # 先确认原片段唯一，模板变动时明确失败，避免只替换一部分或把错误位置改掉。
    if content.count(old) != 1:
        raise ValueError(f"Template contract changed: {old!r}")
    return content.replace(old, new, 1)


def project_content(relative: Path, content: str, *, name: str, username_case: str) -> str:
    """
        将维护资产的项目标识、示例权限和用户名策略调整为明确选择的新项目内容。

    :param relative: 文件相对于运行资产的路径。
    :param content: 文件原始文本。
    :param name: 使用者选择的应用名称。
    :param username_case: sensitive 保留大小写，insensitive 统一按小写存储比较。
    :return: 不含维护示例业务或默认迁移依赖的项目文本。
    """
    # 按文件职责定点调整项目名称、依赖和示例授权，不影响其他模板内容。
    if relative.as_posix() == "pyproject.toml":
        content = replace_once(content, 'name = "fastapi-postgresql-rbac-example"', f'name = "{name}"')
        content = re.sub(r'^version = "[^"]+"$', 'version = "0.1.0"', content, count=1, flags=re.MULTILINE)
        content = replace_once(
            content, 'description = "Opinionated single-project RBAC reference for FastAPI and PostgreSQL"',
            f'description = "{name} API service"')
        content = replace_once(content, '  "alembic>=1.14,<2",\n', "")
        # 不替企业项目指定整体许可；现有 README 承载模板许可，并随包元数据保留。
        content = replace_once(content, 'license-files = ["LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"]',
                               'readme = "README.md"\nlicense-files = []')
        content = replace_once(content, "test = [", "dev = [")
        content = replace_once(
            content, 'markers = [\n  "postgresql: requires the PostgreSQL and Redis services '
            'from compose.dev.yaml",\n]\n',
            "")
        content = content.replace("~/.cache/fastapi-templates-xtn/", f"~/.cache/{name}/")
    elif relative.as_posix() == "app/__init__.py":
        content += ("\n# 本包包含源自 fastapi-templates-xtn 的模板代码；适用版权和许可保留在 README.md 的折叠附录。\n"
                    "# 该说明不替使用者新增的业务代码指定许可，也不要求公开项目。\n")
    elif relative.as_posix() == "app/core/config.py":
        # 默认应用名和版本跟随使用者选择的新项目；限流键不使用服务名。
        content = replace_once(content, 'default="fastapi-access-service"', f'default="{name}"')
        content = replace_once(content, 'default="unreleased"', 'default="0.1.0"')
    elif relative.as_posix() in {"app/core/access/permissions.py", "app/core/access/roles.py"}:
        # 移除维护资产中的项目演示权限，不将未实现的业务授权带入新项目。
        lines = content.splitlines(keepends=True)
        removed = [line for line in lines if "PROJECTS_READ" in line or "PROJECTS_UPDATE" in line]
        if len(removed) != 4:
            raise ValueError("Example permission catalog changed; review project export")
        content = "".join(line for line in lines if line not in removed)
    elif relative.as_posix() == "app/core/security/user_name.py" and username_case == "insensitive":
        # 大小写不敏感时先在应用层转小写，再给模型增加一致的存储约束。
        content = replace_once(content, "    return normalized\n", "    return normalized.lower()\n")
        content = content.replace("保留实际大小写供项目策略处理", "按项目选择统一为小写后存储和比较")
    elif relative.as_posix() == "app/models/postgres/user.py" and username_case == "insensitive":
        content = replace_once(content, '        UniqueConstraint("user_name", name="uq_users_user_name"),',
                               '        UniqueConstraint("user_name", name="uq_users_user_name"),\n'
                               '        CheckConstraint("user_name = lower(user_name)", name="user_name_lowercase"),')
    # 修改后的 Python 先检查能否解析，语法错误不能进入最终交付目录。
    if relative.suffix == ".py":
        ast.parse(content, filename=relative.as_posix())
    return content


def document_file(relative: Path, content: str, *, author: str, generated_on: str) -> str:
    """
        保留文件职责，为新项目仅记录生成当天的 V1.000 新建。
        移除模板维护记录和重复的模块说明，不改函数或类的说明。
        JSON 保持原内容，不为不支持注释的格式另建来源或版本清单。

    :param relative: 文件在新项目中的相对路径。
    :param content: 已按项目选择调整的文件内容。
    :param author: 使用者指定的署名；未知时使用明确的维护角色名称。
    :param generated_on: 本次生成的本机日期，格式为 YYYY/MM/DD。
    :return: 带合法文件头的文本；JSON 等不支持注释的文件保持原内容。
    """
    # 先获取文件职责；Python 用原模块说明作为兜底，JSON 则原样保留。
    description = FILE_DESCRIPTIONS.get(relative.name, f"{relative.as_posix()} 的项目资源与来源保留")
    history_bounds: tuple[int, int] | None = None
    lines = content.splitlines(keepends=True)
    if relative.suffix == ".py":
        tree = ast.parse(content)
        module_description = ast.get_docstring(tree)
        description = (module_description or f"{relative.stem} Python 模块").splitlines()[0]
        if module_description is not None:
            # 文件职责由 # 说明承担；只删除模块字符串，函数和类的 docstring 保持原样。
            module_docstring = tree.body[0]
            del lines[module_docstring.lineno - 1:module_docstring.end_lineno]
    elif relative.suffix == ".json":
        return content

    # Python、配置等已有文件头直接替换旧记录，不再叠加另一份 History。
    if "# History:\n" in lines:
        history_start = lines.index("# History:\n")
        separators = [index for index in range(history_start, len(lines))
                      if lines[index].rstrip() == HISTORY_SEPARATOR]
        if len(separators) < 2:
            raise ValueError(f"Incomplete file history: {relative.as_posix()}")
        # 旧记录偶尔会被加在首条横线前；从标题下一行整体重建，避免它漏进新项目。
        history_bounds = (history_start + 1, separators[1])

    # 按显示宽度对齐中英文署名；超长姓名保留原文并留空格，不截断或改写作者。
    author_width = sum(2 if unicodedata.east_asian_width(char) in {"W", "F"} else 1 for char in author)
    author_column = author + " " * max(1, 10 - author_width)
    row = f"# {generated_on:<14}{author_column}{'V1.000':<14}新建\n"
    if history_bounds is not None:
        start, end = history_bounds
        lines[start:end] = ["# Date          Author    Version       Modification\n",
                            f"{HISTORY_SEPARATOR}\n", row]
        return "".join(lines)

    # 没有现成 History 的文件按自身格式增加文件头，Markdown 使用 HTML 注释。
    content = "".join(lines)
    header = (f"# 说明:\n#    {description}\n# History:\n"
              "# Date          Author    Version       Modification\n"
              f"{HISTORY_SEPARATOR}\n{row}{HISTORY_SEPARATOR}\n\n")
    if relative.suffix == ".py":
        content = "#!/usr/bin/env python\n# -*- coding: utf-8 -*-\n\n" + header + content
    elif relative.suffix == ".toml" or relative.name in {".env.example", ".gitignore"}:
        content = header + content
    elif relative.suffix == ".md":
        content = "<!--\n" + "\n".join(line.removeprefix("# ")
                                       for line in header.rstrip().splitlines()) + "\n-->\n\n" + content
    return content


def create_project(target: Path, *, name: str, username_case: str, max_sessions: int,
                   author: str = "项目维护者") -> Path:
    """
        向不存在或空目录交付项目，先在同一父目录准备完整结果，再原子重命名。
        不安装依赖、不连接服务、不生成密钥或数据库结构；现有非空目录不会被覆盖。

    :param target: 使用者指定的新项目目录。
    :param name: 小写字母起始的包名称，允许数字及连字符，最长 48 位。
    :param username_case: 已确认的用户名大小写策略。
    :param max_sessions: 已确认的每用户最多同时登录次数，必须为正整数。
    :param author: 已知维护者署名；未提供姓名时使用角色名称，不猜测使用者身份。
    :return: 完整交付后的绝对项目路径。
    :raises ValueError: 项目参数无效、目录非空或模板契约发生变化。
    """
    # 先检查项目配置和目标目录；确认不会覆盖使用者文件或把项目写进 Skill 自身。
    if re.fullmatch(r"[a-z][a-z0-9-]{0,47}", name) is None:
        raise ValueError("Project name must match [a-z][a-z0-9-]{0,47}")
    if re.fullmatch(r"[\w.@-]{1,64}", author) is None:
        raise ValueError("Author must be 1-64 letters, digits, underscore, dot, at sign or hyphen")
    if username_case not in {"sensitive", "insensitive"}:
        raise ValueError("Explicit username case is required")
    if isinstance(max_sessions, bool) or not isinstance(max_sessions, int) or max_sessions <= 0:
        raise ValueError("Maximum active logins must be a positive integer")
    if target.is_symlink() or target.is_junction():
        raise ValueError("Project target must not be a symbolic link or junction")
    target = target.resolve()
    if target == SKILL_ROOT or SKILL_ROOT in target.parents or target in SKILL_ROOT.parents:
        raise ValueError("Project target must be separate from the Skill")
    if target.exists() and (not target.is_dir() or any(target.iterdir())):
        raise ValueError("Project target must be absent or empty")
    # 在目标的同级临时目录完整组装，所有文件写好后才把它变成最终项目目录。
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{name}-", dir=target.parent))
    try:
        # 一次生成共用一个日期；每份记录都表示实际生成动作，不冒充原文件创建日期。
        generated_on = date.today().strftime("%Y/%m/%d")
        for path in source_files():
            relative = path.relative_to(ASSET_ROOT)
            output = staging / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            content = project_content(relative, path.read_text(encoding="utf-8"), name=name,
                                      username_case=username_case)
            content = document_file(relative, content, author=author, generated_on=generated_on)
            output.write_text(content, encoding="utf-8", newline="\n")
        # 再生成简短交接说明、环境示例和精选测试，替换已确认的项目配置占位符。
        replacements = {
            "{{PROJECT_NAME}}": name, "{{USERNAME_CASE}}": username_case,
            "{{MAX_SESSIONS}}": str(max_sessions),
        }
        for filename in DELIVERY_FILES:
            relative = Path(filename)
            path = DELIVERY_ROOT / relative
            content = path.read_text(encoding="utf-8")
            for key, value in replacements.items():
                content = content.replace(key, value)
            if filename == "README.md":
                # 只合并实际导出代码涉及的许可；未导出的 Alembic 模板不进入业务项目说明。
                notice = replace_once(
                    (ASSET_ROOT / "NOTICE").read_text(encoding="utf-8"),
                    "This product also contains files derived from Alembic project templates.\n"
                    "Alembic copyright: Copyright 2009-2026 Michael Bayer.\nAlembic license: MIT License\n\n", "")
                notice = replace_once(notice, "The complete third-party license notices are in THIRD_PARTY_NOTICES.md.",
                                      "The applicable license texts follow below.")
                third_party = (ASSET_ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
                third_party, separator, _ = third_party.partition("\n## Alembic project templates\n")
                if not separator:
                    raise ValueError("Third-party source boundaries changed; review project attribution")
                third_party = replace_once(third_party, "provided in\n`LICENSE`.", "provided below.")
                license_text = (ASSET_ROOT / "LICENSE").read_text(encoding="utf-8")
                content += ("\n<details>\n<summary>模板代码来源与许可（点击展开）</summary>\n\n"
                            "以下条款适用于随附模板代码，使用者新增业务代码的许可由使用者决定；项目可以保持私有。\n\n"
                            "模板来源：https://github.com/xtnkking/fastapi-templates-xtn\n\n"
                            f"```text\n{notice.rstrip()}\n```\n\n{third_party.rstrip()}\n\n"
                            f"### Apache License 2.0\n\n```text\n{license_text.rstrip()}\n```\n\n</details>\n")
            content = document_file(relative, content, author=author, generated_on=generated_on)
            output = staging / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(content, encoding="utf-8", newline="\n")
        # 只删除已再次确认的空目标；并发写入会使 rmdir 失败，不会清除使用者文件。
        if target.exists():
            target.rmdir()
        staging.rename(target)
    finally:
        # 组装或最后重命名失败时清理临时内容；成功重命名后临时路径已经不存在。
        if staging.exists():
            shutil.rmtree(staging)
    return target


def main() -> None:
    """
        读取已经向项目使用者确认的配置，运行纯文件导出并说明数据库仍需自行处理。

    :return: 无返回值；成功打印交付目录，参数错误以非零状态退出。
    """
    # 命令行只收集导出所需参数，具体合法性和目录保护由 create_project 统一检查。
    parser = argparse.ArgumentParser(
        description=(
            "Create a curated FastAPI project without connecting to a database "
            "or generating migrations and initial data."
        )
    )
    parser.add_argument(
        "target", type=Path,
        help="New project directory; it must be absent or empty and separate from this Skill",
    )
    parser.add_argument(
        "--name", required=True,
        help="Project name: 1-48 lowercase letters, digits or hyphens; start with a letter",
    )
    parser.add_argument(
        "--username-case", choices=("sensitive", "insensitive"), required=True,
        help="Whether usernames distinguish uppercase and lowercase letters",
    )
    parser.add_argument(
        "--max-active-sessions", type=int, required=True,
        help="Positive maximum number of simultaneous logins retained for one user",
    )
    parser.add_argument("--author", default="项目维护者",
                        help=(
                            "File-history author: 1-64 letters, digits, underscore, dot, at sign or hyphen; "
                            "defaults to the maintainer role label"
                        ))
    args = parser.parse_args()
    # 文件导出失败时转成清楚的非零退出；成功时说明交付位置和后续数据库准备责任。
    try:
        result = create_project(args.target, name=args.name, username_case=args.username_case,
                                max_sessions=args.max_active_sessions,
                                author=args.author)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Cannot create project: {exc}\n")
    print(f"Created {result}. Read README.md for startup and database preparation; no database changes were made.")


if __name__ == "__main__":
    main()
