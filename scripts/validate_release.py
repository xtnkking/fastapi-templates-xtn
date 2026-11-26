#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 说明:
#    离线检查 Skill 分发内容、源码安全边界及文档契约，不导入应用或连接数据库。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        适配按业务拆分的模型、Schema、Service 与统一 API 版本前缀
# 2026/09/23    XTN       V1.001        按语法校验字段约束，区分静态接口文档与运行时中文文案
# 2026/09/23    XTN       V1.002        按入口、中间件、异常处理和健康探针的新归属校验装配与安全边界
# 2026/09/26    XTN       V1.003        同步业务模块命名，按直接认证流程保留防刷和验证码顺序校验
# 2026/09/26    XTN       V1.004        对齐路由校验与限流测试的直接命名
# 2026/09/27    XTN       V1.005        校验统一限流服务、路由旁声明和强制安全配置
# 2026/09/29    XTN       V1.006        校验关闭文档入口、路由名称限流和运行时认证依赖接线
# 2026/09/29    XTN       V1.007        默认不交付健康探针，仅校验业务装配及原有安全边界
# 2026/09/29    XTN       V1.008        核对独立权限与角色文件，并在角色配置中保留十角色上限检查
# 2026/09/29    XTN       V1.009        对齐 JWT、会话和授权策略拆分后的路径及 API 路由规则接线
# 2026/09/29    XTN       V1.010        统一响应校验改用传统泛型声明标记
# 2026/09/29    XTN       V1.011        对齐独立的 v1 路由校验模块与简洁总路由
# 2026/09/30    XTN       V1.012        按文案、语言协商与参数错误的独立归属校验多语言
# 2026/09/30    XTN       V1.013        数据库入口校验改为单文件 PostgreSQL 实现
# 2026/09/30    XTN       V1.014        当前契约不再要求临时密码路径和配置
# 2026/10/02    XTN       V1.015        对齐限流策略的真实运行入口
# 2026/10/02    XTN       V1.016        线下恢复校验改读不导出的维护命令服务
# 2026/10/02    XTN       V1.017        对齐 PostgreSQL 故障及线下维护查询文件归属
# 2026/10/02    XTN       V1.018        会话路由与简化语言协商校验同步当前契约
# 2026/10/02    XTN       V1.019        登录凭据异常归统一错误模块并复用 401 处理器
# 2026/10/02    XTN       V1.020        校验单权限依赖的实际管理认证入口
# 2026/10/02    XTN       V1.021        不再把独立 PostgreSQL 错误文件列为必交付项
# 2026/10/02    XTN       V1.022        删除已取消的密码字节上限检查
# 2026/10/04    XTN       V1.023        按验证码依赖直接拒绝限流入口核对接线
# 2026/10/04    XTN       V1.024        校验登录后验证码依赖同时执行合法场景扣次
# 2026/10/08    XTN       V1.025        注册限流契约统一使用 register 命名
# 2026/10/08    XTN       V1.026        限流接线校验对齐 Service 选策略的现行实现
# 2026/10/09    XTN       V1.027        模型文件清单与密码契约检查覆盖共用及验证码模块
# 2026/10/09    XTN       V1.028        账号审计动作核对集中枚举及各业务实际调用
# 2026/10/09    XTN       V1.029        退出路由接线检查跟随专用身份和限流依赖
# 2026/10/09    XTN       V1.030        响应合同检查对齐现有权限业务 ID 类型
# 2026/10/09    XTN       V1.031        现行注册测试静态引用统一使用 register 命名
# 2026/10/09    XTN       V1.032        分页响应及路由合同检查统一使用 Response 后缀
# 2026/10/09    XTN       V1.033        验证码契约检查对齐无状态共享服务的公开方法
# 2026/10/10    XTN       V1.034        限流合同改为查库前单次计数，删除只读预查要求
# 2026/10/10    XTN       V1.035        请求与响应合同统一核对公共基类
# 2026/10/10    XTN       V1.036        用户字段统一为 user_id，权限对象与审计操作方使用明确名称
# 2026/10/10    XTN       V1.037        验证码签发检查归路由，依赖仅保留校验与一次性消费
# 2026/10/10    XTN       V1.038        密码字段统一核对 Password 保密类型及直接长度约束
# 2026/10/12    XTN       V1.039        核对固定场景验证码依赖及其前置限流、权限和完整请求校验
# 2026/10/12    XTN       V1.040        验证码依赖只管验证码，前置限流和权限在路由声明
# 2026/10/12    XTN       V1.041        验证码直接提取字段并统一可信用户 ID 命名
# 2026/10/13    XTN       V1.042        验证 GETDEL 单次消费及摘要中的业务、用户绑定
# 2026/10/13    XTN       V1.043        会话文档合同对齐登录记录和登录顺序两键
# 2026/10/13    XTN       V1.044        会话键合同使用 sequence 明确登录先后顺序
# 2026/10/14    XTN       V1.045        验证码依赖合同直接核对用途枚举传递
# 2026/10/14    XTN       V1.046        密码默认上限改为 32，长度合同只认统一上下限
# 2026/10/14    XTN       V1.047        取消日志环境必填配置，应用名称和版本只核对实际应用用途
# 2026/10/14    XTN       V1.048        核对请求日志独立指纹密钥的真实装配
# 2026/10/15    XTN       V1.049        线下授权合同不再要求更新已移除的用户权限版本
# 2026/10/15    XTN       V1.050        用户角色集合字段检查统一使用 bound_role_ids
# 2026/10/15    XTN       V1.051        用户创建统一检查 UserService 中的共用及管理员入口
# 2026/10/16    XTN       V1.052        审计合同保留从当前上下文读取关联 ID 的共同入口
# 2026/10/16    XTN       V1.053        异常构造器名称统一标明固定 HTTP 状态
# 2026/10/16    XTN       V1.054        授权接线不再要求全局版本查询，维护 SQL 仅保留协调锁
# 2026/10/16    XTN       V1.055        校验统一操作审计及可选业务审计边界，保留历史迁移合同
# 2026/10/16    XTN       V1.056        业务直接传审计动作枚举，统一检查成功和拒绝写入入口
# 2026/10/16    XTN       V1.057        登录复查校验对齐合并后的账号状态判断与哈希比较
# 2026/10/16    XTN       V1.058        登录业务方法及调用接线统一检查 login 名称
# 2026/10/16    XTN       V1.059        单次密码验证后直接拒绝并发哈希变化
# 2026/10/16    XTN       V1.060        登录业务统一检查锁外令牌签发，路由只调用完整登录
# 2026/10/19    XTN       V1.061        账号状态比较检查对齐 user_info 命名
# 2026/10/20    XTN       V1.062        密码合同区分旧密码传输边界及设置新密码的策略长度
# 2026/10/20    XTN       V1.063        核对密码计算繁忙异常必须登记专用 503 处理器
# 2026/10/20    XTN       V1.064        可见性合同区分角色 level 与用户 role_level
# 2026/10/20    XTN       V1.065        验证直写认证依赖及账号读取前的单次限流
# 2026/10/20    XTN       V1.066        管理及本人接线合同同步上下文依赖名称
# 2026/10/20    XTN       V1.067        次数选择归限流模块，JWT字段集合采用直观名称
# 2026/10/20    XTN       V1.068        JWT 字段字典检查同步 token_fields 名称
# 2026/10/20    XTN       V1.069        会话维护接线检查同步登录记录检查和删除入口
# 2026/10/22    XTN       V1.070        退出路由接线改为直接校验登录，不再要求退出限流
# 2026/10/22    XTN       V1.071        权限回调直接复用 Token 与账号检查，并核对管理限流顺序
# 2026/10/22    XTN       V1.072        限流默认值检查对齐简短本人和管理配置名称
# 2026/10/22    XTN       V1.073        权限检查默认普通额度，核对业务显式选择和验证码前置顺序
# 2026/10/22    XTN       V1.074        用户和角色查询归属业务仓储，认证共用账号状态检查
# 2026/10/22    XTN       V1.075        用户权限查询复用已加载用户及共同汇总，保留页面过滤和锁内复查
# 2026/10/23    XTN       V1.076        用户权限统一 users 集合入口，查询和汇总合并为同一内部步骤
# 2026/10/23    XTN       V1.077        登录记录归 Redis 仓储，校验业务签发与锁外登记接线
# 2026/10/23    XTN       V1.078        当前用户信息路由改为 user_info 并对齐处理函数名称
# 2026/10/24    XTN       V1.079        验证码依赖检查跟随三个完整业务场景名称
# 2026/10/24    XTN       V1.080        用户仓储检查对齐直观查询命名和共用用户信息组装
# 2026/10/24    XTN       V1.081        用户列表、详情和查询构造检查采用简短业务名称
# 2026/10/24    XTN       V1.082        角色仓储检查对齐列表、详情及统一角色权限入口
# 2026/10/24    XTN       V1.083        用户角色绑定数量检查使用 count_roles 和直观计数名称
# 2026/10/24    XTN       V1.084        角色业务检查对齐加锁、操作校验、版本检查及删除名称
# 2026/10/24    XTN       V1.085        用户管理资料检查使用 UserDetails 和 get_users_info
# 2026/10/24    XTN       V1.086        公共事务检查对齐 user_role_transaction 文件与入口
# 2026/10/26    XTN       V1.087        用户权限信息类型统一使用 UserInfo，保持原有验证行为
# 2026/10/26    XTN       V1.088        权限结果字段明确区分有效用户信息与包含停用角色的信息
# 2026/10/26    XTN       V1.089        本人改密的验证码前置检查对齐基础权限依赖
# 2026/10/26    XTN       V1.090        角色可见性文档检查对齐列表删除状态与详情范围
# 2026/11/26    XTN       V1.091        用户名字段合同改为核对统一规则引用
# 2026/11/26    XTN       V1.092        区分历史版本说明与当前模型，按完整禁令判断跨行范围文案
# --------------------------------------------------------------------------------------------------

"""Validate the distributable Skill without external Python dependencies."""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
import tomllib
from pathlib import Path
from urllib.parse import unquote

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOT = REPO_ROOT / "skills" / "fastapi-templates-xtn"
ASSET_ROOT = SKILL_ROOT / "assets" / "postgresql-rbac"
EXPECTED_NAME = "fastapi-templates-xtn"
VERSION_PATH = SKILL_ROOT / "VERSION"
RELEASE_VERSION = (
    VERSION_PATH.read_text(
        encoding="utf-8").strip() if VERSION_PATH.is_file() else ""
)
RELEASE_TAG = f"v{RELEASE_VERSION}"
RELEASE_INSTALL_URL = (
    f"https://github.com/xtnkking/fastapi-templates-xtn/tree/{RELEASE_TAG}/"
    "skills/fastapi-templates-xtn"
)
UPSTREAM_COMMIT = "47a5dbc3f9c2661c6afb13638f80d4a4d4449040"

REQUIRED_REPO_FILES = (
    ".gitattributes",
    ".gitignore",
    "LICENSE",
    "NOTICE",
    "THIRD_PARTY_NOTICES.md",
    "INSTALL.md",
    "INSTALL.zh-CN.md",
    "README.md",
    "README.zh-CN.md",
    "CHANGELOG.md",
    "CHANGELOG.zh-CN.md",
    "CONTRIBUTING.md",
    "CONTRIBUTING.zh-CN.md",
    "SECURITY.md",
    "SECURITY.zh-CN.md",
    "RELEASE_CHECKLIST.md",
    "RELEASE_CHECKLIST.zh-CN.md",
    "scripts/test_update_installed_skill.py",
    "scripts/test_validate_ci_environment.py",
    "scripts/test_validate_release.py",
    "scripts/test_create_project.py",
    "scripts/update_installed_skill.py",
    "scripts/validate_asset_wheel.py",
    "scripts/validate_ci_environment.py",
    "V0.6.1_OPTIMIZATION_PLAN.zh-CN.md",
    "docs/history/v0.4.0/DESIGN_REVIEW.zh-CN.md",
    ".github/CODEOWNERS",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/ISSUE_TEMPLATE/bug-report.yml",
    ".github/workflows/ci.yml",
)
REQUIRED_SKILL_FILES = (
    "SKILL.md",
    "VERSION",
    "LICENSE",
    "NOTICE",
    "THIRD_PARTY_NOTICES.md",
    "agents/openai.yaml",
    "references/api-response-standard.md",
    "references/api-internationalization.md",
    "references/audit-module.md",
    "references/business-audit-module.md",
    "references/business-audit-operations.md",
    "references/business-audit-postgresql.md",
    "references/architecture-overview.zh-CN.md",
    "references/country-catalog.md",
    "references/country-catalog-postgresql.md",
    "references/identity-soft-delete.md",
    "references/jwt-session-implementation.md",
    "references/jwt-session-security.md",
    "references/local-password-authentication.md",
    "references/operational-logging.md",
    "references/proxy-availability-backend.md",
    "references/proxy-availability-detection.md",
    "references/proxy-availability-frontend.md",
    "references/proxy-availability-testing.md",
    "references/rate-limiting.md",
    "references/reuse-and-abstraction.md",
    "references/project-structure.md",
    "references/python-comments.md",
    "references/new-project-delivery.md",
    "references/application-capacity-and-availability.md",
    "references/redis-connections.md",
    "references/verification-and-abuse-defense.md",
    "scripts/test_validate_country_csv.py",
    "scripts/validate_country_csv.py",
    "scripts/create_project.py",
    "assets/starter-delivery/README.md",
    "assets/starter-delivery/.env.example",
    "assets/starter-delivery/tests/test_user_name.py",
    "assets/starter-delivery/tests/test_authorization.py",
)
REQUIRED_ASSET_FILES = (
    ".env.example",
    "README.md",
    "LICENSE",
    "NOTICE",
    "THIRD_PARTY_NOTICES.md",
    "constraints-ci-py312.txt",
    "pyproject.toml",
    "alembic/env.py",
    "app/core/response.py",
    "app/core/codes.py",
    "app/core/exceptions.py",
    "app/core/exception_handlers.py",
    "app/core/middleware/request_body_limit.py",
    "app/core/middleware/request_logging.py",
    "app/core/middleware/security_headers.py",
    "app/db/postgres_db.py",
    "app/core/i18n/messages.py",
    "app/core/i18n/language.py",
    "app/core/i18n/validation_messages.py",
    "app/core/access/permissions.py",
    "app/core/access/roles.py",
    "app/core/access/authorization.py",
    "app/assets/locales/__init__.py",
    "app/assets/locales/en.json",
    "app/assets/locales/zh-CN.json",
    "app/core/audit.py",
    "app/api/v1/endpoints/auth.py",
    "app/schemas/auth.py",
    "app/schemas/common.py",
    "app/schemas/captcha.py",
    "app/schemas/user.py",
    "app/schemas/role.py",
    "app/schemas/permission.py",
    "app/models/postgres/user.py",
    "app/models/postgres/role.py",
    "app/models/postgres/permission.py",
    "app/models/postgres/rbac_state.py",
    "app/models/postgres/operation_audit.py",
    "app/services/auth_service.py",
    "app/services/audit_service.py",
    "app/services/business_audit_service.py",
    "app/core/business_audit.py",
    "app/models/postgres/business_audit.py",
    "app/services/captcha_service.py",
    "app/dependencies/captcha.py",
    "app/core/logging/events.py",
    "app/core/logging/context.py",
    "app/core/logging/output.py",
    "app/commands/reset_super_admin_password.py",
    "app/commands/operator_password_service.py",
    "app/commands/operator_password_repository.py",
    "app/core/security/passwords.py",
    "app/core/security/user_name.py",
    "app/core/rate_limit/limiter.py",
    "app/dependencies/rate_limit.py",
    "app/core/route_validation.py",
    "app/db/redis_db.py",
    "scripts/load_test.py",
    "tests/test_load_test.py",
    "tests/test_database_availability.py",
    "tests/integration/test_database_availability.py",
    "tests/integration/test_auth_connections.py",
    "tests/integration/test_multi_instance.py",
    "tests/integration/instance_server.py",
    "app/api/v1/endpoints/permissions.py",
    "app/api/v1/endpoints/roles.py",
    "app/api/v1/endpoints/users.py",
    "app/api/v1/endpoints/me.py",
    "app/api/v1/router.py",
    "app/api/v1/route_validation.py",
    "app/core/access/authorization_policy.py",
    "app/core/access/role_policy.py",
    "app/core/access/user_policy.py",
    "app/repositories/postgres/permission_repository.py",
    "app/repositories/postgres/role_repository.py",
    "app/repositories/postgres/user_repository.py",
    "app/repositories/postgres/user_role_repository.py",
    "app/repositories/postgres/rbac_state_repository.py",
    "app/core/security/jwt_tokens.py",
    "app/repositories/redis/__init__.py",
    "app/repositories/redis/login_session_repository.py",
    "app/services/role_service.py",
    "app/services/permission_service.py",
    "app/services/user_service.py",
    "app/services/user_role_transaction.py",
    "app/core/config.py",
    "alembic/versions/0003_business_audit.py",
    "alembic/versions/0004_password_auth.py",
    "sql/bootstrap_super_admin.sql",
    "sql/handover_super_admin.sql",
    "tests/test_audit.py",
    "tests/test_auth_api.py",
    "tests/test_auth_service.py",
    "tests/test_integration_safety.py",
    "tests/test_i18n.py",
    "tests/test_business_audit.py",
    "tests/test_captcha.py",
    "tests/test_captcha_redis_live.py",
    "tests/test_dependency_logging.py",
    "tests/test_logging.py",
    "tests/test_logging_formatter.py",
    "tests/test_logging_output.py",
    "tests/integration/database_proxy.py",
    "tests/integration/test_database_deadlines.py",
    "tests/test_password_migration.py",
    "tests/test_password_models.py",
    "tests/test_passwords.py",
    "tests/test_policy.py",
    "tests/test_rate_limit.py",
    "tests/test_rate_limit_dependencies.py",
    "tests/test_route_validation.py",
    "tests/test_http_security_middleware.py",
    "tests/test_rate_limit_middleware.py",
    "tests/test_request_logging.py",
    "tests/test_rbac_queries.py",
    "tests/test_rbac_service_logging.py",
    "tests/test_rbac_service_operations.py",
    "tests/test_schemas.py",
    "tests/test_security.py",
    "tests/test_settings.py",
    "tests/test_redis_clients.py",
    "tests/test_redis_session_keys.py",
    "tests/integration/test_redis_session_registry.py",
    "tests/integration/safety.py",
    "tests/integration/test_business_audit.py",
    "tests/integration/test_captcha_redis.py",
    "tests/integration/test_password_authentication.py",
    "tests/integration/test_password_persistence.py",
    "tests/integration/test_migrations.py",
    "tests/integration/test_postgresql_locking.py",
    "tests/integration/test_rbac_api.py",
    "tests/integration/test_rate_limit_redis.py",
    "tests/integration/test_read_visibility.py",
    "tests/integration/test_user_role_limit.py",
)
MIRRORED_LEGAL_FILES = ("LICENSE", "NOTICE")
BILINGUAL_DOC_PAIRS = (
    ("INSTALL.md", "INSTALL.zh-CN.md"),
    ("README.md", "README.zh-CN.md"),
    ("CHANGELOG.md", "CHANGELOG.zh-CN.md"),
    ("CONTRIBUTING.md", "CONTRIBUTING.zh-CN.md"),
    ("SECURITY.md", "SECURITY.zh-CN.md"),
    ("RELEASE_CHECKLIST.md", "RELEASE_CHECKLIST.zh-CN.md"),
)
FORBIDDEN_DIRECTORY_NAMES = {
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "build",
    "dist",
    "htmlcov",
}
FORBIDDEN_DIRECTORY_SUFFIXES = (".egg-info",)
FORBIDDEN_FILE_NAMES = {".coverage"}
FORBIDDEN_FILE_SUFFIXES = {".db", ".pyc", ".pyo", ".sqlite", ".sqlite3"}
FORBIDDEN_SKILL_TABULAR_SUFFIXES = {".csv", ".tsv"}
COUNTRY_OR_FLAG_MEDIA_SUFFIXES = {
    ".apng",
    ".avif",
    ".bmp",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".png",
    ".svg",
    ".tif",
    ".tiff",
    ".webp",
}
COUNTRY_OR_FLAG_PATH_RE = re.compile(
    r"(?:^|[-_.])(?:countries|country|flags|flag)(?:$|[-_.])", re.IGNORECASE
)
TEXT_SUFFIXES = {
    "",
    ".ini",
    ".json",
    ".md",
    ".mako",
    ".py",
    ".sql",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
FRONTMATTER_RE = re.compile(r"\A---\r?\n(.*?)\r?\n---(?:\r?\n|\Z)", re.DOTALL)
LOCAL_HOME_PATH_RE = re.compile(
    r"(?:[A-Za-z]:[\\/](?:Users|home)[\\/][^\\/\r\n]+|/(?:Users|home)/[^/\r\n]+)"
)
SECRET_MATERIAL_RE = re.compile(
    r"(?:"
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    r"|AKIA[0-9A-Z]{16}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|ghp_[A-Za-z0-9]{20,}"
    r")"
)


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def require_semantics(
    errors: list[str],
    *,
    path: Path,
    checks: tuple[tuple[str, tuple[str, ...]], ...],
) -> None:
    """Require concepts while allowing maintainers to improve prose wording."""
    content = re.sub(r"\s+", " ", path.read_text(encoding="utf-8"))
    for label, patterns in checks:
        if not any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns):
            fail(
                errors,
                f"{path.relative_to(REPO_ROOT)} is missing required concept: {label}",
            )


def validate_required_files(errors: list[str]) -> None:
    for relative in REQUIRED_REPO_FILES:
        if not (REPO_ROOT / relative).is_file():
            fail(errors, f"missing repository file: {relative}")
    for relative in REQUIRED_SKILL_FILES:
        if not (SKILL_ROOT / relative).is_file():
            fail(errors, f"missing distributable Skill file: {relative}")
    for relative in REQUIRED_ASSET_FILES:
        if not (ASSET_ROOT / relative).is_file():
            fail(errors, f"missing copied-asset legal file: {relative}")


def validate_frontmatter(errors: list[str]) -> None:
    skill_md = SKILL_ROOT / "SKILL.md"
    if not skill_md.is_file():
        return
    content = skill_md.read_text(encoding="utf-8")
    match = FRONTMATTER_RE.match(content)
    if match is None:
        fail(errors, "SKILL.md has invalid YAML frontmatter delimiters")
        return

    fields: dict[str, str] = {}
    for line in match.group(1).splitlines():
        if not line.strip() or line.startswith((" ", "\t")):
            continue
        key, separator, value = line.partition(":")
        if not separator:
            fail(errors, f"SKILL.md has an invalid frontmatter line: {line!r}")
            continue
        fields[key.strip()] = value.strip().strip("\"'")

    if fields.get("name") != EXPECTED_NAME:
        fail(errors, f"SKILL.md name must be {EXPECTED_NAME!r}")
    if not fields.get("description"):
        fail(errors, "SKILL.md description must be non-empty")
    unexpected = set(fields) - {
        "name",
        "description",
        "license",
        "allowed-tools",
        "metadata",
    }
    if unexpected:
        fail(
            errors, f"SKILL.md has unsupported frontmatter keys: {sorted(unexpected)}")

    proxy_reference = "references/proxy-availability-detection.md"
    if proxy_reference not in content:
        fail(errors, f"SKILL.md does not route to {proxy_reference}")
    business_audit_reference = "references/business-audit-module.md"
    if business_audit_reference not in content:
        fail(errors, f"SKILL.md does not route to {business_audit_reference}")
    identity_lifecycle_reference = "references/identity-soft-delete.md"
    if identity_lifecycle_reference not in content:
        fail(
            errors, f"SKILL.md does not route to {identity_lifecycle_reference}")
    country_reference = "references/country-catalog.md"
    if country_reference not in content:
        fail(errors, f"SKILL.md does not route to {country_reference}")
    rate_limit_reference = "references/rate-limiting.md"
    if rate_limit_reference not in content:
        fail(errors, f"SKILL.md does not route to {rate_limit_reference}")
    verification_reference = "references/verification-and-abuse-defense.md"
    if verification_reference not in content:
        fail(errors, f"SKILL.md does not route to {verification_reference}")
    i18n_reference = "references/api-internationalization.md"
    if i18n_reference not in content:
        fail(errors, f"SKILL.md does not route to {i18n_reference}")


def validate_identity_and_row_lifecycle(errors: list[str]) -> None:
    paths = {
        "entrypoint": SKILL_ROOT / "SKILL.md",
        "reference": SKILL_ROOT / "references" / "identity-soft-delete.md",
        "models": ASSET_ROOT / "app" / "models" / "postgres" / "user.py",
        "role model": ASSET_ROOT / "app" / "models" / "postgres" / "role.py",
        "permission model": ASSET_ROOT / "app" / "models" / "postgres" / "permission.py",
        "state model": ASSET_ROOT / "app" / "models" / "postgres" / "rbac_state.py",
        "audit model": ASSET_ROOT / "app" / "models" / "postgres" / "operation_audit.py",
        "migration": ASSET_ROOT
        / "alembic"
        / "versions"
        / "0001_single_project_rbac.py",
        "readme": REPO_ROOT / "README.md",
        "readme zh-CN": REPO_ROOT / "README.zh-CN.md",
        "checklist": REPO_ROOT / "RELEASE_CHECKLIST.md",
        "checklist zh-CN": REPO_ROOT / "RELEASE_CHECKLIST.zh-CN.md",
    }
    missing = False
    for name, path in paths.items():
        if not path.is_file():
            fail(
                errors,
                f"missing identity/lifecycle {name}: {path.relative_to(REPO_ROOT)}",
            )
            missing = True
    if missing:
        return

    text = {name: path.read_text(encoding="utf-8")
            for name, path in paths.items()}
    required_markers = {
        "reference": (
            "## Choose The Identity And Login Contract Before Greenfield Work",
            "Required `user_name` only in the new-project baseline",
            "Permanently reserve a deleted user's username",
            "Classify every table before creating it",
            "Mutable runtime data",
            "Append-only evidence",
            "Permanent control state or immutable system catalog",
        ),
        "models": (
            "class User(Base):",
            "user_name: Mapped[str]",
            'UniqueConstraint("user_name", name="uq_users_user_name")',
            "class UserRole(Base):",
        ),
        "role model": ("class Role(Base):", "class RolePermission(Base):"),
        "permission model": ("class Permission(Base):",),
        "state model": ("class RbacState(Base):",),
        "audit model": ("class OperationAuditEvent(Base):",),
        "migration": (
            'sa.Column("user_name", sa.String(length=32), nullable=False)',
            'sa.UniqueConstraint("user_name", name="uq_users_user_name")',
            '"deleted_at", sa.DateTime(timezone=True), nullable=True',
            'ondelete="RESTRICT"',
        ),
        "readme": (
            "username/password login",
            "cannot be reused after soft deletion",
        ),
        "readme zh-CN": (
            "用户名密码",
            "软删除",
        ),
        "checklist": (
            "required `user_name`",
            "Inventory every table and row-removal path",
        ),
        "checklist zh-CN": (
            "必填 `user_name`",
            "盘点全部表和所有数据移除路径",
        ),
    }
    for name, markers in required_markers.items():
        for marker in markers:
            if marker not in text[name]:
                fail(
                    errors,
                    f"{paths[name].relative_to(REPO_ROOT)} is missing "
                    f"identity/lifecycle marker: {marker!r}",
                )

    model_classes = {
        "User": "soft-delete",
        "Permission": "soft-delete",
        "Role": "soft-delete",
        "RolePermission": "soft-delete",
        "UserRole": "soft-delete",
        "RbacState": "permanent",
        "OperationAuditEvent": "append-only",
    }
    model_source = "\n".join(text[name] for name in (
        "models", "role model", "permission model", "state model", "audit model",
    ))
    class_positions = []
    for name, lifecycle in model_classes.items():
        position = model_source.find(f"class {name}(Base):")
        if position >= 0:
            class_positions.append((position, name, lifecycle))
    class_positions.sort()
    for index, (start, name, lifecycle) in enumerate(class_positions):
        end = (
            class_positions[index + 1][0]
            if index + 1 < len(class_positions)
            else len(model_source)
        )
        body = model_source[start:end]
        has_tombstone = "deleted_at: Mapped[" in body
        if lifecycle == "soft-delete" and not has_tombstone:
            fail(
                errors, f"asset model {name} must define a deleted_at tombstone")
        if lifecycle != "soft-delete" and has_tombstone:
            fail(
                errors,
                f"asset {lifecycle} model {name} must not expose soft deletion",
            )

    runtime_schema_files = sorted((ASSET_ROOT / "app").rglob("*.py"))
    runtime_schema_files.extend(sorted((ASSET_ROOT / "alembic").rglob("*.py")))
    cascade_pattern = re.compile(
        r"ondelete\s*=\s*['\"]cascade['\"]|on\s+delete\s+cascade",
        re.IGNORECASE,
    )
    for path in runtime_schema_files:
        if cascade_pattern.search(path.read_text(encoding="utf-8")):
            fail(
                errors,
                f"{path.relative_to(REPO_ROOT)} uses cascading hard deletion",
            )


def validate_links(errors: list[str]) -> None:
    for markdown in sorted(REPO_ROOT.rglob("*.md")):
        content = markdown.read_text(encoding="utf-8")
        for raw_target in LINK_RE.findall(content):
            target = raw_target.strip().strip("<>").split(maxsplit=1)[0]
            if not target or target.startswith(("#", "https://", "http://", "mailto:")):
                continue
            target_path = unquote(target.split("#", 1)[0])
            if not (markdown.parent / target_path).resolve().exists():
                relative_markdown = markdown.relative_to(REPO_ROOT)
                fail(
                    errors, f"broken link in {relative_markdown}: {raw_target}")


def validate_bilingual_docs(errors: list[str]) -> None:
    for english_name, chinese_name in BILINGUAL_DOC_PAIRS:
        english_path = REPO_ROOT / english_name
        chinese_path = REPO_ROOT / chinese_name
        if not english_path.is_file() or not chinese_path.is_file():
            continue

        english = english_path.read_text(encoding="utf-8")
        chinese = chinese_path.read_text(encoding="utf-8")
        if f"[简体中文]({chinese_name})" not in english:
            fail(
                errors, f"{english_name} is missing its Simplified Chinese link")
        if f"[English]({english_name})" not in chinese:
            fail(errors, f"{chinese_name} is missing its English link")


def validate_legal_mirrors(errors: list[str]) -> None:
    for name in MIRRORED_LEGAL_FILES:
        repo_file = REPO_ROOT / name
        skill_file = SKILL_ROOT / name
        if repo_file.is_file() and skill_file.is_file():
            if repo_file.read_bytes() != skill_file.read_bytes():
                fail(
                    errors, f"repository and distributable copies differ: {name}")

    notice_markers = (
        UPSTREAM_COMMIT,
        "Copyright (c) 2024 Seth Hobson",
        "Copyright 2009-2026 Michael Bayer",
        "MIT License",
    )
    for notice_path in (
        REPO_ROOT / "THIRD_PARTY_NOTICES.md",
        SKILL_ROOT / "THIRD_PARTY_NOTICES.md",
        ASSET_ROOT / "THIRD_PARTY_NOTICES.md",
    ):
        if not notice_path.is_file():
            continue
        notice_text = notice_path.read_text(encoding="utf-8")
        for marker in notice_markers:
            if marker not in notice_text:
                relative = notice_path.relative_to(REPO_ROOT)
                fail(
                    errors, f"{relative} is missing required notice: {marker}")

    if (SKILL_ROOT / "SKILL.md").is_file():
        skill_text = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        if UPSTREAM_COMMIT not in skill_text:
            fail(errors, "SKILL.md does not pin the upstream attribution commit")


def _current_checklist_section(content: str, heading: str) -> str | None:
    marker = f"## {heading}"
    start = content.find(marker)
    if start < 0:
        return None
    end = content.find("\n## ", start + len(marker))
    return content[start:] if end < 0 else content[start:end]


def validate_release_readiness(errors: list[str], *, release_ready: bool) -> None:
    definitions = (
        (
            REPO_ROOT / "RELEASE_CHECKLIST.md",
            f"Prepare {RELEASE_TAG}",
            "Release readiness",
            "### Pre-tag evidence",
            "### Post-release verification",
        ),
        (
            REPO_ROOT / "RELEASE_CHECKLIST.zh-CN.md",
            f"准备 {RELEASE_TAG}",
            "发布就绪状态",
            "### 发布前证据",
            "### 发布后核验",
        ),
    )
    statuses: list[str] = []
    incomplete_counts: list[int] = []
    for path, heading, status_label, pre_heading, post_heading in definitions:
        if not path.is_file():
            continue
        section = _current_checklist_section(
            path.read_text(encoding="utf-8"), heading)
        if section is None:
            fail(
                errors, f"{path.name} is missing current section: ## {heading}")
            continue
        status_match = re.search(
            rf"^{re.escape(status_label)}[^\n]*`(DRAFT|READY)`\s*$",
            section,
            re.MULTILINE,
        )
        if status_match is None:
            fail(
                errors, f"{path.name} must declare DRAFT or READY release status")
            continue
        statuses.append(status_match.group(1))

        pre_start = section.find(pre_heading)
        post_start = section.find(post_heading)
        if pre_start < 0 or post_start <= pre_start:
            fail(
                errors, f"{path.name} has invalid current pre-tag evidence sections")
            continue
        pre_tag = section[pre_start:post_start]
        states = re.findall(r"^- \[([ xX])\] ", pre_tag, re.MULTILINE)
        if not states:
            fail(errors, f"{path.name} has no current pre-tag evidence items")
            continue
        incomplete = sum(state == " " for state in states)
        incomplete_counts.append(incomplete)
        if status_match.group(1) == "READY" and incomplete:
            fail(
                errors,
                f"{path.name} says READY but has {incomplete} unchecked pre-tag item(s)",
            )
        if status_match.group(1) == "DRAFT" and not incomplete:
            fail(
                errors, f"{path.name} must say READY when every pre-tag item is checked"
            )
        if release_ready and status_match.group(1) != "READY":
            fail(
                errors, f"{path.name} is DRAFT; release-ready validation requires READY"
            )

    if len(set(statuses)) > 1 or len(set(incomplete_counts)) > 1:
        fail(errors, "English and Chinese release readiness records disagree")
    if not release_ready and statuses and statuses[0] == "DRAFT":
        count = incomplete_counts[0] if incomplete_counts else 0
        print(
            f"NOTICE: {RELEASE_TAG} release checklist is DRAFT "
            f"with {count} incomplete pre-tag item(s)."
        )


def validate_release_metadata(errors: list[str], *, release_ready: bool) -> None:
    pyproject_path = ASSET_ROOT / "pyproject.toml"
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", RELEASE_VERSION):
        fail(errors, "Skill VERSION must contain exactly one semantic version")

    version_markers = {
        "README.md": (
            f"`{RELEASE_TAG}`",
            "skills/fastapi-templates-xtn/VERSION",
        ),
        "README.zh-CN.md": (
            f"`{RELEASE_TAG}`",
            "skills/fastapi-templates-xtn/VERSION",
        ),
        "skills/fastapi-templates-xtn/references/migrations.md": (
            f"`{RELEASE_TAG}`",
        ),
        "skills/fastapi-templates-xtn/references/architecture-overview.zh-CN.md": (
            f"`{RELEASE_TAG}`",
        ),
    }
    for relative, markers in version_markers.items():
        path = REPO_ROOT / relative
        if not path.is_file():
            continue
        content = path.read_text(encoding="utf-8")
        for marker in markers:
            if marker not in content:
                fail(
                    errors,
                    f"{relative} is missing current version marker: {marker!r}",
                )

    release_dates: list[str] = []
    changelog_patterns = {
        "CHANGELOG.md": rf"^## \[{re.escape(RELEASE_VERSION)}\] - (Unreleased|\d{{4}}-\d{{2}}-\d{{2}})$",
        "CHANGELOG.zh-CN.md": rf"^## \[{re.escape(RELEASE_VERSION)}\] - (?:未发布|(\d{{4}}-\d{{2}}-\d{{2}}))$",
    }
    for changelog_name, pattern in changelog_patterns.items():
        path = REPO_ROOT / changelog_name
        if not path.is_file():
            continue
        match = re.search(pattern, path.read_text(
            encoding="utf-8"), re.MULTILINE)
        if match is None:
            fail(
                errors, f"{changelog_name} lacks the current {RELEASE_VERSION} heading"
            )
            continue
        value = (match.group(1) if match.lastindex else None) or match.group(0)
        if release_ready:
            date_match = re.search(r"\d{4}-\d{2}-\d{2}", value)
            if date_match is None:
                fail(
                    errors, f"{changelog_name} still marks {RELEASE_VERSION} unreleased"
                )
            else:
                release_dates.append(date_match.group(0))
    if release_ready and len(set(release_dates)) > 1:
        fail(errors, "English and Chinese changelogs use different release dates")

    if release_ready:
        release_install_docs = (
            "README.md",
            "README.zh-CN.md",
            "INSTALL.md",
            "INSTALL.zh-CN.md",
        )
        for document_name in release_install_docs:
            document_path = REPO_ROOT / document_name
            if document_path.is_file() and RELEASE_INSTALL_URL not in (
                document_path.read_text(encoding="utf-8")
            ):
                fail(
                    errors,
                    f"{document_name} is missing the {RELEASE_TAG} installation URL",
                )
        published_markers = {
            "README.md": f"`{RELEASE_TAG}` is the latest published tag",
            "README.zh-CN.md": f"`{RELEASE_TAG}` 是最新正式标签",
        }
        for readme_name, marker in published_markers.items():
            readme_path = REPO_ROOT / readme_name
            if readme_path.is_file() and marker not in readme_path.read_text(
                encoding="utf-8"
            ):
                fail(
                    errors,
                    f"{readme_name} must identify {RELEASE_TAG} as latest published",
                )
        github_ref = os.environ.get("GITHUB_REF", "")
        if github_ref.startswith("refs/tags/") and github_ref != (
            f"refs/tags/{RELEASE_TAG}"
        ):
            fail(
                errors,
                f"Git tag {github_ref.removeprefix('refs/tags/')} does not match "
                f"Skill VERSION {RELEASE_VERSION}",
            )

    if pyproject_path.is_file():
        pyproject = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
        asset_version = pyproject.get("project", {}).get("version")
        if asset_version != RELEASE_VERSION:
            fail(
                errors,
                "asset pyproject.toml version must match Skill VERSION "
                f"{RELEASE_VERSION!r}, got {asset_version!r}",
            )

    validate_release_readiness(errors, release_ready=release_ready)


def validate_access_token_baseline(errors: list[str]) -> None:
    """
        核对 JWT 规则、Redis 登录仓储和认证接线，防止移层时漏掉原有安全要求。

    :param errors: 接收文件、协议或调用顺序不符合约定的说明。
    :return: 无返回值；只读取源码和文档，不访问 Redis 或数据库。
    """
    # 1. 从各自归属的文件读取合同；JWT 编解码与 Redis 登录读写分别维护。
    paths = {
        "skill": SKILL_ROOT / "SKILL.md",
        "policy": SKILL_ROOT / "references" / "jwt-session-security.md",
        "implementation": SKILL_ROOT / "references" / "jwt-session-implementation.md",
        "settings": ASSET_ROOT / "app" / "core" / "config.py",
        "JWT codec": ASSET_ROOT / "app" / "core" / "security" / "jwt_tokens.py",
        "login repository": ASSET_ROOT / "app" / "repositories" / "redis" / "login_session_repository.py",
        "auth service": ASSET_ROOT / "app" / "services" / "auth_service.py",
        "dependencies": ASSET_ROOT / "app" / "dependencies" / "auth.py",
        "environment": ASSET_ROOT / ".env.example",
        "settings tests": ASSET_ROOT / "tests" / "test_settings.py",
        "security tests": ASSET_ROOT / "tests" / "test_security.py",
    }
    if any(not path.is_file() for path in paths.values()):
        return
    text = {name: path.read_text(encoding="utf-8")
            for name, path in paths.items()}

    require_semantics(
        errors,
        path=paths["policy"],
        checks=(
            (
                "Access Token defaults to 24 hours / 86400 seconds and must be reviewed",
                (
                    r"86,400 seconds after `iat` by default.*starting default",
                    r"24-hour lifetime.*tell the user to adjust",
                ),
            ),
            (
                "iss and aud remain absent when the owner gives no answer",
                (r"iss.*aud.*No reply is not consent",),
            ),
            (
                "iss and aud require explicit consent",
                (r"iss.*aud.*require explicit consent",),
            ),
            (
                "an existing configured iss/aud pair is preserved by default",
                (r"existing project already has both configured, preserve",),
            ),
            (
                "PostgreSQL has no Token/session table or per-request Token lookup",
                (
                    r"Do not add a PostgreSQL table for individual Token records.*"
                    r"do not add another database query per request",
                ),
            ),
        ),
    )
    required_markers = {
        "policy": (
            "86,400 seconds after `iat` by default",
            "Redis 7 Lua operation",
            "server `TIME`",
            "HSETNX",
            "PEXPIREAT",
            "PEXPIRETIME",
            "Redis is the only per-token online active-JTI gate",
        ),
        "implementation": (
            "../assets/postgresql-rbac/app/core/security/jwt_tokens.py",
            "../assets/postgresql-rbac/app/repositories/redis/login_session_repository.py",
            "../assets/postgresql-rbac/app/services/auth_service.py",
            "issue_access_token(",
            "register_login_session(",
            "check_login_session(",
            "delete_login_session(",
            "HSETNX",
            "PEXPIRETIME",
            "PEXPIREAT",
            "login:sessions:",
            "login:sequence:",
        ),
        "settings": (
            "jwt_issuer: str | None = None",
            "jwt_audience: str | None = None",
            "must be configured together or omitted",
            "Field(default=86_400, ge=1)",
        ),
        "JWT codec": (
            'REQUIRED_ACCESS_TOKEN_FIELDS = frozenset({"user_id", "jti", "iat", "exp", "token_type"})',
            'OPTIONAL_ACCESS_TOKEN_FIELDS = frozenset({"iss", "aud"})',
            "expected_fields = REQUIRED_ACCESS_TOKEN_FIELDS",
            "expected_fields |= OPTIONAL_ACCESS_TOKEN_FIELDS",
            "if set(token_fields) != expected_fields",
            "if settings.jwt_issuer is not None and settings.jwt_audience is not None",
        ),
        "login repository": (
            "class LoginSessionRepository:",
            "login_session_repository = LoginSessionRepository()",
            "register_login_session(",
            "_ACTIVATE_JTI =",
            "redis.call('TIME')",
            "redis.call('HSETNX', KEYS[1], ARGV[1], ARGV[2])",
            "redis.call('PEXPIRETIME', KEYS[1])",
            "redis.call('PEXPIREAT', key, deadline_ms)",
            "_READ_ACTIVE_JTI",
            "_LIST_USER_SESSIONS",
            "redis.eval(",
            "_COMPARE_AND_DELETE",
        ),
        "auth service": (
            "async def issue_access_token(",
            "await login_session_repository.register_login_session(",
        ),
        "environment": ("JWT_ACCESS_TOKEN_TTL_SECONDS=86400",),
        "settings tests": (
            "test_access_token_lifetime_defaults_to_twenty_four_hours_and_is_configurable",
            "test_issuer_and_audience_are_disabled_by_default",
            "test_issuer_and_audience_can_be_enabled_together",
            "test_issuer_and_audience_must_be_a_complete_nonblank_pair",
        ),
        "security tests": (
            "test_issuer_uses_configured_access_token_lifetime",
            "test_valid_access_token_resolves_only_fixed_claims",
            "test_default_mode_rejects_each_missing_required_claim",
            "test_default_mode_rejects_optional_scope_claims",
            "test_configured_issuer_and_audience_mode_accepts_exact_seven_claims",
            "test_configured_issuer_and_audience_mode_rejects_invalid_scope",
            "test_configured_issuer_and_audience_mode_rejects_each_missing_claim",
            "test_configured_scope_uses_the_same_active_jti_lifecycle",
        ),
    }
    for name, markers in required_markers.items():
        for marker in markers:
            if marker not in text[name]:
                relative = paths[name].relative_to(REPO_ROOT)
                fail(
                    errors, f"{relative} is missing Access Token invariant: {marker!r}"
                )

    # 2. 老模块不能继续保留为转发入口；Redis 仓储只管理已生成的登录信息，不签发 JWT。
    old_registry = ASSET_ROOT / "app" / "core" / "security" / "session_registry.py"
    if old_registry.exists():
        fail(errors, "Redis login access must not retain the old core session registry")
    repository_tree = _parse_python(errors, paths["login repository"], label="Redis login repository")
    repository_class = _class_node(repository_tree, "LoginSessionRepository") if repository_tree else None
    repository_methods = {
        node.name for node in repository_class.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    } if repository_class is not None else set()
    required_repository_methods = {
        "register_login_session", "check_login_session", "delete_login_session", "list_active_sessions",
    }
    if not required_repository_methods.issubset(repository_methods):
        fail(errors, "Redis login repository must own registration, validation, deletion and listing")
    if repository_tree is not None and any(
        isinstance(node, ast.ImportFrom) and node.module == "app.core.security.jwt_tokens"
        and any(alias.name not in {"AccessTokenInfo", "integer_numeric_date"} for alias in node.names)
        or isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "issue_access_token"
        for node in ast.walk(repository_tree)
    ):
        fail(errors, "Redis login repository must not sign or decode JWTs or orchestrate Token issuance")

    # 3. 默认示例不能启用签发者/使用方；请求鉴权仍须先查 Redis，再查 PostgreSQL 账号。
    active_optional_scope = re.compile(r"^\s*JWT_(?:ISSUER|AUDIENCE)\s*=")
    if any(
        active_optional_scope.match(line)
        for line in text["environment"].splitlines()
        if not line.lstrip().startswith("#")
    ):
        fail(
            errors,
            ".env.example must leave optional JWT_ISSUER/JWT_AUDIENCE disabled",
        )

    dependency_tree = _parse_python(errors, paths["dependencies"], label="authentication dependencies")
    token_check = _function_node(dependency_tree.body, "check_token") if dependency_tree else None
    token_calls = {
        ast.unparse(node.func): node.lineno
        for node in ast.walk(token_check) if isinstance(node, ast.Call)
    } if token_check is not None else {}
    decode_position = token_calls.get("decode_access_token")
    redis_position = token_calls.get("login_session_repository.check_login_session")
    if (decode_position is None or redis_position is None or decode_position >= redis_position
            or "SessionFactory" in token_calls or "user_repository.check_current_user" in token_calls):
        fail(errors, "Token dependency must verify JWT then Redis without loading PostgreSQL authority")

    if re.search(
        r"""[\"']ver[\"']\s*:|(?:token_fields|payload)\s*\[\s*[\"']ver[\"']\s*\]""", text["JWT codec"]
    ):
        fail(errors, "asset JWT code must not contain a ver claim")

    forbidden_patterns = (
        re.compile(r"refresh[_\s-]+token", re.IGNORECASE),
        re.compile(r"authentication[_\s-]+sessions?", re.IGNORECASE),
        re.compile(
            r"postgresql[_\s]+(?:token|authentication)[_\s]+sessions?", re.IGNORECASE
        ),
    )
    executable_paths = tuple(
        path
        for path in ASSET_ROOT.rglob("*")
        if path.is_file() and path.suffix.lower() in {".py", ".sql"}
    )
    for path in executable_paths:
        content = path.read_text(encoding="utf-8")
        # 日志把常见敏感字段写入脱敏清单，不代表实现了刷新令牌；只排除这份纯字符串声明。
        if path == ASSET_ROOT / "app" / "core" / "logging" / "details.py":
            logging_tree = _parse_python(errors, path, label="HTTP log redaction")
            for node in logging_tree.body if logging_tree is not None else ():
                if (isinstance(node, ast.Assign) and len(node.targets) == 1
                        and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "_REDACTED_FIELDS"
                        and isinstance(node.value, ast.Call) and ast.unparse(node.value.func) == "frozenset"
                        and len(node.value.args) == 1 and isinstance(node.value.args[0], ast.Set)
                        and all(isinstance(field, ast.Constant) and isinstance(field.value, str)
                                for field in node.value.args[0].elts)):
                    declaration = ast.get_source_segment(content, node)
                    if declaration is not None:
                        content = content.replace(declaration, "", 1)
        for pattern in forbidden_patterns:
            if pattern.search(content):
                relative = path.relative_to(REPO_ROOT)
                fail(
                    errors,
                    f"{relative} reintroduces a forbidden authentication concept: "
                    f"{pattern.pattern!r}",
                )


def _parse_python(
    errors: list[str],
    path: Path,
    *,
    label: str,
) -> ast.Module | None:
    try:
        return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError, UnicodeDecodeError) as exc:
        fail(
            errors, f"cannot parse {label} {path.relative_to(REPO_ROOT)}: {exc}")
        return None


def _module_literals(tree: ast.Module) -> dict[str, object]:
    values: dict[str, object] = {}
    for node in tree.body:
        name: str | None = None
        value: ast.expr | None = None
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            name = node.target.id
            value = node.value
        elif (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            name = node.targets[0].id
            value = node.value
        if name is None or value is None:
            continue
        try:
            values[name] = ast.literal_eval(value)
        except (TypeError, ValueError):
            continue
    return values


def _class_node(tree: ast.Module, name: str) -> ast.ClassDef | None:
    return next(
        (
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == name
        ),
        None,
    )


def _function_node(
    nodes: list[ast.stmt],
    name: str,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    return next(
        (
            node
            for node in nodes
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == name
        ),
        None,
    )


def _returned_names(node: ast.Return) -> tuple[str, ...] | None:
    value = node.value
    if isinstance(value, ast.Name):
        return (value.id,)
    if not isinstance(value, (ast.Tuple, ast.List)):
        return None
    if not all(isinstance(item, ast.Name) for item in value.elts):
        return None
    return tuple(item.id for item in value.elts if isinstance(item, ast.Name))


def _validate_field_contract(tree: ast.Module, class_name: str, field_name: str,
                             annotation: str, keywords: dict[str, str], errors: list[str]) -> None:
    """
        按真实字段语法校验必填类型及指定约束，允许换行和补充文档说明。

    :param tree: 仅解析、不会执行的模型源码语法树。
    :param class_name: 声明字段的模型类名。
    :param field_name: 必须保持合同的字段名。
    :param annotation: 预期的字段类型表达式。
    :param keywords: 必须保留的 Field 参数及其表达式。
    :param errors: 接收合同错误的列表。
    :return: 无返回值；缺失、非必填或约束错误时追加错误。
    """
    model = _class_node(tree, class_name)
    field = next((
        node for node in model.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == field_name
    ), None) if model is not None else None
    declaration = field.value if field is not None else None
    if (
        field is None
        or ast.unparse(field.annotation) != annotation
        or not isinstance(declaration, ast.Call)
        or ast.unparse(declaration.func) != "Field"
        or declaration.args
    ):
        fail(
            errors, f"{class_name}.{field_name} must be a required {annotation} Field")
        return
    actual = {keyword.arg: keyword.value for keyword in declaration.keywords}
    if any(name in actual for name in (None, "default", "default_factory")):
        fail(
            errors, f"{class_name}.{field_name} must remain required without a default")
    for name, expected in keywords.items():
        value = actual.get(name)
        if value is None or ast.dump(value) != ast.dump(ast.parse(expected, mode="eval").body):
            fail(
                errors, f"{class_name}.{field_name} must keep {name}={expected}")


def _validate_role_schema_contract(tree: ast.Module, errors: list[str]) -> None:
    """
        校验三个角色写入请求的严格版本号，以及权限 ID 批次边界。

    :param tree: 角色请求源码的语法树，不受 Field 换行或说明文字影响。
    :param errors: 接收丢失严格整数校验或数量边界等错误的列表。
    :return: 无返回值；检查结果追加到 errors。
    """
    for class_name in ("RoleUpdateRequest", "RoleVersionRequest", "RolePermissionIdsRequest"):
        _validate_field_contract(
            tree, class_name, "expected_version", "int", {
                "strict": "True", "ge": "0"}, errors
        )
    _validate_field_contract(
        tree, "RolePermissionIdsRequest", "permission_ids", "list[PermissionId]",
        {"min_length": "1", "max_length": "100"}, errors,
    )


def _validate_runtime_message_literals(tree: ast.Module, errors: list[str], *, label: str) -> None:
    """
        允许字段说明及用户名规则的双语字符标签，拒绝其他绕开多语言目录的中文文案。

    :param tree: 应用源码语法树；不导入或执行应用。
    :param errors: 接收运行时硬编码中文文案错误的列表。
    :param label: 错误信息使用的源码相对路径。
    :return: 无返回值；发现不属于文档或指定规则标签的中文字符串时追加错误。
    """
    # 仅豁免真正的文档字符串及 Field/Query 声明中的 description，不豁免整个模型或路由。
    documented = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        and ast.get_docstring(node) is not None
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and ast.unparse(node.func) in {"Field", "Query"}:
            documented.update(
                id(part) for keyword in node.keywords
                if keyword.arg == "description" and isinstance(keyword.value, (ast.Constant, ast.JoinedStr))
                for part in ast.walk(keyword.value) if isinstance(part, ast.Constant)
            )

    # 用户名允许字符的双语标签与字符规则一起维护；只放行该文件的这个文字常量。
    # 完整错误句仍由语言目录提供，同文件其他中文返回值和异常继续检查。
    if label.replace("\\", "/").endswith("/app/core/security/user_name.py"):
        documented.update(
            id(node.value) for node in tree.body
            if isinstance(node, ast.Assign) and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "USER_NAME_CHARACTERS_ZH"
            and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
        )

    # Redis Lua 的独立注释行用于解释代码，不是接口文案；脚本内真实字符串仍然检查。
    lua_script_names = {
        "FIXED_WINDOW_SCRIPT", "_SESSION_FUNCTIONS",
        "_ACTIVATE_JTI", "_COMPARE_AND_DELETE", "_READ_ACTIVE_JTI", "_LIST_USER_SESSIONS",
    }
    script_content: dict[int, str] = {}
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names, value = {node.target.id}, node.value
        elif isinstance(node, ast.Assign):
            names = {target.id for target in node.targets if isinstance(
                target, ast.Name)}
            value = node.value
        else:
            continue
        if names & lua_script_names and value is not None:
            for literal in ast.walk(value):
                if isinstance(literal, ast.Constant) and isinstance(literal.value, str):
                    script_content[id(literal)] = re.sub(
                        r"(?m)^\s*--[^\n]*", "", literal.value)

    # 下列变量仅声明 OpenAPI 响应文档；仍只接受 description 值，其他键中的中文照常报错。
    metadata_names = {
        "REQUEST_ID_OPENAPI_HEADER",
        "NO_STORE_OPENAPI_HEADER",
        "RATE_LIMIT_OPENAPI_HEADERS",
    }
    metadata_nodes: list[ast.AST] = []
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id in metadata_names and node.value is not None:
                metadata_nodes.append(node.value)
        elif isinstance(node, ast.FunctionDef) and node.name == "_role_update_json_schema":
            # 此回调仅原位调整两个字段的文档；不豁免任意返回值、异常或局部变量。
            metadata_nodes.extend(
                statement.value for statement in node.body
                if isinstance(statement, ast.Assign) and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Subscript)
                and isinstance(statement.targets[0].value, ast.Name)
                and statement.targets[0].value.id == "properties"
                and isinstance(statement.targets[0].slice, ast.Constant)
                and statement.targets[0].slice.value in {"name", "description"}
                and isinstance(statement.value, ast.Dict)
            )
    for metadata in metadata_nodes:
        for node in ast.walk(metadata):
            if isinstance(node, ast.Dict):
                documented.update(
                    id(value) for key, value in zip(node.keys, node.values, strict=True)
                    if isinstance(key, ast.Constant) and key.value == "description"
                    and isinstance(value, ast.Constant)
                )
            # 常见错误文档使用状态码 → description 的静态字典生成；不放行任意生成器内容。
            if (
                isinstance(node, ast.DictComp)
                and isinstance(node.key, ast.Name) and node.key.id == "status_code"
                and isinstance(node.value, ast.Dict)
                and any(
                    isinstance(
                        key, ast.Constant) and key.value == "description"
                    and isinstance(value, ast.Name) and value.id == "description"
                    for key, value in zip(node.value.keys, node.value.values, strict=True)
                )
            ):
                for generator in node.generators:
                    iterator = generator.iter
                    if (
                        ast.unparse(
                            generator.target) == "(status_code, description)"
                        and isinstance(iterator, ast.Call) and not iterator.args and not iterator.keywords
                        and isinstance(iterator.func, ast.Attribute) and iterator.func.attr == "items"
                        and isinstance(iterator.func.value, ast.Dict)
                    ):
                        documented.update(
                            id(value) for key, value in zip(
                                iterator.func.value.keys, iterator.func.value.values, strict=True
                            )
                            if isinstance(key, ast.Constant) and type(key.value) is int
                            and 400 <= key.value <= 599 and isinstance(value, ast.Constant)
                        )
    if any(
        isinstance(node, ast.Constant) and isinstance(node.value, str)
        and id(node) not in documented
        and re.search(r"[\u4e00-\u9fff]", script_content.get(id(node), node.value))
        for node in ast.walk(tree)
    ):
        fail(
            errors, f"{label} contains rendered Chinese API text outside catalogs")


def _validate_authentication_schema_contract(tree: ast.Module, errors: list[str]) -> None:
    """
        校验旧密码和新密码分别使用直接字段约束，避免新策略阻止原密码验证。

    :param tree: 身份请求模型的语法树，只解析源码，不导入应用或连接服务。
    :param errors: 本次校验发现的具体合同问题列表。
    :return: 无返回值；发现的问题追加到 errors。
    """
    aliases = {
        node.targets[0].id: node.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
    }
    if "ExistingPassword" in aliases or _function_node(
        tree.body, "_validate_new_password_length"
    ) is not None:
        fail(errors, "password inputs must not restore ExistingPassword or a custom length validator")
    # 两种字段都直接使用 SecretStr + Field；旧密码只有传输边界，新密码单独读取策略上下限。
    for name, minimum, maximum in (
        ("Password", "1", "MAX_PASSWORD_INPUT_CHARACTERS"),
        ("NewPassword", "MIN_PASSWORD_CHARACTERS", "MAX_PASSWORD_CHARACTERS"),
    ):
        alias = aliases.get(name)
        if (
            not isinstance(alias, ast.Subscript)
            or ast.unparse(alias.value) != "Annotated"
            or not isinstance(alias.slice, ast.Tuple)
            or not alias.slice.elts
            or ast.unparse(alias.slice.elts[0]) != "SecretStr"
        ):
            fail(errors, f"{name} must remain an Annotated SecretStr alias")
            continue
        fields = [node for node in alias.slice.elts
                  if isinstance(node, ast.Call) and ast.unparse(node.func) == "Field"]
        if len(fields) != 1 or len(alias.slice.elts) != 2:
            fail(
                errors, f"{name} must use only SecretStr and one Field contract")
        if len(fields) == 1:
            keywords = {item.arg: item.value for item in fields[0].keywords}
            if any(
                ast.unparse(keywords.get(key, ast.Constant(None))) != expected
                for key, expected in {"min_length": minimum, "max_length": maximum}.items()
            ) or "json_schema_extra" in keywords:
                fail(
                    errors, f"{name} must enforce its character bounds directly in Field")

    schema_class_fields: dict[str, dict[str, str]] = {}
    required_secret_fields = {
        "RegisterRequest": {"password": "NewPassword"},
        "LoginRequest": {"password": "Password"},
        "PasswordChangeRequest": {"current_password": "Password", "new_password": "NewPassword"},
        "UserPasswordResetRequest": {"new_password": "NewPassword"},
        "UserCreateRequest": {"password": "NewPassword"},
    }
    for class_name, field_contracts in required_secret_fields.items():
        node = _class_node(tree, class_name)
        actual = {
            item.target.id: ast.unparse(item.annotation)
            for item in node.body
            if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name)
        } if node is not None else {}
        schema_class_fields[class_name] = actual
        for field_name, expected in field_contracts.items():
            if actual.get(field_name) != expected:
                fail(
                    errors, f"{class_name}.{field_name} must use the SecretStr-based {expected} contract")
    if set(schema_class_fields.get("UserPasswordResetRequest", {})) != {"new_password", "user_id"}:
        fail(errors, "UserPasswordResetRequest must expose only user_id and new_password beyond CAPTCHA fields")

    username_request = _class_node(tree, "UsernameRequest")
    username_field = next((
        item.value for item in username_request.body
        if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name) and item.target.id == "user_name"
    ), None) if username_request is not None else None
    # 用户名规则由业务文件维护；这里检查字段是否复用它，避免维护检查另存一份数字。
    username_keywords = {
        item.arg: ast.unparse(item.value)
        for item in username_field.keywords
    } if isinstance(username_field, ast.Call) and ast.unparse(username_field.func) == "Field" else {}
    if any(username_keywords.get(name) != expected for name, expected in {
        "min_length": "MIN_USER_NAME_LENGTH", "max_length": "MAX_USER_NAME_LENGTH", "pattern": "USER_NAME_PATTERN",
    }.items()):
        fail(errors, "username OpenAPI contract must reuse the central username length and character rules")


def validate_local_password_authentication(errors: list[str]) -> None:
    """
        核对本地账号、密码和完整登录链路的源码合同，不运行应用或访问数据库。

    :param errors: 收集缺失文件、字段和调用顺序等具体问题的列表。
    :return: 无返回值；不符合约定的内容追加到 errors。
    """
    # 先收集各业务真实维护的文件，再解析其中的模型、接口和方法；不执行这些源码。
    paths = {
        "skill": SKILL_ROOT / "SKILL.md",
        "reference": SKILL_ROOT / "references" / "local-password-authentication.md",
        "README": REPO_ROOT / "README.md",
        "Chinese README": REPO_ROOT / "README.zh-CN.md",
        "environment": ASSET_ROOT / ".env.example",
        "pyproject": ASSET_ROOT / "pyproject.toml",
        "main": ASSET_ROOT / "app" / "main.py",
        "settings": ASSET_ROOT / "app" / "core" / "config.py",
        "passwords": ASSET_ROOT / "app" / "core" / "security" / "passwords.py",
        "audit actions": ASSET_ROOT / "app" / "core" / "audit.py",
        "models": ASSET_ROOT / "app" / "models" / "postgres" / "operation_audit.py",
        "users model": ASSET_ROOT / "app" / "models" / "postgres" / "user.py",
        "state model": ASSET_ROOT / "app" / "models" / "postgres" / "rbac_state.py",
        "schemas": ASSET_ROOT / "app" / "schemas" / "auth.py",
        "common schemas": ASSET_ROOT / "app" / "schemas" / "common.py",
        "captcha schemas": ASSET_ROOT / "app" / "schemas" / "captcha.py",
        "user schemas": ASSET_ROOT / "app" / "schemas" / "user.py",
        "API": ASSET_ROOT / "app" / "api" / "v1" / "endpoints" / "auth.py",
        "account API": ASSET_ROOT / "app" / "api" / "v1" / "endpoints" / "users.py",
        "self API": ASSET_ROOT / "app" / "api" / "v1" / "endpoints" / "me.py",
        "API router": ASSET_ROOT / "app" / "api" / "v1" / "router.py",
        "service": ASSET_ROOT / "app" / "services" / "auth_service.py",
        "user service": ASSET_ROOT / "app" / "services" / "user_service.py",
        "password repository": ASSET_ROOT / "app" / "repositories" / "postgres" / "user_repository.py",
        "security audit service": ASSET_ROOT / "app" / "services" / "audit_service.py",
        "operator": ASSET_ROOT / "app" / "commands" / "reset_super_admin_password.py",
        "operator service": ASSET_ROOT / "app" / "commands" / "operator_password_service.py",
        "Alembic environment": ASSET_ROOT / "alembic" / "env.py",
        "model registry": ASSET_ROOT / "app" / "models" / "postgres" / "__init__.py",
        "migration": (ASSET_ROOT / "alembic" / "versions" / "0004_password_auth.py"),
        "API tests": ASSET_ROOT / "tests" / "test_auth_api.py",
        "service tests": ASSET_ROOT / "tests" / "test_auth_service.py",
        "password tests": ASSET_ROOT / "tests" / "test_passwords.py",
        "PostgreSQL authentication tests": (
            ASSET_ROOT / "tests" / "integration" / "test_password_authentication.py"
        ),
        "PostgreSQL persistence tests": (
            ASSET_ROOT / "tests" / "integration" / "test_password_persistence.py"
        ),
    }
    missing = False
    for label, path in paths.items():
        if not path.is_file():
            fail(
                errors,
                f"missing local-password {label}: {path.relative_to(REPO_ROOT)}",
            )
            missing = True
    if missing:
        return

    text = {label: path.read_text(encoding="utf-8")
            for label, path in paths.items()}
    trees: dict[str, ast.Module] = {}
    for label in (
        "main",
        "settings",
        "passwords",
        "audit actions",
        "models",
        "users model",
        "schemas",
        "common schemas",
        "captcha schemas",
        "user schemas",
        "API",
        "account API",
        "self API",
        "API router",
        "service",
        "user service",
        "operator",
        "operator service",
        "migration",
    ):
        tree = _parse_python(errors, paths[label], label=label)
        if tree is None:
            return
        trees[label] = tree

    question_markers = (
        "Is username comparison case-sensitive?",
        "must the password contain uppercase,",
        "maximum simultaneously active login count",
        "If existing users have no password",
    )
    for marker in question_markers:
        if marker not in text["reference"]:
            fail(
                errors, f"local-password product-question batch is missing {marker!r}")
    normalized_reference = re.sub(r"\s+", " ", text["reference"])
    for marker in (
        "Do not invent",
        "neither behavior is a generic recommendation",
        "required notice, not another blocking choice",
    ):
        if marker not in normalized_reference:
            fail(
                errors,
                f"local-password decision boundary is missing {marker!r}",
            )
    if "interactive operator command" not in text["reference"]:
        fail(errors, "local-password reference must retain offline operator recovery")

    api_labels = ("API", "account API", "self API")
    text["API"] = "\n".join(text[label] for label in api_labels)
    routes: set[tuple[str, str, str]] = set()
    expected_prefixes = {"API": "/auth",
                         "account API": "/users", "self API": "/me"}
    version_router = next((
        node.value for node in trees["API router"].body
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
        and ast.unparse(node.value.func) == "APIRouter"
    ), None)
    version_prefix = next((
        keyword.value.value for keyword in version_router.keywords
        if keyword.arg == "prefix" and isinstance(keyword.value, ast.Constant)
    ), None) if version_router is not None else None
    if version_prefix != "/api/v1":
        fail(errors, "API assembly router must own the /api/v1 version prefix")
        version_prefix = ""
    # 不同业务文件均可名为 router；必须先在各自模块解析前缀，再校验完整路径。
    for label in api_labels:
        prefixes: dict[str, str] = {}
        for node in trees[label].body:
            if not (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Call)
                and ast.unparse(node.value.func) == "APIRouter"
            ):
                continue
            prefix = next(
                (keyword.value for keyword in node.value.keywords if keyword.arg == "prefix"), None)
            if not isinstance(prefix, ast.Constant) or prefix.value != expected_prefixes[label]:
                fail(
                    errors, f"{label} must use the {expected_prefixes[label]} business prefix")
                continue
            prefixes[node.targets[0].id] = prefix.value
        for node in trees[label].body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and isinstance(decorator.func.value, ast.Name)
                    and decorator.func.attr.lower() in {"get", "post", "put", "patch", "delete"}
                    and decorator.args
                    and isinstance(decorator.args[0], ast.Constant)
                    and isinstance(decorator.args[0].value, str)
                ):
                    continue
                prefix = prefixes.get(decorator.func.value.id)
                if prefix is None:
                    fail(
                        errors, f"{label}.{node.name} has an unresolved router prefix")
                    continue
                routes.add((decorator.func.attr.lower(), version_prefix +
                           prefix + decorator.args[0].value, node.name))
    expected_routes = {
        ("post", "/api/v1/auth/captcha", "create_public_captcha"),
        ("post", "/api/v1/auth/register", "register"),
        ("post", "/api/v1/auth/login", "login"),
        ("post", "/api/v1/auth/logout", "logout"),
        ("post", "/api/v1/me/captcha", "create_authenticated_captcha"),
        ("post", "/api/v1/me/password/change", "change_my_password"),
        ("get", "/api/v1/me/user_info", "get_user_info"),
        ("get", "/api/v1/users/sessions/list", "list_user_sessions"),
        ("get", "/api/v1/users/list", "list_users"),
        ("get", "/api/v1/users/detail", "get_user_detail"),
        ("post", "/api/v1/users/create", "create_user"),
        ("post", "/api/v1/users/password/reset", "reset_user_password"),
        ("post", "/api/v1/users/roles/bind", "bind_user_roles"),
        ("post", "/api/v1/users/roles/unbind", "unbind_user_roles"),
        ("post", "/api/v1/users/disable", "disable_user"),
        ("post", "/api/v1/users/enable", "enable_user"),
        ("post", "/api/v1/users/sessions/logout-all", "revoke_user_sessions"),
    }
    missing_routes = expected_routes - routes
    if missing_routes:
        fail(
            errors, f"local-password API is missing routes: {missing_routes!r}")
    unexpected_routes = sorted(
        route for route in routes if route not in expected_routes
    )
    if unexpected_routes:
        fail(
            errors,
            f"local-password API contains unexpected routes: {unexpected_routes!r}",
        )

    installed_routers = {
        ast.unparse(node.value.args[0])
        for node in trees["API router"].body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and ast.unparse(node.value.func) == "router.include_router"
        and len(node.value.args) == 1
    }
    if not {
        "auth.router",
        "me.router",
        "users.router",
        "roles.router",
        "permissions.router",
    }.issubset(installed_routers):
        fail(
            errors,
            "all authentication routers must remain installed",
        )

    active_environment = {
        key.strip(): value.strip()
        for line in text["environment"].splitlines()
        if line.strip() and not line.lstrip().startswith("#") and "=" in line
        for key, value in (line.split("=", 1),)
    }
    if "PUBLIC_REGISTRATION_ENABLED" in active_environment:
        fail(
            errors,
            "public registration must not reintroduce a deployment switch",
        )
    if "ADMIN_PASSWORD_RESET_MODE" in active_environment:
        fail(errors, "administrator password reset must not expose a mode switch")
    for label, marker in (
        ("state model", "public_registration_enabled"),
        ("service", "set_registration_enabled"),
        ("service", "state.public_registration_enabled"),
        ("schemas", "RegistrationStatusData"),
        ("API", "get_registration_status"),
        ("API", "update_registration_status"),
    ):
        if marker in text[label]:
            fail(
                errors, f"{label} reintroduces the removed registration switch")

    password_constants = _module_literals(trees["passwords"])
    expected_password_constants = {
        "ARGON2_MEMORY_COST_KIB": 65_536,
        "ARGON2_TIME_COST": 3,
        "ARGON2_PARALLELISM": 4,
        "ARGON2_HASH_LENGTH": 32,
        "ARGON2_SALT_LENGTH": 16,
        "MIN_PASSWORD_CHARACTERS": 8,
        "MAX_PASSWORD_CHARACTERS": 32,
        "MAX_PASSWORD_INPUT_CHARACTERS": 1024,
        "DEFAULT_MAX_CONCURRENT_OPERATIONS": 2,
    }
    for name, expected in expected_password_constants.items():
        if password_constants.get(name) != expected:
            fail(errors, f"password constant {name} must be {expected!r}")

    hasher_configuration: dict[str, str] | None = None
    for node in ast.walk(trees["passwords"]):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "PasswordHasher"
        ):
            hasher_configuration = {
                keyword.arg: ast.unparse(keyword.value)
                for keyword in node.keywords
                if keyword.arg is not None
            }
            break
    expected_hasher_configuration = {
        "time_cost": "ARGON2_TIME_COST",
        "memory_cost": "ARGON2_MEMORY_COST_KIB",
        "parallelism": "ARGON2_PARALLELISM",
        "hash_len": "ARGON2_HASH_LENGTH",
        "salt_len": "ARGON2_SALT_LENGTH",
        "type": "Type.ID",
    }
    if hasher_configuration != expected_hasher_configuration:
        fail(errors, "PasswordHasher must use every fixed Argon2id baseline constant")
    password_calls = {
        ast.unparse(node.func)
        for node in ast.walk(trees["passwords"])
        if isinstance(node, ast.Call)
    }
    if (
        "asyncio.to_thread" not in password_calls
        or "asyncio.Semaphore" not in password_calls
    ):
        fail(errors, "Argon2 work must be offloaded and protected by a local semaphore")

    pyproject = tomllib.loads(text["pyproject"])
    dependencies = pyproject.get("project", {}).get("dependencies", [])
    if not isinstance(dependencies, list) or not any(
        isinstance(item, str) and item.startswith("argon2-cffi")
        for item in dependencies
    ):
        fail(errors, "asset pyproject.toml must directly depend on argon2-cffi")

    schema_contract = ast.Module(
        body=[*trees["common schemas"].body, *trees["captcha schemas"].body,
              *trees["schemas"].body, *trees["user schemas"].body], type_ignores=[])
    _validate_authentication_schema_contract(schema_contract, errors)

    user_model = _class_node(trees["users model"], "User")
    audit_model = _class_node(trees["models"], "OperationAuditEvent")
    if user_model is None or audit_model is None:
        fail(errors, "user password fields and account-security audit are required")
    else:
        audit_table = next(
            (
                ast.literal_eval(node.value)
                for node in audit_model.body
                if isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "__tablename__"
            ),
            None,
        )
        if audit_table != "operation_audit_events":
            fail(errors, "OperationAuditEvent table name is incorrect")
        password_fields = {
            node.target.id
            for node in user_model.body
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
        }
        expected_fields = {
            "password_hash",
            "password_changed_at",
        }
        if not expected_fields.issubset(password_fields):
            fail(
                errors,
                "User is missing password-state fields: "
                f"{sorted(expected_fields - password_fields)!r}",
            )
    if _class_node(trees["models"], "PasswordCredential") is not None:
        fail(errors, "password state must not use a separate credential model")
    for marker in (
        'name="password_hash_shape"',
        'name="password_state_coherent"',
        'name="deleted_user_no_password"',
        "password_changed_at IS NULL",
        "deleted_at IS NULL OR password_hash IS NULL",
    ):
        if marker not in text["users model"]:
            fail(
                errors, f"User password-state constraint is missing {marker!r}")

    migration_literals = _module_literals(trees["migration"])
    if (
        migration_literals.get("revision") != "0004_password_auth"
        or migration_literals.get("down_revision") != "0003_business_audit"
    ):
        fail(errors, "0004_password_auth must directly follow 0003_business_audit")
    migration_calls: dict[str, list[str]] = {
        "create_table": [], "drop_table": []}
    added_columns: list[str] = []
    dropped_columns: list[str] = []
    for node in ast.walk(trees["migration"]):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in migration_calls
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            migration_calls[node.func.attr].append(node.args[0].value)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "users"
        ):
            if node.func.attr == "add_column":
                column = node.args[1]
                if (
                    isinstance(column, ast.Call)
                    and isinstance(column.func, ast.Attribute)
                    and column.func.attr == "Column"
                    and column.args
                    and isinstance(column.args[0], ast.Constant)
                    and isinstance(column.args[0].value, str)
                ):
                    added_columns.append(column.args[0].value)
            elif (
                node.func.attr == "drop_column"
                and isinstance(node.args[1], ast.Constant)
                and isinstance(node.args[1].value, str)
            ):
                dropped_columns.append(node.args[1].value)
    if "user_password_credentials" in (
        migration_calls["create_table"] + migration_calls["drop_table"]
    ):
        fail(errors, "migration must not create or drop a password-episode table")
    audit_table_name = "account_security_audit_events"
    if migration_calls["create_table"].count(audit_table_name) != 1:
        fail(errors, "migration must create account-security audit exactly once")
    if migration_calls["drop_table"].count(audit_table_name) != 1:
        fail(errors, "migration must drop account-security audit exactly once")
    for field in ("password_hash", "must_change_password", "password_changed_at"):
        if added_columns.count(field) != 1 or dropped_columns.count(field) != 1:
            fail(errors, f"0004 must add and drop users.{field} exactly once")
    for constraint in (
        "ck_users_password_hash_shape",
        "ck_users_password_state_coherent",
        "ck_users_deleted_user_no_password",
    ):
        if constraint not in text["migration"]:
            fail(errors, f"0004 must install {constraint}")

    revisions: dict[str, str | None] = {}
    for path in sorted((ASSET_ROOT / "alembic" / "versions").glob("*.py")):
        tree = _parse_python(errors, path, label="Alembic revision")
        if tree is None:
            return
        literals = _module_literals(tree)
        revision = literals.get("revision")
        down_revision = literals.get("down_revision")
        if not isinstance(revision, str):
            fail(errors, f"Alembic file has no literal revision: {path.name}")
            continue
        if down_revision is not None and not isinstance(down_revision, str):
            fail(
                errors, f"Alembic file has unsupported down_revision: {path.name}")
            continue
        if revision in revisions:
            fail(errors, f"duplicate Alembic revision: {revision}")
        revisions[revision] = down_revision
    heads = set(revisions) - \
        {parent for parent in revisions.values() if parent}
    if heads != {"0004_password_auth"}:
        fail(
            errors, f"0004_password_auth must be the sole migration head, got {heads!r}"
        )

    append_only_markers = (
        "reject_account_security_audit_mutation",
        "BEFORE UPDATE OR DELETE ON account_security_audit_events",
        "BEFORE TRUNCATE ON account_security_audit_events",
    )
    for marker in append_only_markers:
        if marker not in text["migration"]:
            fail(errors, f"account-security audit is missing {marker!r}")

    service_class = _class_node(trees["service"], "AuthService")
    service_methods = (
        {
            node.name
            for node in service_class.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        if service_class is not None
        else set()
    )
    required_methods = {
        "register",
        "login",
        "issue_access_token",
        "change_password",
    }
    if not required_methods.issubset(service_methods):
        fail(
            errors,
            f"local authentication service is missing {required_methods - service_methods!r}",
        )
    # 登录业务必须在同一个方法中完成签发；先退出数据库事务，不能拿着行锁等待 Redis。
    login_method = _function_node(
        service_class.body, "login") if service_class is not None else None
    issuer_calls = [
        node for node in ast.walk(login_method)
        if isinstance(node, ast.Await) and isinstance(node.value, ast.Call)
        and ast.unparse(node.value.func) == "self.issue_access_token"
    ] if login_method is not None else []
    if len(issuer_calls) != 1:
        fail(errors, "AuthService.login must await its Token issuer exactly once")
    elif login_method is not None:
        issuer = issuer_calls[0]
        if any(
            isinstance(node, (ast.With, ast.AsyncWith)
                       ) and issuer in ast.walk(node)
            for node in ast.walk(login_method)
        ):
            fail(
                errors, "AuthService.login must issue the Token after leaving database contexts")
        result_returns = [
            node for node in ast.walk(login_method)
            if isinstance(node, ast.Return) and isinstance(node.value, ast.Call)
            and ast.unparse(node.value.func) == "LoginResult"
        ]
        if (login_method.returns is None or ast.unparse(login_method.returns) != "LoginResult"
                or len(result_returns) != 1
                or result_returns[0].lineno <= issuer.lineno):
            fail(
                errors, "AuthService.login must return LoginResult only after confirmed issuance")
    # 业务层先签名，再交给仓储登记；只有确认登记成功的分支才可返回 Token。
    issuer_method = _function_node(
        service_class.body, "issue_access_token") if service_class is not None else None
    registration_calls = [
        node for node in ast.walk(issuer_method)
        if isinstance(node, ast.Await) and isinstance(node.value, ast.Call)
        and ast.unparse(node.value.func) == "login_session_repository.register_login_session"
    ] if issuer_method is not None else []
    token_returns = [
        node for node in ast.walk(issuer_method)
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Name) and node.value.id == "token"
    ] if issuer_method is not None else []
    if (len(registration_calls) != 1 or len(token_returns) != 1
            or token_returns[0].lineno <= registration_calls[0].lineno):
        fail(errors, "AuthService issuer must register the signed Token before returning it")
    elif issuer_method is not None:
        registration = registration_calls[0]
        confirmed_returns = [
            node for node in ast.walk(issuer_method)
            if isinstance(node, ast.If) and ast.unparse(node.test) == "registered"
            and token_returns[0] in ast.walk(node)
        ]
        if len(confirmed_returns) != 1:
            fail(errors, "AuthService issuer must return a Token only after confirmed registration")
        if any(
            isinstance(node, (ast.With, ast.AsyncWith)) and registration in ast.walk(node)
            for node in ast.walk(issuer_method)
        ):
            fail(errors, "AuthService issuer must register Redis sessions outside database contexts")
    operator_service_class = _class_node(
        trees["operator service"], "OperatorPasswordService")
    operator_methods = {
        node.name for node in operator_service_class.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    } if operator_service_class is not None else set()
    if "reset_super_admin_password" not in operator_methods:
        fail(errors, "offline operator recovery service is missing reset_super_admin_password")
    user_service_class = _class_node(trees["user service"], "UserService")
    user_service_methods = {
        node.name for node in user_service_class.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    } if user_service_class is not None else set()
    required_user_methods = {
        "create_user", "admin_create_user", "reset_user_password"}
    if not required_user_methods.issubset(user_service_methods):
        fail(
            errors, f"user service is missing {required_user_methods - user_service_methods!r}")
    # 动作只在核心枚举定义一次，业务直接传成员，由统一审计入口判断所属分类。
    expected_actions = {
        "REGISTER_USER": ("account_security.registration.completed", "service"),
        "ADMIN_CREATE_USER": ("account_security.registration.admin_created", "user service"),
        "CHANGE_PASSWORD": ("account_security.password.changed", "service"),
        "ADMIN_RESET_PASSWORD": ("account_security.password.admin_reset", "user service"),
        "OPERATOR_RESET_PASSWORD": ("account_security.password.operator_reset", "operator service"),
    }
    action_catalog = _class_node(trees["audit actions"], "AccountAuditAction")
    action_values = {
        node.targets[0].id: node.value.value
        for node in action_catalog.body if isinstance(node, ast.Assign)
        and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
        and isinstance(node.value, ast.Constant)
    } if action_catalog is not None else {}
    for member, (action, label) in expected_actions.items():
        if action_values.get(member) != action:
            fail(
                errors, f"account-security audit catalog must retain {member} = {action!r}")
        action_inputs = {
            ast.unparse(keyword.value)
            for node in ast.walk(trees[label]) if isinstance(node, ast.Call)
            for keyword in node.keywords if keyword.arg == "action"
        }
        if f"AccountAuditAction.{member}" not in action_inputs:
            fail(
                errors, f"{label} must use AccountAuditAction.{member} for audit writes")
    safeguards = {
        "service": (
            "if verification.needs_rehash:",
            "user.password_hash = replacement_hash",
            "user.password_changed_at == user_info.password_changed_at",
            "self._same_account_state(user, user_info)",
            "user.password_hash != user_info.password_hash",
        ),
        "operator service": (
            "holder_ids != frozenset({user_id})",
            "load_live_super_admin_holder_ids(session)",
        ),
        "password repository": ("user.password_changed_at = cast(datetime, password_changed_at)",),
        "security audit service": (
            "if error.status_code >= 500:", "except Exception as exc:", '"audit.write.failed"',
        ),
    }
    for label, markers in safeguards.items():
        for marker in markers:
            if marker not in text[label]:
                fail(
                    errors, f"{label} is missing local-authentication safeguard {marker!r}")

    operator_calls = [
        ast.unparse(node.func)
        for node in ast.walk(trees["operator"])
        if isinstance(node, ast.Call)
    ]
    if operator_calls.count("getpass.getpass") != 2:
        fail(
            errors,
            "offline operator recovery must read the password twice with getpass",
        )
    if '"--user-id"' not in text["operator"] or "--password" in text["operator"]:
        fail(errors, "offline operator recovery must accept only an immutable user ID")

    required_test_markers = {
        "API tests": (
            "test_public_register_route_remains_available",
            "test_captcha_is_required_before_public_register_calls_service",
            "test_registration_switch_routes_are_absent",
            "test_admin_reset_sets_a_directly_usable_password",
            "test_admin_reset_request_rejects_unsupported_mode",
            "test_password_routes_are_post_only_and_do_not_expose_the_mechanism",
        ),
        "service tests": (
            "test_unknown_and_wrong_passwords_use_one_public_failure",
            "test_successful_login_upgrades_a_stale_hash_after_rechecking_locks",
            "test_password_rotation_updates_user_row_and_timestamp",
            "test_service_self_change_rejects_reusing_the_current_password",
            "test_account_security_denial_audit_excludes_infrastructure_failures",
            "test_operator_reset_requires_the_exact_super_admin_holder_set",
            "test_operator_reset_accepts_only_the_target_as_sole_super_admin",
        ),
        "password tests": (
            "test_hash_and_verify_use_the_fixed_argon2id_profile",
            "test_hash_work_is_bounded_even_when_callers_run_concurrently",
        ),
        "PostgreSQL authentication tests": (
            "test_register_and_login_persist_complete_local_identity",
            "test_self_password_change_updates_user_and_revokes_old_token",
            "test_admin_reset_sets_a_directly_usable_password",
        ),
        "PostgreSQL persistence tests": (
            "test_rotation_updates_same_user_row",
            "test_deleted_user_cannot_retain_password_hash",
            "test_account_security_audit_rows_are_append_only",
        ),
    }
    for label, markers in required_test_markers.items():
        for marker in markers:
            if marker not in text[label]:
                fail(
                    errors, f"{label} is missing local-password test {marker!r}")

    environment_tree = ast.parse(text["Alembic environment"])
    registry_tree = ast.parse(text["model registry"])
    registry_used = any(
        isinstance(node, ast.ImportFrom)
        and node.module == "app.models.postgres"
        and any(alias.name == "Base" for alias in node.names)
        for node in ast.walk(environment_tree)
    )
    operation_audit_registered = any(
        isinstance(node, ast.ImportFrom)
        and node.module == "app.models.postgres.operation_audit"
        and any(alias.name == "OperationAuditEvent" for alias in node.names)
        for node in registry_tree.body
    )
    if not registry_used or not operation_audit_registered:
        fail(errors, "Alembic metadata must use the default registry including operation audit")
    for label, markers in {
        "reference": (
            "Administrator creation and reset set a directly usable password",
        ),
        "README": (
            "username/password login",
            "Public registration remains available",
            "Changing that holder is another user-owned guarded, audited offline action",
            "Administrator creation, password reset",
        ),
        "Chinese README": (
            "用户名密码",
            "自行注册不提供开关",
            "不生成或执行迁移、初始化、交接脚本",
            "管理员新增、重置密码",
        ),
    }.items():
        for marker in markers:
            if marker not in text[label]:
                fail(
                    errors, f"{label} is missing local-password marker {marker!r}")


def _validate_auth_entry_order(tree: ast.Module, errors: list[str]) -> None:
    """
        检查认证接口先通过限流和验证码，再调用完整业务；路由不自行签发令牌。

    :param tree: 认证路由语法树，不执行请求或连接外部服务。
    :param errors: 接收遗漏前置保护或执行顺序错误的列表。
    :return: 无返回值；错误追加到 errors，函数名简化不改变原有安全边界。
    """
    expected_flows = {
        "login": (
            "auth_service.login",
        ),
        "register": (
            "auth_service.register",
        ),
    }
    # 路由只保留业务调用；限流和验证码仍由前面的显式依赖执行。
    for function_name, expected in expected_flows.items():
        function = _function_node(tree.body, function_name)
        expected_dependency = f"Depends(rate_limit_{function_name})"
        if function is None or expected_dependency not in ast.unparse(function):
            fail(
                errors, f"{function_name} must show its rate-limit dependency on the route")
        captcha_dependency = f"Depends(require_captcha(CaptchaScene.{function_name.upper()}))"
        if function is None or captcha_dependency not in ast.unparse(function):
            fail(
                errors, f"{function_name} must declare its fixed-scene CAPTCHA dependency")
        calls = sorted(
            (node.lineno, ast.unparse(node.value.func)) for node in ast.walk(function)
            if isinstance(node, ast.Await) and isinstance(node.value, ast.Call)
            and ast.unparse(node.value.func) in expected
        ) if function is not None else []
        if tuple(name for _, name in calls) != expected:
            fail(
                errors, f"{function_name} must call its complete service operation after dependencies")
        if function is not None and any(
            isinstance(node, ast.Call) and ast.unparse(
                node.func).split(".")[-1] == "issue_access_token"
            for node in ast.walk(function)
        ):
            fail(
                errors, f"{function_name} route must leave Token issuance to its service")


def _validate_captcha_dependency_wiring(
    captcha_tree: ast.Module,
    route_trees: dict[str, ast.Module],
    errors: list[str],
) -> None:
    """
        检查路由先声明限流或身份权限，验证码依赖只校验答案和可信所属用户。

    :param captcha_tree: 验证码依赖模块语法树，只做离线检查。
    :param route_trees: 按 auth、me、users 分组的真实路由语法树。
    :param errors: 接收场景、路由顺序或验证码职责越界的问题。
    :return: 无返回值；不会实例化应用或连接 Redis、数据库。
    """
    expected_scenes = {
        "LOGIN": ("auth", "login", "rate_limited", "Depends(rate_limit_login)"),
        "REGISTER": ("auth", "register", "rate_limited", "Depends(rate_limit_register)"),
        "USER_CHANGE_PASSWORD": ("me", "change_my_password", "context",
                                 "require_permission(PermissionKey.ACCOUNT_CHANGE_PASSWORD)"),
        "ADMIN_CREATE_USER": ("users", "create_user", "context",
                              "require_permission(PermissionKey.USERS_CREATE, management=True)"),
        "ADMIN_RESET_USER_PASSWORD": ("users", "reset_user_password", "context",
                                      "require_permission(PermissionKey.USERS_PASSWORD_RESET, management=True)"),
    }
    factory = _function_node(captcha_tree.body, "require_captcha")
    factory_source = ast.unparse(factory) if factory is not None else ""
    for scene, (module, function_name, prerequisite_name, prerequisite) in expected_scenes.items():
        function = _function_node(route_trees[module].body, function_name)
        if function is None or f"Depends(require_captcha(CaptchaScene.{scene}))" not in ast.unparse(function):
            fail(
                errors, f"{function_name} must declare its fixed-scene CAPTCHA dependency")
        # FastAPI 按参数声明顺序执行依赖；检查前置依赖必须排在验证码参数之前。
        arguments = function.args.args if function is not None else []
        names = [argument.arg for argument in arguments]
        defaults = [None] * (len(arguments) - len(function.args.defaults)
                             ) + function.args.defaults if function else []
        declarations = {
            argument.arg: ast.unparse(
                argument) + (ast.unparse(default) if default is not None else "")
            for argument, default in zip(arguments, defaults, strict=True)
        }
        if (prerequisite not in declarations.get(prerequisite_name, "")
                or prerequisite_name not in names or "captcha_checked" not in names
                or names.index(prerequisite_name) >= names.index("captcha_checked")):
            fail(
                errors, f"{function_name} must declare its route prerequisite before CAPTCHA")

    # 配置别名 AppSettings 可以来自 auth；验证码模块不应导入业务模型或执行限流、权限、身份依赖。
    for node in captcha_tree.body:
        if isinstance(node, ast.ImportFrom) and node.module in {
            "app.dependencies.auth", "app.dependencies.permission", "app.dependencies.rate_limit",
            "app.schemas.auth", "app.schemas.user", "app.core.access.authorization", "app.core.access.permissions",
        } and (node.module != "app.dependencies.auth" or any(alias.name != "AppSettings" for alias in node.names)):
            fail(errors, "CAPTCHA dependency must not import business models, authentication, permissions or limiters")
    if factory is not None and any(
        isinstance(node, ast.Call) and ast.unparse(node.func) == "Depends" for node in ast.walk(factory)
    ):
        fail(errors, "CAPTCHA dependency must not embed business prerequisites")

    dependency = _function_node(
        factory.body, "check_captcha") if factory is not None else None
    dependency_source = ast.unparse(
        dependency) if dependency is not None else ""
    calls = [node for node in ast.walk(dependency) if isinstance(
        node, ast.Call)] if dependency is not None else []
    reads = [node for node in calls if ast.unparse(
        node.func) == "read_body_field"]
    verification = [node for node in calls if ast.unparse(
        node.func) == "captcha_service.verify_captcha"]
    fields = {node.args[1].value for node in reads
              if len(node.args) == 2 and isinstance(node.args[1], ast.Constant)}
    if (len(reads) != 2 or fields != {"captcha_id", "captcha_answer"} or len(verification) != 1
            or any(node.lineno >= verification[0].lineno for node in reads)):
        fail(errors, "CAPTCHA dependency must validate CAPTCHA fields before one verification")
    if ("request.json()" not in dependency_source or "except JSONDecodeError" not in dependency_source
            or "not isinstance(body, dict)" not in dependency_source or "uuid.UUID(" not in dependency_source
            or "raise invalid_request_400(" not in dependency_source or "scene=scene," not in dependency_source):
        fail(errors, "CAPTCHA dependency must preserve body validation errors and its fixed scene")
    if ("getattr(request.state, 'user_id', None)" not in dependency_source
            or "scene.requires_login" not in dependency_source or "raise unauthenticated_401(" not in dependency_source
            or "not isinstance(user_id, str)" not in dependency_source or "not user_id" not in dependency_source
            or "user_id=user_id" not in dependency_source or "owner_id" in dependency_source):
        fail(errors, "CAPTCHA dependency must bind its private user_id from trusted request state or reject it")
    if "verify_and_consume_captcha" in ast.unparse(captcha_tree):
        fail(errors, "retired direct CAPTCHA adapter must not remain")
    if "return check_captcha" not in factory_source:
        fail(errors, "require_captcha must return its request dependency")


def _validate_captcha_service_consumption(tree: ast.Module, errors: list[str]) -> None:
    """
        验证验证码先通过 GETDEL 一次作废，再比较包含业务和用户的摘要。

    :param tree: 验证码服务的源码语法树，不导入应用或调用 Redis。
    :param errors: 接收单次消费、摘要绑定或旧实现残留问题的列表。
    :return: 无返回值；将不符合现行消费约定的源码问题加入 errors。
    """
    service = _class_node(tree, "CaptchaService")
    verify = _function_node(
        service.body, "verify_captcha") if service is not None else None
    calls = [node for node in ast.walk(verify) if isinstance(
        node, ast.Call)] if verify is not None else []
    consumed = [node for node in calls if ast.unparse(
        node.func) == "redis.getdel"]
    compared = [node for node in calls if ast.unparse(
        node.func) == "hmac.compare_digest"]
    # 一次 Redis 命令同时读取、删除，不能退回先比较正确答案再删除的流程。
    if (len(consumed) != 1 or len(compared) != 1 or consumed[0].lineno >= compared[0].lineno
            or any(ast.unparse(node.func) in {"redis.get", "redis.delete", "redis.eval"} for node in calls)):
        fail(errors, "CAPTCHA must use one GETDEL before comparing the answer")

    # 签发和校验必须使用同一份摘要绑定，不能遗漏用途或当前用户。
    for method_name in ("create_captcha", "verify_captcha"):
        method = _function_node(
            service.body, method_name) if service is not None else None
        hashes = [node for node in ast.walk(method) if isinstance(node, ast.Call)
                  and ast.unparse(node.func) == "self.hash_captcha_code"] if method is not None else []
        if (len(hashes) != 1 or {keyword.arg: ast.unparse(keyword.value) for keyword in hashes[0].keywords}
                != {"scene": "scene", "user_id": "user_id"}):
            fail(
                errors, f"CAPTCHA {method_name} must bind scene and user_id in its digest")
    hash_method = _function_node(
        service.body, "hash_captcha_code") if service is not None else None
    payloads = [node for node in ast.walk(hash_method) if isinstance(
        node, ast.List)] if hash_method else []
    if not any({"scene", "user_id", "captcha_id", "answer"} <= {
        node.id for node in ast.walk(payload) if isinstance(node, ast.Name)
    } for payload in payloads):
        fail(errors, "CAPTCHA digest must encode scene, user_id, ID and answer together")
    if any(marker in ast.unparse(tree) for marker in ("CONSUME_CAPTCHA_SCRIPT", "parse_captcha_record")):
        fail(errors, "retired CAPTCHA Lua/JSON-record implementation must not remain")


def _validate_user_rate_limit_wiring(
    rate_limit_tree: ast.Module,
    auth_tree: ast.Module,
    permission_tree: ast.Module,
    route_validation_tree: ast.Module,
    api_route_rules_tree: ast.Module,
    errors: list[str],
) -> None:
    """
        校验已登录业务以路由名称分桶，并在账号读取前按普通或验证码窗口计数一次。

    :param rate_limit_tree: 限流 HTTP 适配源码语法树。
    :param auth_tree: JWT 与账号依赖源码语法树。
    :param permission_tree: 接口权限依赖源码语法树。
    :param route_validation_tree: 启动期业务路由接线校验源码语法树。
    :param api_route_rules_tree: 声明公开入口及特殊认证依赖的 v1 校验模块语法树。
    :param errors: 接收路由名称或运行时依赖接线缺失问题的列表。
    :return: 无返回值；发现契约缺失时追加具体错误。
    """
    # 普通业务直接把路由名与当前用户 ID 交给一次 Redis 计数。
    function = _function_node(rate_limit_tree.body, "rate_limit_user")
    source = ast.unparse(function) if function is not None else ""
    if any(marker not in source for marker in (
        "getattr(request.scope.get('route'), 'name', None)",
        "subject_type='user_id'",
        "key_parts=[str(login_info.user_id)]",
    )):
        fail(errors, "rate_limit_user must show route and user_id key parts")

    load_context = _function_node(
        auth_tree.body, "_load_current_user")
    quota_calls = ("rate_limit_private_captcha", "rate_limit_user")
    database_calls = (
        "user_repository.check_current_user",
    )
    # 数据库共用入口只查账号，不能再藏一层限流选择或重复扣次。
    load_calls = [
        ast.unparse(node.value.func)
        for node in ast.walk(load_context)
        if isinstance(node, ast.Await) and isinstance(node.value, ast.Call)
    ] if load_context is not None else []
    if any(load_calls.count(name) != 1 for name in database_calls) or any(
        name in load_calls for name in quota_calls
    ):
        fail(errors, "current-user loading must read the account once without nested quota counting")

    dependency_contracts = {
        "get_current_user": (
            "Depends(check_token)",
            "rate_limit_user(request, login_info, settings)",
            "_load_current_user",
        ),
        "get_captcha_user": (
            "Depends(check_token)",
            "_load_current_user",
            "get_captcha_scene",
        ),
    }
    for function_name, markers in dependency_contracts.items():
        function = _function_node(auth_tree.body, function_name)
        source = ast.unparse(function) if function is not None else ""
        if any(marker not in source for marker in markers):
            fail(
                errors,
                f"{function_name} must keep its complete authenticated rate-limit dependency",
            )
        # 每个用途入口直接限流一次，再读账号；验证码必须使用自己的限流函数。
        expected_quota = "rate_limit_private_captcha" if function_name == "get_captcha_user" else "rate_limit_user"
        call_positions = {
            name: [
                node.lineno for node in ast.walk(function)
                if isinstance(node, ast.Await) and isinstance(node.value, ast.Call)
                and ast.unparse(node.value.func) == name
            ]
            for name in (*quota_calls, "_load_current_user")
        } if function is not None else {}
        quotas = call_positions.get(expected_quota, [])
        loads = call_positions.get("_load_current_user", [])
        if (
            len(quotas) != 1 or len(loads) != 1
            or sum(len(call_positions.get(name, [])) for name in quota_calls) != 1
            or quotas[0] >= loads[0]
        ):
            fail(
                errors, f"{function_name} must count exactly once before database account load")

    permission_factory = _function_node(
        permission_tree.body, "require_permission")
    permission_dependency = (
        _function_node(permission_factory.body, "dependency")
        if permission_factory is not None else None
    )
    permission_source = (
        ast.unparse(permission_dependency)
        if permission_dependency is not None
        else ""
    )
    if any(marker not in permission_source for marker in (
        "Depends(auth.check_token)",
        "Depends(get_settings)",
        "rate_limit_user(request, login_info, settings, management=management)",
        "auth._load_current_user(request, login_info)",
    )):
        fail(errors, "require_permission must keep Token validation, selected business quota and shared account load")
    # 权限工厂默认普通额度，由路由选择管理额度，不能因有权限检查就固定使用管理次数。
    quota_defaults = dict(zip(
        (argument.arg for argument in permission_factory.args.kwonlyargs),
        permission_factory.args.kw_defaults,
        strict=True,
    )) if permission_factory is not None else {}
    management_default = quota_defaults.get("management")
    if not isinstance(management_default, ast.Constant) or management_default.value is not False:
        fail(errors, "require_permission must default to ordinary quota with management=False")
    # 权限入口没有中转依赖；直接核对回调内的一次限流、一次查库和指定权限判断。
    permission_calls = {
        name: [
            node.lineno for node in ast.walk(permission_dependency)
            if isinstance(node, ast.Await) and isinstance(node.value, ast.Call)
            and ast.unparse(node.value.func) == name
        ]
        for name in (*quota_calls, "auth._load_current_user")
    } if permission_dependency is not None else {}
    management_quotas = permission_calls.get("rate_limit_user", [])
    management_loads = permission_calls.get("auth._load_current_user", [])
    permission_checks = [
        node.lineno for node in ast.walk(permission_dependency)
        if isinstance(node, ast.If) and ast.unparse(node.test) == "required_key not in context.permissions"
    ] if permission_dependency is not None else []
    if (
        len(management_quotas) != 1 or len(management_loads) != 1 or len(permission_checks) != 1
        or sum(len(permission_calls.get(name, [])) for name in quota_calls) != 1
        or not management_quotas[0] < management_loads[0] < permission_checks[0]
    ):
        fail(errors, "require_permission must count selected quota exactly once before account and permission checks")

    route_validation = _function_node(
        route_validation_tree.body, "validate_api_routes")
    route_validation_source = (
        ast.unparse(route_validation)
        if route_validation is not None
        else ""
    )
    required_route_checks = (
        "route.name", "_uses_dependency", "public_routes",
        "authenticated_dependencies", "special_routes",
    )
    if any(marker not in route_validation_source for marker in required_route_checks):
        fail(errors, "route validation must inspect every authenticated runtime rate-limit dependency")
    if any(
        isinstance(
            node, ast.ImportFrom) and node.module == "app.dependencies.auth"
        for node in route_validation_tree.body
    ):
        fail(errors, "core route validation must not import business authentication dependencies")
    api_route_rules_source = ast.unparse(api_route_rules_tree)
    route_wiring = _function_node(
        api_route_rules_tree.body, "validate_v1_api_routes")
    required_api_rules = (
        "check_token",
        "get_current_user",
        "require_permission",
        "get_captcha_user",
    )
    expected_arguments = {
        "public_routes": "_PUBLIC_ROUTES",
        "authenticated_dependencies": "_AUTHENTICATED_DEPENDENCIES",
        "special_routes": "_SPECIAL_ROUTES",
    }
    calls = (
        [node for node in ast.walk(route_wiring)
         if isinstance(node, ast.Call) and ast.unparse(node.func) == "validate_api_routes"]
        if route_wiring is not None else []
    )
    wired = any(
        len(call.args) == 1 and ast.unparse(call.args[0]) == "app"
        and {keyword.arg: ast.unparse(keyword.value) for keyword in call.keywords} == expected_arguments
        for call in calls
    )
    if any(marker not in api_route_rules_source for marker in required_api_rules) or not wired:
        fail(errors, "API route rules must supply public and authenticated routes to core validation")


def validate_rate_limiting_and_verification(errors: list[str]) -> None:
    paths = {
        "rate-limit reference": SKILL_ROOT / "references" / "rate-limiting.md",
        "verification reference": (
            SKILL_ROOT / "references" / "verification-and-abuse-defense.md"
        ),
        "settings": ASSET_ROOT / "app" / "core" / "config.py",
        "limiter": ASSET_ROOT / "app" / "core" / "rate_limit" / "limiter.py",
        "user dependency": ASSET_ROOT / "app" / "dependencies" / "rate_limit.py",
        "authorization dependency": ASSET_ROOT / "app" / "dependencies" / "auth.py",
        "permission dependency": ASSET_ROOT / "app" / "dependencies" / "permission.py",
        "route validation": ASSET_ROOT / "app" / "core" / "route_validation.py",
        "API route rules": ASSET_ROOT / "app" / "api" / "v1" / "route_validation.py",
        "authentication routes": ASSET_ROOT / "app" / "api" / "v1" / "endpoints" / "auth.py",
        "current-account routes": ASSET_ROOT / "app" / "api" / "v1" / "endpoints" / "me.py",
        "user-management routes": ASSET_ROOT / "app" / "api" / "v1" / "endpoints" / "users.py",
        "captcha dependency": ASSET_ROOT / "app" / "dependencies" / "captcha.py",
        "captcha service": ASSET_ROOT / "app" / "services" / "captcha_service.py",
        "redis client": ASSET_ROOT / "app" / "db" / "redis_db.py",
        "application": ASSET_ROOT / "app" / "main.py",
        "exception handlers": ASSET_ROOT / "app" / "core" / "exception_handlers.py",
        "environment": ASSET_ROOT / ".env.example",
        "settings tests": ASSET_ROOT / "tests" / "test_settings.py",
        "rate-limit dependency tests": ASSET_ROOT / "tests" / "test_rate_limit_dependencies.py",
        "authentication HTTP tests": ASSET_ROOT / "tests" / "test_auth_api.py",
        "captcha tests": ASSET_ROOT / "tests" / "test_captcha.py",
        "captcha Redis tests": ASSET_ROOT
        / "tests"
        / "integration"
        / "test_captcha_redis.py",
        "compose": ASSET_ROOT / "compose.dev.yaml",
        "CI": REPO_ROOT / ".github" / "workflows" / "ci.yml",
        "README": REPO_ROOT / "README.md",
        "Chinese README": REPO_ROOT / "README.zh-CN.md",
        "changelog": REPO_ROOT / "CHANGELOG.md",
        "Chinese changelog": REPO_ROOT / "CHANGELOG.zh-CN.md",
        "release checklist": REPO_ROOT / "RELEASE_CHECKLIST.md",
        "Chinese release checklist": REPO_ROOT / "RELEASE_CHECKLIST.zh-CN.md",
    }
    missing = False
    for name, path in paths.items():
        if not path.is_file():
            fail(
                errors,
                f"missing rate-limit/CAPTCHA {name}: {path.relative_to(REPO_ROOT)}",
            )
            missing = True
    if missing:
        return

    for retired_path in (
        ASSET_ROOT / "app" / "dependencies" / "auth_guard.py",
        ASSET_ROOT / "app" / "services" / "auth_guard_service.py",
    ):
        if retired_path.exists():
            fail(
                errors,
                f"retired limiter path remains: {retired_path.relative_to(REPO_ROOT)}",
            )

    required_markers = {
        "rate-limit reference": (
            "## Redis Fixed Window",
            "42901",
            "50301",
        ),
        "verification reference": (
            "CAPTCHA",
            "login",
            "register",
        ),
        "settings": (
            "rate_limit_redis_url: str | None = Field(default=None, repr=False)",
            "rate_limit_hmac_key: SecretStr",
            "max_active_sessions_per_user: int = Field(ge=1)",
            "rate_limit_captcha_create_per_five_minutes: int = Field(default=10",
            "rate_limit_user_read: int = Field(default=600",
            "rate_limit_user_write: int = Field(default=120",
            "rate_limit_admin_read: int = Field(default=300",
            "rate_limit_admin_write: int = Field(default=60",
            "rate_limit_login_ip_per_five_minutes: int = Field(default=20",
            "rate_limit_register_ip_per_hour: int = Field(default=5",
        ),
        "limiter": (
            "FIXED_WINDOW_SCRIPT:",
            "redis.call('INCR', KEYS[1])",
            "redis.call('EXPIRE', KEYS[1], window)",
            "redis.call('PTTL', KEYS[1])",
            "async def check_rate_limit(",
        ),
        "user dependency": (
            "def get_limit_ip(",
            "return ipaddress.ip_address(host).compressed",
            'return ""',
            "async def rate_limit_user(",
            'getattr(request.scope.get("route"), "name", None)',
            "async def rate_limit_login(",
            "async def rate_limit_register(",
            "async def rate_limit_public_captcha(",
            "key_parts=[get_limit_ip(request)]",
            "key_parts=[str(login_info.user_id)]",
        ),
        "authentication routes": (
            "async def login(",
            "auth_service.login(",
            "async def register(",
            "auth_service.register(",
            "captcha_service.create_captcha(",
        ),
        "current-account routes": (
            "async def create_authenticated_captcha(",
            "captcha_service.create_captcha(",
        ),
        "captcha dependency": (
            "def require_captcha(",
            ".verify_captcha(",
        ),
        "captcha service": (
            "class CaptchaService:",
            "async def create_captcha(",
            ") -> CaptchaResponse:",
            "async def verify_captcha(",
            "def build_redis_key(",
            "def hash_captcha_code(",
            "def build_png_base64_image(",
            "EXPIRE_SECONDS",
            "captcha_service = CaptchaService()",
        ),
        "redis client": ("def create_rate_limit_redis_client(",),
        "application": (
            "create_rate_limit_redis_client(settings)",
            "app.state.rate_limit_redis",
            "register_exception_handlers(app)",
        ),
        "exception handlers": (
            "async def handle_rate_limit_exceeded(",
            "async def handle_rate_limit_unavailable(",
        ),
        "environment": (
            "# RATE_LIMIT_REDIS_URL=redis://127.0.0.1:6380/0",
            "RATE_LIMIT_HMAC_KEY=",
            "MAX_ACTIVE_SESSIONS_PER_USER=",
            "RATE_LIMIT_CAPTCHA_CREATE_PER_FIVE_MINUTES=10",
            "RATE_LIMIT_LOGIN_IP_PER_FIVE_MINUTES=20",
            "RATE_LIMIT_REGISTER_IP_PER_HOUR=5",
        ),
        "settings tests": (
            "test_app_environment_is_not_a_runtime_setting",
            "test_rate_limit_defaults_are_explicit_and_configurable",
            "test_session_limit_must_be_positive_and_explicit",
        ),
        "rate-limit dependency tests": (
            "test_missing_route_name_fails_closed",
            "test_denied_user_check_raises_rate_limit_exceeded",
            "test_authenticated_captcha_charges_its_exact_window_once",
        ),
        "authentication HTTP tests": (
            "test_register_http_flow_admits_before_captcha_and_write",
            "test_login_http_flow_admits_before_captcha_and_complete_login",
        ),
        "captcha tests": ("test_",),
        "captcha Redis tests": ("test_",),
        "compose": (
            "redis-rate-limit:",
            'profiles: ["separate-rate-limit"]',
            '"127.0.0.1:6380:6379"',
        ),
        "CI": (
            "TEST_RATE_LIMIT_REDIS_URL: redis://127.0.0.1:6380/0",
            "redis-rate-limit:",
            "- 6380:6379",
        ),
        "README": ("Redis fixed-window quotas", "no global or cross-business quotas"),
        "Chinese README": ("Redis 限流使用简单固定窗口", "没有全站总额度"),
        "changelog": ("rate",),
        "Chinese changelog": ("限流",),
        "release checklist": ("rate",),
        "Chinese release checklist": ("限流",),
    }
    text = {name: path.read_text(encoding="utf-8")
            for name, path in paths.items()}
    for name, markers in required_markers.items():
        for marker in markers:
            if marker not in text[name]:
                relative = paths[name].relative_to(REPO_ROOT)
                fail(
                    errors,
                    f"{relative} is missing rate-limit/verification marker: {marker!r}",
                )

    settings_tree = _parse_python(
        errors,
        paths["settings"],
        label="rate-limit settings",
    )
    if settings_tree is None:
        return
    settings_class = _class_node(settings_tree, "Settings")
    # 单项目不再为了日志要求填写运行环境；测试夹具自己的环境安全检查不在这里删除。
    if settings_class is not None and any(
        isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "app_environment"
        for node in settings_class.body
    ):
        fail(
            errors,
            "Settings must not restore the retired app_environment logging field",
        )

    active_environment = {
        key.strip(): value.strip()
        for line in text["environment"].splitlines()
        if line.strip() and not line.lstrip().startswith("#") and "=" in line
        for key, value in (line.split("=", 1),)
    }
    if "APP_ENVIRONMENT" in active_environment:
        fail(errors, ".env.example must not restore the retired APP_ENVIRONMENT logging setting")

    for name in (
        "settings",
        "environment",
        "user dependency",
        "authentication routes",
    ):
        for retired_marker in (
            "rate_limit_enabled",
            "RATE_LIMIT_ENABLED",
            "AuthGuardService",
            "get_auth_guard",
        ):
            if retired_marker in text[name]:
                relative = paths[name].relative_to(REPO_ROOT)
                fail(
                    errors,
                    f"{relative} retains retired limiter marker {retired_marker!r}",
                )

    retired_shared_quota_markers = (
        "api_global",
        "api_ip",
        "login_pair",
        "login_global",
        "registration_target",
        "registration_pair",
        "registration_global",
        "super_admin_transfer",
        "login_failure_state_retention_seconds",
        "verification_global",
        "TOKEN_BUCKET_SCRIPT",
    )
    for name in (
        "settings",
        "user dependency",
        "authentication routes",
        "environment",
    ):
        for marker in retired_shared_quota_markers:
            if marker in text[name]:
                relative = paths[name].relative_to(REPO_ROOT)
                fail(
                    errors,
                    f"{relative} reintroduces retired quota marker: {marker!r}",
                )

    # Dimension and exact behavior are also exercised by the dependency tests.

    rate_limit_tree = _parse_python(
        errors, paths["user dependency"], label="user rate-limit dependency")
    authorization_tree = _parse_python(
        errors, paths["authorization dependency"], label="authorization dependency")
    permission_tree = _parse_python(
        errors, paths["permission dependency"], label="permission dependency")
    route_validation_tree = _parse_python(
        errors, paths["route validation"], label="route validation")
    api_route_rules_tree = _parse_python(
        errors, paths["API route rules"], label="API route rules")
    if (
        rate_limit_tree is not None
        and authorization_tree is not None
        and permission_tree is not None
        and route_validation_tree is not None
        and api_route_rules_tree is not None
    ):
        _validate_user_rate_limit_wiring(
            rate_limit_tree,
            authorization_tree,
            permission_tree,
            route_validation_tree,
            api_route_rules_tree,
            errors,
        )

    authentication_routes_tree = _parse_python(
        errors, paths["authentication routes"], label="authentication routes")
    if authentication_routes_tree is not None:
        _validate_auth_entry_order(authentication_routes_tree, errors)
    captcha_tree = _parse_python(
        errors, paths["captcha dependency"], label="captcha dependency")
    me_tree = _parse_python(
        errors, paths["current-account routes"], label="current-account routes")
    users_tree = _parse_python(
        errors, paths["user-management routes"], label="user-management routes")
    service_tree = _parse_python(
        errors, paths["captcha service"], label="captcha service")
    if service_tree is not None:
        _validate_captcha_service_consumption(service_tree, errors)
    if (captcha_tree is not None and authentication_routes_tree is not None
            and me_tree is not None and users_tree is not None):
        _validate_captcha_dependency_wiring(
            captcha_tree, {"auth": authentication_routes_tree,
                           "me": me_tree, "users": users_tree}, errors,
        )


def validate_simplified_authentication_and_administration(errors: list[str]) -> None:
    """Keep retired baseline features out of the executable asset."""

    retired_files = (
        "app/verification.py",
        "app/verification_flow.py",
        "tests/test_verification.py",
        "tests/test_verification_flow.py",
        "tests/integration/test_verification_redis.py",
        "app/auth.py",
        "app/repositories/postgres/user_authority_repository.py",
    )
    for relative in retired_files:
        if (ASSET_ROOT / relative).exists():
            fail(
                errors,
                f"retired baseline module is still bundled: {relative}",
            )

    app_root = ASSET_ROOT / "app"
    for path in sorted(app_root.rglob("*.py")):
        if any(part in FORBIDDEN_DIRECTORY_NAMES for part in path.parts):
            continue
        content = path.read_text(encoding="utf-8")
        for marker in ("can_delegate", "super_admin_transfer"):
            if marker in content:
                fail(
                    errors, f"{path.relative_to(REPO_ROOT)} reintroduces {marker!r}")

    migration_path = ASSET_ROOT / "alembic" / "versions" / "0004_password_auth.py"
    if migration_path.is_file():
        migration = migration_path.read_text(encoding="utf-8")
        if (
            '"public_registration_enabled"' not in migration
            or 'sa.text("true")' not in migration
        ):
            fail(
                errors,
                "historical 0004 migration must retain its published registration column",
            )

    reference_paths = (
        SKILL_ROOT / "references" / "country-catalog.md",
        SKILL_ROOT / "references" / "proxy-availability-backend.md",
    )
    for path in reference_paths:
        if not path.is_file():
            continue
        content = path.read_text(encoding="utf-8")
        marker = (
            "implicit anonymous API from this Skill"
            if path.name == "country-catalog.md"
            else "never add an all-user or cross-business request quota"
        )
        if marker not in re.sub(r"\s+", " ", content):
            fail(
                errors,
                f"{path.relative_to(REPO_ROOT)} must preserve optional-feature security scope",
            )


def validate_single_project_scope(errors: list[str]) -> None:
    active_paths = [
        SKILL_ROOT / "SKILL.md",
        SKILL_ROOT / "agents" / "openai.yaml",
        *sorted((SKILL_ROOT / "references").rglob("*.md")),
    ]
    for root in (
        ASSET_ROOT / "app",
        ASSET_ROOT / "alembic",
        ASSET_ROOT / "sql",
    ):
        if root.is_dir():
            active_paths.extend(
                sorted(
                    path
                    for path in root.rglob("*")
                    if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES
                )
            )

    forbidden_patterns = (
        re.compile(
            r"(?<![A-Za-z0-9])(?:multi[\s_-]*)?"
            r"(?:tenant(?:s|[_-][A-Za-z0-9_]+)?|tenancy)",
            re.IGNORECASE,
        ),
        re.compile(r"租户"),
    )
    for path in active_paths:
        if not path.is_file():
            continue
        content = path.read_text(encoding="utf-8")
        for pattern in forbidden_patterns:
            for match in pattern.finditer(content):
                # Markdown 会把同一句禁令折成多行；句号、空段和下一条列表才切断它。
                # 只认目标词前面的否定，不能借上一句或后面的“不”掩盖实际新增范围。
                boundaries = list(re.finditer(
                    r"\n[ \t]*\n|[.!?;。！？；](?:\s+|$)|\n(?=[ \t]*(?:[-*+] |#{1,6} ))",
                    content[:match.start()],
                ))
                sentence_start = boundaries[-1].end() if boundaries else 0
                before_scope = content[sentence_start:match.start()].casefold()
                if re.search(r"\b(?:do not|does not|without|no)\b", before_scope) or any(
                    marker in before_scope for marker in ("不", "无", "禁止")
                ):
                    continue
                line = content.count("\n", 0, match.start()) + 1
                relative = path.relative_to(REPO_ROOT)
                fail(
                    errors,
                    f"{relative}:{line} introduces a forbidden multi-project "
                    "authorization scope",
                )


def validate_user_role_limit(errors: list[str]) -> None:
    paths = {
        "entrypoint": SKILL_ROOT / "SKILL.md",
        "RBAC reference": SKILL_ROOT / "references" / "rbac.md",
        "atomic reference": SKILL_ROOT / "references" / "atomic-consistency.md",
        "PostgreSQL reference": SKILL_ROOT
        / "references"
        / "postgresql-rbac-implementation.md",
        "migration reference": SKILL_ROOT / "references" / "migrations.md",
        "testing reference": SKILL_ROOT / "references" / "testing.md",
        "role definitions": ASSET_ROOT / "app" / "core" / "access" / "roles.py",
        "schemas": ASSET_ROOT / "app" / "schemas" / "user.py",
        "role schemas": ASSET_ROOT / "app" / "schemas" / "role.py",
        "queries": ASSET_ROOT
        / "app"
        / "repositories"
        / "postgres"
        / "user_role_repository.py",
        "service": ASSET_ROOT / "app" / "services" / "user_service.py",
        "migration": ASSET_ROOT
        / "alembic"
        / "versions"
        / "0001_single_project_rbac.py",
        "bootstrap": ASSET_ROOT / "sql" / "bootstrap_super_admin.sql",
        "schema tests": ASSET_ROOT / "tests" / "test_schemas.py",
        "integration tests": ASSET_ROOT
        / "tests"
        / "integration"
        / "test_user_role_limit.py",
        "bootstrap tests": ASSET_ROOT / "tests" / "integration" / "test_bootstrap.py",
        "migration tests": ASSET_ROOT / "tests" / "integration" / "test_migrations.py",
    }
    missing = False
    for name, path in paths.items():
        if not path.is_file():
            fail(
                errors,
                f"missing user-role-limit {name}: {path.relative_to(REPO_ROOT)}",
            )
            missing = True
    if missing:
        return

    text = {name: path.read_text(encoding="utf-8")
            for name, path in paths.items()}
    required_markers = {
        "RBAC reference": (
            "each user may have at most 10",
            "disabled role still occupies one of the 10 slots",
        ),
        "atomic reference": (
            "more than 10 live role bindings",
            "two bindings racing for a user's tenth live role slot",
        ),
        "PostgreSQL reference": (
            "at most 10 live rows per user",
            "concurrent tenth-slot race",
        ),
        "migration reference": (
            "Enforce at most 10 live `user_roles` rows per user",
            "a binding to a disabled role still counts",
            "tombstone does not",
        ),
        "testing reference": (
            "the 10-live-role limit",
            "concurrent race for the tenth slot",
        ),
        "role definitions": ("MAX_ROLES_PER_USER = 10",),
        "schemas": (
            "max_length=MAX_ROLES_PER_USER",
        ),
        "queries": (
            "async def count_roles(",
            "UserRole.deleted_at.is_(None)",
        ),
        "service": (
            "bound_role_count + len(changed_ids) > MAX_ROLES_PER_USER",
            'conflict_409("user_role_limit_exceeded", business_code=BusinessCode.USER_ROLE_LIMIT_EXCEEDED)',
        ),
        "migration": (
            'revision: str = "0001_single_project_rbac"',
            "down_revision: str | None = None",
            "CREATE FUNCTION lock_rbac_state_before_user_roles_write()",
            "FOR EACH STATEMENT",
            "DEFERRABLE INITIALLY DEFERRED",
            "ct_user_roles_max_ten_live",
        ),
        "bootstrap": (
            "candidate_role_count >= 10",
            "target user already has 10 live role assignments",
        ),
        "schema tests": (
            "test_permission_batches_require_one_to_one_hundred_unique_ids",
            "test_role_batches_require_one_to_ten_unique_ids",
        ),
        "integration tests": (
            "test_service_enforces_limit_and_keeps_bind_idempotent",
            "test_database_counts_disabled_roles_and_ignores_tombstones",
            "test_concurrent_bind_cannot_create_an_eleventh_live_role",
            "test_operator_handover_rejects_a_full_target_atomically",
        ),
        "bootstrap tests": (
            "test_operator_sql_uses_the_tenth_role_slot_and_replays_idempotently",
            "test_operator_sql_rejects_a_full_target_without_partial_changes",
        ),
        "migration tests": (
            'assert revision == "0004_password_auth"',
            "role_limit_trigger_count == 1",
        ),
    }
    for name, markers in required_markers.items():
        normalized_content = re.sub(r"\s+", " ", text[name])
        for marker in markers:
            if re.sub(r"\s+", " ", marker) not in normalized_content:
                relative = paths[name].relative_to(REPO_ROOT)
                fail(
                    errors,
                    f"{relative} is missing user-role-limit marker: {marker!r}",
                )

    role_request_start = text["schemas"].find(
        "class UserRoleIdsRequest(RequestBase):")
    role_request_end = text["schemas"].find("\nclass ", role_request_start + 1)
    role_request = text["schemas"][
        role_request_start: role_request_end if role_request_end >= 0 else None
    ]
    if "max_length=100" in role_request:
        fail(errors, "UserRoleIdsRequest must not retain the old 100-item batch limit")


def validate_administrative_read_visibility(errors: list[str]) -> None:
    paths = {
        "entrypoint": SKILL_ROOT / "SKILL.md",
        "hierarchy reference": SKILL_ROOT
        / "references"
        / "administrative-hierarchy.md",
        "atomic reference": SKILL_ROOT / "references" / "atomic-consistency.md",
        "PostgreSQL reference": SKILL_ROOT
        / "references"
        / "postgresql-rbac-implementation.md",
        "testing reference": SKILL_ROOT / "references" / "testing.md",
        "queries": ASSET_ROOT
        / "app"
        / "repositories"
        / "postgres"
        / "user_repository.py",
        "role queries": ASSET_ROOT
        / "app"
        / "repositories"
        / "postgres"
        / "role_repository.py",
        "user policy": ASSET_ROOT / "app" / "core" / "access" / "user_policy.py",
        "role policy": ASSET_ROOT / "app" / "core" / "access" / "role_policy.py",
        "routes": ASSET_ROOT / "app" / "api" / "v1" / "endpoints" / "users.py",
        "role routes": ASSET_ROOT / "app" / "api" / "v1" / "endpoints" / "roles.py",
        "service": ASSET_ROOT / "app" / "services" / "user_service.py",
        "role service": ASSET_ROOT / "app" / "services" / "role_service.py",
        "transaction service": ASSET_ROOT
        / "app"
        / "services"
        / "user_role_transaction.py",
        "audit service": ASSET_ROOT / "app" / "services" / "audit_service.py",
        "policy tests": ASSET_ROOT / "tests" / "test_policy.py",
        "dependency tests": ASSET_ROOT / "tests" / "test_dependency_logging.py",
        "query tests": ASSET_ROOT / "tests" / "test_rbac_queries.py",
        "service audit tests": ASSET_ROOT
        / "tests"
        / "test_rbac_service_logging.py",
        "read integration tests": ASSET_ROOT
        / "tests"
        / "integration"
        / "test_read_visibility.py",
        "locking integration tests": ASSET_ROOT
        / "tests"
        / "integration"
        / "test_postgresql_locking.py",
        "write integration tests": ASSET_ROOT
        / "tests"
        / "integration"
        / "test_rbac_api.py",
    }
    missing = False
    for name, path in paths.items():
        if not path.is_file():
            fail(
                errors,
                f"missing administrative-visibility {name}: "
                f"{path.relative_to(REPO_ROOT)}",
            )
            missing = True
    if missing:
        return

    text = {name: path.read_text(encoding="utf-8")
            for name, path in paths.items()}
    text["queries"] += "\n" + text["role queries"]
    text["routes"] += "\n" + text["role routes"]
    text["service"] += "\n" + text["role service"] + \
        "\n" + text["transaction service"]
    required_markers = {
        "hierarchy reference": (
            "## Administrative Read Visibility",
            "### Administrative Write Visibility",
            "the current `super_admin` may inspect every non-deleted user and role, and",
            "strictly lower than the current user's `role_level`",
            "Batch-load role grants and user authority",
            "collections such as `bound_role_ids` contain only roles visible to the",
            "A caller without that capability receives `40301`",
            "is concealed with the same `40401`",
        ),
        "atomic reference": (
            "Public nested collections such as `bound_role_ids` use the",
            "Do not reopen a route/request `Session`",
        ),
        "PostgreSQL reference": (
            "Assemble page authorities and role grants in bounded",
            "`bound_role_ids` contains only roles visible to the current user",
        ),
        "testing reference": (
            "role and user pages loading grants and authority in a bounded number of",
            "nested `bound_role_ids`",
        ),
        "queries": (
            "class UserRepository:",
            "async def get_user(",
            "async def check_current_user(",
            "class UserPermissions:",
            "class UserDetails:",
            "class RoleRepository:",
            "def _is_super_admin(",
            "async def get_role_permissions(",
            "async def get_users_info(",
            "current_user: UserInfo",
            "self._is_super_admin(current_user)",
            "Role.level < current_user.role_level",
            "Role.is_protected.is_(False)",
            "async def list_roles(",
            "async def list_users(",
            "async def get_user_detail(",
            "async def get_user_permissions(",
            "async def _load_user_permissions(",
        ),
        "user policy": (
            "def is_administrative_user_visible(",
            "current_user.user_id != target.user_id",
            "target.role_level < current_user.role_level",
        ),
        "role policy": (
            "def is_administrative_role_visible(",
            "role.level < current_user.role_level",
        ),
        "routes": (
            "await role_service.list_roles(",
            "await role_service.get_role_detail(",
            "await user_service.list_users(",
            "await user_service.get_user_detail(",
        ),
        "service": (
            "async def _lock_current_and_target_user(",
            "not is_administrative_user_visible(current_user=current_user, target=target_permissions.user_info)",
            "not is_administrative_role_visible(current_user=locked.current_user, role=grant)",
            "async def _lock_role(",
            "not is_administrative_role_visible(current_user=current_user, role=role_info)",
            "await user_repository.get_user_permissions(",
            "await role_repository.get_role_permissions(",
            "await user_repository.list_users(",
            "await role_repository.list_roles(",
            "await user_repository.get_users_info(",
            "except AppError as exc:",
        ),
        "policy tests": (
            "test_administrative_user_visibility_is_strictly_downward_for_admin",
            "test_administrative_role_visibility_is_strictly_downward_for_admin",
        ),
        "dependency tests": (
            "test_audit_log_failure_does_not_replace_permission_denial",
            "assert caught.value.status_code == 403",
        ),
        "query tests": (
            "test_batch_authority_loader_uses_one_select_for_multiple_users",
            "test_batch_role_grant_loader_uses_one_select_for_multiple_roles",
        ),
        "service audit tests": (
            "test_denied_audit_failure_preserves_original_rbac_error",
            "((forbidden_403, 403), (not_found_404, 404), (conflict_409, 409))",
        ),
        "read integration tests": (
            "test_user_reads_apply_strict_visibility_and_filtered_pagination",
            "test_role_reads_hide_peer_and_higher_authority",
            "test_disabled_roles_remain_assigned_but_do_not_contribute_authority",
            "test_list_select_count_does_not_grow_with_page_size",
        ),
        "locking integration tests": (
            "test_shared_role_lock_select_count_does_not_grow_with_holders",
        ),
        "write integration tests": (
            "test_lower_authority_cannot_manage_users",
            "test_admin_user_writes_conceal_self_peer_higher_and_protected_targets",
            "test_admin_role_writes_conceal_peer_higher_and_protected_roles",
            "test_user_role_batch_conceals_hidden_role_and_remains_atomic",
        ),
    }
    for name, markers in required_markers.items():
        for marker in markers:
            if marker not in text[name]:
                relative = paths[name].relative_to(REPO_ROOT)
                fail(
                    errors,
                    f"{relative} is missing administrative-visibility marker: "
                    f"{marker!r}",
                )

    def function_source(source: str, function_name: str) -> str:
        """
        按 AST 定位函数并统一格式，避免校验依赖缩进、换行或相邻函数顺序。

        :param source: 已通过语法校验的 Python 源码，可以包含多个模块的文本。
        :param function_name: 需要检查的唯一函数或方法名称。
        :return: 格式规范化后的函数源码；找不到时返回空字符串并由调用方报错。
        """
        for node in ast.walk(ast.parse(source)):
            if (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == function_name
            ):
                return ast.unparse(node)
        return ""

    query_sections = {
        "shared user permissions read": (
            "_load_user_permissions",
            (
                "UserRole.user_id",
                "Role",
                "Permission.key.label('permission_key')",
                "UserRole.deleted_at.is_(None)",
                "Role.deleted_at.is_(None)",
                "RolePermission.deleted_at.is_(None)",
                "Permission.deleted_at.is_(None)",
                "populate_existing=True",
                "Role.level < current_user.role_level",
                "Role.is_protected.is_(False)",
                "await session.execute(role_permissions_query)",
                "role.is_active",
                "UserPermissions(",
                "user_info=self._build_user_info(",
                "user_info_with_disabled_roles=self._build_user_info(",
            ),
        ),
        "user permissions": (
            "get_user_permissions",
            (
                "users: Sequence[User]",
                "await self._load_user_permissions(",
            ),
        ),
        "user projection": (
            "get_users_info",
            (
                "await self._load_user_permissions(",
                "current_user=current_user",
                "permissions.user_info_with_disabled_roles.roles",
                "user_info = permissions.user_info",
                "user_info=user_info",
            ),
        ),
        "visible users": (
            "_build_user_query",
            (
                "if self._is_super_admin(current_user):",
                "User.user_id != current_user.user_id",
                "if current_user.role_level <= 0:",
                "UserRole.user_id == User.user_id",
                "Role.level >= current_user.role_level",
                "~has_hidden_role",
            ),
        ),
        "visible roles": (
            "_build_role_query",
            (
                "if any(",
                "role.key == SystemRoleKey.SUPER_ADMIN.value and role.is_super_admin",
                "Role.level < current_user.role_level",
                "Role.is_protected.is_(False)",
            ),
        ),
    }
    query_source = text["queries"]
    for name, (function_name, markers) in query_sections.items():
        section = function_source(query_source, function_name)
        for marker in markers:
            if marker not in section:
                fail(
                    errors,
                    f"{paths['queries'].relative_to(REPO_ROOT)} {name} section "
                    f"is missing {marker!r}",
                )

    # 已读取或锁住的用户直接复用；权限入口不能再按 ID 重查同一用户。
    for function_name in ("get_user_permissions", "_load_user_permissions"):
        section = function_source(query_source, function_name)
        if "self.get_user(" in section:
            fail(errors, f"{function_name} must reuse loaded users without another account query")

    # 完整权限只保留一个固定返回映射的入口；页面可见过滤仅供内部页面读取使用。
    repository = _class_node(ast.parse(text["queries"]), "UserRepository")
    if repository is not None:
        permissions_loader = _function_node(repository.body, "get_user_permissions")
        if permissions_loader is not None and (
            tuple(argument.arg for argument in permissions_loader.args.kwonlyargs) != ("users",)
            or permissions_loader.returns is None
            or ast.unparse(permissions_loader.returns) != "dict[str, UserPermissions]"
        ):
            fail(errors, "get_user_permissions must accept users only and return a user-ID mapping")
        if any(_function_node(repository.body, name) is not None for name in (
            "get_users_permissions", "_select_user_role_permissions", "_get_user_permissions",
        )):
            fail(errors, "user permission reads must not restore separate singular/batch or query wrappers")

    service_source = text["service"]
    transaction_tree = ast.parse(text["transaction service"])
    transaction = _function_node(transaction_tree.body, "user_role_transaction")
    audit_class = _class_node(ast.parse(text["audit service"]), "AuditService")
    audit_writer = _function_node(
        audit_class.body, "audit_denied") if audit_class is not None else None
    denial_preserves_error = False
    if transaction is not None and audit_writer is not None:
        calls_shared_writer = ".audit_denied(" in ast.unparse(transaction)
        reraises_original = any(
            isinstance(node, ast.ExceptHandler)
            and isinstance(node.type, ast.Name)
            and node.type.id == "AppError"
            and node.body
            and isinstance(node.body[-1], ast.Raise)
            and node.body[-1].exc is None
            for node in ast.walk(transaction)
        )
        handles_audit_failure = any(
            isinstance(node, ast.ExceptHandler)
            and isinstance(node.type, ast.Name)
            and node.type.id == "Exception"
            and any(
                isinstance(call, ast.Call)
                and ast.unparse(call.func) == "safe_log"
                and any(
                    isinstance(argument, ast.Constant)
                    and argument.value == "audit.write.failed"
                    for argument in call.args
                )
                for call in ast.walk(node)
            )
            and not any(isinstance(child, ast.Raise) for child in ast.walk(node))
            for node in ast.walk(audit_writer)
        )
        denial_preserves_error = (
            calls_shared_writer and reraises_original and handles_audit_failure
        )
    if not denial_preserves_error:
        fail(
            errors,
            "RBAC service must log denied-audit failure and re-raise the original "
            "authorization error",
        )

    service_sections = {
        "user write gate": (
            "_lock_current_and_target_user",
            (
                "if required_permission.value not in current_user.permissions:",
                "if target_user_id not in users:",
                "if not is_administrative_user_visible(current_user=current_user, "
                "target=target_permissions.user_info):",
            ),
        ),
        "user-role batch gate": (
            "change_user_roles",
            (
                "role_info_by_id = await role_repository.get_role_permissions(",
                "not is_administrative_role_visible(current_user=locked.current_user, role=grant)",
                "decision = decide_role_change(",
            ),
        ),
        "role write gate": (
            "_lock_role",
            (
                "if required_permission.value not in current_user.permissions:",
                "role = locked_roles.get(role_id)",
                "if not is_administrative_role_visible(current_user=current_user, role=role_info):",
            ),
        ),
    }
    for name, (function_name, ordered_markers) in service_sections.items():
        section = function_source(service_source, function_name)
        if not section:
            fail(
                errors,
                f"{paths['service'].relative_to(REPO_ROOT)} {name} section missing",
            )
            continue
        positions = [section.find(marker) for marker in ordered_markers]
        if any(position < 0 for position in positions) or positions != sorted(
            positions
        ):
            fail(
                errors,
                f"{paths['service'].relative_to(REPO_ROOT)} {name} must keep "
                "capability, visibility, and policy checks in non-leaking order",
            )


def validate_super_admin_bootstrap(errors: list[str]) -> None:
    sql_path = ASSET_ROOT / "sql" / "bootstrap_super_admin.sql"
    handover_path = ASSET_ROOT / "sql" / "handover_super_admin.sql"
    legacy_python_path = ASSET_ROOT / "app" / "rbac" / "bootstrap.py"
    if legacy_python_path.exists():
        fail(
            errors,
            "legacy Python super-admin bootstrap entry point must not be distributed",
        )
    if not sql_path.is_file():
        return

    sql = sql_path.read_text(encoding="utf-8")
    required_markers = (
        "\\set ON_ERROR_STOP on",
        "BEGIN;",
        "rbac_state",
        "WHERE scope = 'global'",
        "FOR UPDATE",
        "target user account does not exist",
        "INSERT INTO user_roles",
        # 留存 SQL 面向旧 UUID schema，不能假装已经适配当前统一审计表。
        "INSERT INTO rbac_audit_events",
        "super_admin.bootstrap",
        "COMMIT;",
    )
    for marker in required_markers:
        if marker not in sql:
            relative = sql_path.relative_to(REPO_ROOT)
            fail(
                errors, f"{relative} is missing bootstrap invariant: {marker!r}")

    if "INSERT INTO users" in sql:
        fail(errors, "super-admin bootstrap SQL must require an existing user")
    if not handover_path.is_file():
        fail(errors, "offline super-admin handover SQL is missing")
        return
    handover = handover_path.read_text(encoding="utf-8")
    for marker in (
        "\\set ON_ERROR_STOP on",
        "BEGIN;",
        "rbac_state",
        "FOR UPDATE",
        "UPDATE user_roles",
        "INSERT INTO user_roles",
        "INSERT INTO rbac_audit_events",
        "COMMIT;",
    ):
        if marker not in handover:
            fail(
                errors, f"offline super-admin handover SQL is missing {marker!r}")
    if "INSERT INTO users" in handover:
        fail(errors, "offline super-admin handover must require an existing user")


def validate_rbac_database_naming(errors: list[str]) -> None:
    paths = {
        "state model": ASSET_ROOT / "app" / "models" / "postgres" / "rbac_state.py",
        "audit model": ASSET_ROOT / "app" / "models" / "postgres" / "operation_audit.py",
        "role model": ASSET_ROOT / "app" / "models" / "postgres" / "role.py",
        "migration": ASSET_ROOT
        / "alembic"
        / "versions"
        / "0001_single_project_rbac.py",
        "bootstrap": ASSET_ROOT / "sql" / "bootstrap_super_admin.sql",
        "schema reference": SKILL_ROOT
        / "references"
        / "postgresql-rbac-implementation.md",
    }
    if any(not path.is_file() for path in paths.values()):
        return

    required_markers = {
        "state model": (
            "class RbacState(Base):",
            '__tablename__ = "rbac_state"',
        ),
        "audit model": (
            "class OperationAuditEvent(Base):",
            '__tablename__ = "operation_audit_events"',
        ),
        "role model": (
            "is_super_admin: Mapped[bool]",
            '"uq_roles_single_super_admin"',
        ),
        "migration": (
            '"rbac_state"',
            'name="pk_rbac_state"',
            'name="scope_global"',
            'name="epoch_nonnegative"',
            '"rbac_audit_events"',
            'name="pk_rbac_audit_events"',
            # 已发布迁移保留当时名称，当前模型单独核对 user_id 命名。
            '"ix_rbac_audit_actor_created"',
            '"ix_rbac_audit_request_id"',
            '"is_super_admin"',
            '"uq_roles_single_super_admin"',
        ),
        "bootstrap": (
            "FROM rbac_state",
            "FOR UPDATE",
            "INSERT INTO rbac_audit_events",
        ),
        "schema reference": ("`rbac_state`", "`operation_audit_events`"),
    }
    for name, markers in required_markers.items():
        content = paths[name].read_text(encoding="utf-8")
        for marker in markers:
            if marker not in content:
                relative = paths[name].relative_to(REPO_ROOT)
                fail(
                    errors, f"{relative} is missing RBAC database marker: {marker!r}")

    stale_markers = (
        "authorization_audit_events",
        "AuthorizationAuditEvent",
        "ix_authz_audit",
        "authorization_state",
        "AuthorizationState",
        "lock_authorization_state",
        "authorization-state",
        "authorization_scope_global",
        "authorization_epoch_nonnegative",
        "pk_authorization_state",
        "is_owner",
        "owner_tier_reserved",
        "owner_shape",
        "uq_roles_single_owner",
    )
    for path in SKILL_ROOT.rglob("*"):
        relative_parts = path.relative_to(SKILL_ROOT).parts
        if any(
            part in FORBIDDEN_DIRECTORY_NAMES
            or part.endswith(FORBIDDEN_DIRECTORY_SUFFIXES)
            for part in relative_parts
        ):
            continue
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        content = path.read_text(encoding="utf-8")
        for marker in stale_markers:
            if marker in content:
                relative = path.relative_to(REPO_ROOT)
                fail(
                    errors, f"{relative} contains obsolete RBAC name: {marker!r}")


def validate_api_internationalization(errors: list[str]) -> None:
    paths = {
        "entrypoint": SKILL_ROOT / "SKILL.md",
        "reference": SKILL_ROOT / "references" / "api-internationalization.md",
        "response reference": SKILL_ROOT / "references" / "api-response-standard.md",
        "Chinese architecture": (
            SKILL_ROOT / "references" / "architecture-overview.zh-CN.md"
        ),
        "README": REPO_ROOT / "README.md",
        "Chinese README": REPO_ROOT / "README.zh-CN.md",
        "asset README": ASSET_ROOT / "README.md",
        "changelog": REPO_ROOT / "CHANGELOG.md",
        "Chinese changelog": REPO_ROOT / "CHANGELOG.zh-CN.md",
        "release checklist": REPO_ROOT / "RELEASE_CHECKLIST.md",
        "Chinese release checklist": REPO_ROOT / "RELEASE_CHECKLIST.zh-CN.md",
        "implementation": ASSET_ROOT / "app" / "core" / "i18n" / "messages.py",
        "language": ASSET_ROOT / "app" / "core" / "i18n" / "language.py",
        "validation": ASSET_ROOT / "app" / "core" / "i18n" / "validation_messages.py",
        "contract": ASSET_ROOT / "app" / "core" / "response.py",
        "codes": ASSET_ROOT / "app" / "core" / "codes.py",
        "request middleware": ASSET_ROOT / "app" / "core" / "middleware" / "request_logging.py",
        "exception handlers": ASSET_ROOT / "app" / "core" / "exception_handlers.py",
        "errors": ASSET_ROOT / "app" / "core" / "exceptions.py",
        "pyproject": ASSET_ROOT / "pyproject.toml",
        "tests": ASSET_ROOT / "tests" / "test_i18n.py",
        "Chinese catalog": ASSET_ROOT / "app" / "assets" / "locales" / "zh-CN.json",
        "English catalog": ASSET_ROOT / "app" / "assets" / "locales" / "en.json",
    }
    if any(not path.is_file() for path in paths.values()):
        return

    require_semantics(
        errors,
        path=paths["reference"],
        checks=(
            (
                "default Chinese and English Accept-Language contract",
                (r"Accept-Language.*zh-CN.*en",),
            ),
            (
                "canonical response language and cache variation headers",
                (r"Content-Language.*Vary.*Accept-Language",),
            ),
            (
                "stable machine fields are not translated",
                (r"HTTP status.*business code.*remain language-independent",),
            ),
            (
                "validation uses stable error types rather than raw messages",
                (
                    r"Do not return Pydantic.s raw.*error\[.type.\]",
                    r"error\[.type.\].*raw",
                ),
            ),
            (
                "validation paths do not reflect attacker-controlled keys",
                (r"mask an extra field.*mapping keys",),
            ),
            (
                "request language never selects a resource path",
                (r"Never turn a request value into a file path or dynamic import",),
            ),
            (
                "zero-weight languages are skipped and wildcard does not choose a language",
                (r"q=0.*skips.*\*.*does not choose",),
            ),
        ),
    )
    for label in (
        "response reference",
        "Chinese architecture",
        "README",
        "Chinese README",
        "asset README",
    ):
        text = paths[label].read_text(encoding="utf-8")
        for marker in ("Accept-Language", "Content-Language", "Vary: Accept-Language"):
            if marker not in text:
                fail(errors, f"{label} is missing API i18n marker {marker!r}")

    document_markers = {
        "Chinese architecture": (
            "api-internationalization.md",
            "静态 Schema",
            "数据库",
        ),
        "README": ("API internationalization", "Database-authored", "static schema"),
        "Chinese README": ("API 多语言", "数据库", "静态 Schema"),
        "asset README": ("Database-authored", "static schema descriptions"),
    }
    for label, markers in document_markers.items():
        content = paths[label].read_text(encoding="utf-8")
        for marker in markers:
            if marker not in content:
                fail(
                    errors, f"{label} is missing API i18n boundary {marker!r}")

    release_documents = {
        "changelog": (
            "## [0.6.0] - 2026-09-20",
            "Accept-Language",
        ),
        "Chinese changelog": (
            "## [0.6.0] - 2026-09-20",
            "Accept-Language",
        ),
        "release checklist": (
            "## v0.6.0 acceptance baseline",
            "Accept-Language",
        ),
        "Chinese release checklist": (
            "## v0.6.0 验收基线",
            "Accept-Language",
        ),
    }
    for label, (heading, marker) in release_documents.items():
        content = paths[label].read_text(encoding="utf-8")
        _, separator, remainder = content.partition(heading)
        if not separator:
            fail(errors, f"{label} is missing {heading!r}")
            continue
        release_section = remainder.split("\n## ", maxsplit=1)[0]
        if marker not in release_section:
            fail(
                errors, f"{label} does not document API i18n under {heading!r}")

    implementation_tree = _parse_python(
        errors, paths["implementation"], label="API i18n implementation"
    )
    if implementation_tree is None:
        return
    message_key_class = _class_node(implementation_tree, "MessageKey")
    if message_key_class is None:
        fail(errors, "API i18n implementation is missing MessageKey")
        return
    message_keys = {
        node.value.value
        for node in message_key_class.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    }
    if not message_keys:
        fail(errors, "MessageKey must contain a closed set of string keys")
        return

    catalogs: dict[str, dict[str, object]] = {}
    for label in ("Chinese catalog", "English catalog"):
        try:
            raw_catalog = json.loads(paths[label].read_text(encoding="utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            fail(errors, f"{label} is not valid UTF-8 JSON: {exc}")
            continue
        if not isinstance(raw_catalog, dict):
            fail(errors, f"{label} must be a JSON object")
            continue
        catalogs[label] = raw_catalog
        if set(raw_catalog) != message_keys:
            fail(errors, f"{label} keys do not exactly match MessageKey")
        for key, value in raw_catalog.items():
            if (
                not isinstance(key, str)
                or not isinstance(value, str)
                or value != value.strip()
                or not value
                or len(value) > 200
                or any(ord(character) < 32 for character in value)
            ):
                fail(errors, f"{label} contains an unsafe value for {key!r}")

    module_markers = {
        "implementation": ("CATALOGS.get(locale, CATALOGS[DEFAULT_LOCALE])[key.value]",),
        "language": (
            'DEFAULT_LOCALE = "zh-CN"',
            'SUPPORTED_LOCALES = ("zh-CN", "en")',
            "_MAX_ACCEPT_LANGUAGE_LENGTH",
            "_MAX_LANGUAGE_RANGES",
            "def select_locale(",
            "if 0.0 < quality <= 1.0",
            "request.state.locale",
            'headers["Content-Language"]',
            'headers["Vary"]',
        ),
        "validation": ("def validation_field", "def validation_message"),
    }
    for label, markers in module_markers.items():
        content = paths[label].read_text(encoding="utf-8")
        for marker in markers:
            if marker not in content:
                fail(errors, f"API i18n {label} is missing {marker!r}")

    required_code_markers = {
        "contract": (
            "message_key: MessageKey",
            "translate(request, message_key)",
            "apply_language_headers(localized_headers, locale_for_request(request))",
        ),
        "request middleware": (
            "request.state.locale = locale_for_request(request)",
            "apply_language_headers(response_headers, request.state.locale)",
        ),
        "exception handlers": (
            "field=validation_field(error)",
            "message=validation_message(request, error)",
        ),
        "errors": ("message_key: MessageKey", "self.message_key = message_key"),
        "pyproject": ('"app.assets.locales" = ["*.json"]',),
        "tests": (
            "test_catalogs_are_complete_bounded_and_safe",
            "test_accept_language_negotiation",
            "test_untrusted_language_values_never_escape_supported_locales",
            "test_concurrent_requests_do_not_share_locale",
            "test_validation_outer_and_field_messages_are_localized",
            "test_validation_fields_do_not_echo_untrusted_keys",
            "test_unhandled_500_keeps_language_headers",
            '"zh-CN;q=0, *;q=1"',
            '"zh-CN;q=0, zh;q=1"',
        ),
    }
    for label, markers in required_code_markers.items():
        content = paths[label].read_text(encoding="utf-8")
        for marker in markers:
            if marker not in content:
                fail(errors, f"{label} is missing API i18n marker {marker!r}")

    for source_path in sorted((ASSET_ROOT / "app").rglob("*.py")):
        source = source_path.read_text(encoding="utf-8")
        relative = source_path.relative_to(REPO_ROOT)
        if "public_message" in source:
            fail(
                errors, f"{relative} stores rendered public_message instead of a key")
        tree = _parse_python(errors, source_path, label=str(relative))
        if tree is None:
            continue
        if source_path != paths["implementation"]:
            _validate_runtime_message_literals(
                tree, errors, label=str(relative))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            call_name = (
                node.func.id
                if isinstance(node.func, ast.Name)
                else node.func.attr
                if isinstance(node.func, ast.Attribute)
                else None
            )
            keyword_names = {keyword.arg for keyword in node.keywords}
            if call_name in {"api_response", "error_content"}:
                if "message" in keyword_names or "message_key" not in keyword_names:
                    fail(
                        errors, f"{relative} has a response call without message_key")
            if call_name == "AppError" and (
                "public_message" in keyword_names or "message_key" not in keyword_names
            ):
                fail(
                    errors, f"{relative} constructs AppError without message_key")


def validate_api_response_contract(errors: list[str]) -> None:
    paths = {
        "entrypoint": SKILL_ROOT / "SKILL.md",
        "reference": SKILL_ROOT / "references" / "api-response-standard.md",
        "contract": ASSET_ROOT / "app" / "core" / "response.py",
        "codes": ASSET_ROOT / "app" / "core" / "codes.py",
        "request middleware": ASSET_ROOT / "app" / "core" / "middleware" / "request_logging.py",
        "exception handlers": ASSET_ROOT / "app" / "core" / "exception_handlers.py",
        "routes": ASSET_ROOT / "app" / "api" / "v1" / "endpoints" / "roles.py",
        "user routes": ASSET_ROOT / "app" / "api" / "v1" / "endpoints" / "users.py",
        "permission routes": ASSET_ROOT
        / "app"
        / "api"
        / "v1"
        / "endpoints"
        / "permissions.py",
        "errors": ASSET_ROOT / "app" / "core" / "exceptions.py",
        "schemas": ASSET_ROOT / "app" / "schemas" / "role.py",
        "service": ASSET_ROOT / "app" / "services" / "role_service.py",
        "proxy backend": SKILL_ROOT / "references" / "proxy-availability-backend.md",
        "proxy frontend": SKILL_ROOT / "references" / "proxy-availability-frontend.md",
    }
    if any(not path.is_file() for path in paths.values()):
        return

    required_markers = {
        "entrypoint": (
            "references/api-response-standard.md",
            "`code`, `message`, `data`",
            "`expected_version`",
            "`40931`",
        ),
        "reference": (
            "`items`, `page`, `page_size`, and `total`",
            "server-generated UUIDv4",
            "Resource Version Instead Of A Strong Envelope ETag",
        ),
        "contract": (
            "class ResponseBase(BaseModel):",
            "class ApiResponse(ResponseBase, Generic[T]):",
            "class PageResponse(ResponseBase, Generic[T]):",
            'ConfigDict(extra="forbid", frozen=True)',
            "request_id: UUID4",
        ),
        "codes": (
            "class BusinessCode(IntEnum):",
            "ROLE_VERSION_STALE = 40931",
            "return status_code * 100 + 1",
        ),
        "request middleware": (
            "request.state.request_id = str(uuid.uuid4())",
            'response_headers["X-Request-ID"]',
        ),
        "exception handlers": (
            "handle_request_validation_error",
            "handle_unexpected_error",
            "handle_database_unavailable",
            'headers.setdefault("WWW-Authenticate", "Bearer")',
            "500: (BusinessCode.INTERNAL_ERROR",
        ),
        "routes": (
            "response_model=ApiResponse[PageResponse[PermissionResponse]]",
            "response_model=ApiResponse[PageResponse[RoleResponse]]",
            "response_model=ApiResponse[PageResponse[UserResponse]]",
            "expected_version=body.expected_version",
        ),
        "errors": (
            "status_code=status.HTTP_400_BAD_REQUEST",
            "business_code: BusinessCode = BusinessCode.BAD_REQUEST",
            "business_code=business_code",
        ),
        "service": (
            "_check_role_version",
            "decide_role_permissions_change",
        ),
        "proxy backend": ("business code `50302`",),
        "proxy frontend": ("business code\n`50302`",),
    }
    route_text = "\n".join(
        paths[name].read_text(encoding="utf-8")
        for name in ("routes", "user routes", "permission routes")
    )
    for name, markers in required_markers.items():
        content = (
            route_text if name == "routes" else paths[name].read_text(
                encoding="utf-8")
        )
        for marker in markers:
            if marker not in content:
                relative = paths[name].relative_to(REPO_ROOT)
                fail(
                    errors, f"{relative} is missing API contract marker: {marker!r}")

    for stale_marker in ("IfMatchHeader", 'response.headers["ETag"]'):
        if stale_marker in route_text:
            relative = paths["routes"].relative_to(REPO_ROOT)
            fail(
                errors, f"{relative} contains stale API contract: {stale_marker!r}")

    # 按每个模型真实字段检查，既不依赖排版，也不会让另一类中的同名字面量冒充所需约束。
    schema_tree = _parse_python(errors, paths["schemas"], label="role schemas")
    if schema_tree is not None:
        _validate_role_schema_contract(schema_tree, errors)
    contract_tree = _parse_python(
        errors, paths["contract"], label="API response contract")
    if contract_tree is not None:
        _validate_field_contract(
            contract_tree, "ApiResponse", "code", "int",
            {"strict": "True", "ge": "10000", "le": "59999"}, errors,
        )

    service_text = paths["service"].read_text(encoding="utf-8")
    policy_markers = {
        "update_role": "_check_role_change",
        "set_role_active": "_check_role_change",
        "delete_role": "_check_role_change",
        "change_role_permissions": "decide_role_permissions_change",
    }
    for method_name, policy_marker in policy_markers.items():
        start = service_text.find(f"    async def {method_name}(")
        end = service_text.find("\n    async def ", start + 1)
        method_text = service_text[start: end if end >= 0 else None]
        policy_position = method_text.find(policy_marker)
        version_position = method_text.find("_check_role_version")
        if (
            start < 0
            or policy_position < 0
            or version_position < 0
            or policy_position > version_position
        ):
            fail(
                errors,
                f"{method_name} must authorize the locked proposal before "
                "checking expected_version",
            )

    for name in ("proxy backend", "proxy frontend"):
        if "availability_cache_available" in paths[name].read_text(encoding="utf-8"):
            relative = paths[name].relative_to(REPO_ROOT)
            fail(errors, f"{relative} contains an invalid fifth envelope flag")


def validate_logging_and_audit(errors: list[str]) -> None:
    paths = {
        "entrypoint": SKILL_ROOT / "SKILL.md",
        "logging reference": SKILL_ROOT / "references" / "operational-logging.md",
        "audit reference": SKILL_ROOT / "references" / "audit-module.md",
        "logging implementation": ASSET_ROOT / "app" / "core" / "logging" / "events.py",
        "logging context": ASSET_ROOT / "app" / "core" / "logging" / "context.py",
        "logging output": ASSET_ROOT / "app" / "core" / "logging" / "output.py",
        "audit implementation": ASSET_ROOT / "app" / "core" / "audit.py",
        "audit service": ASSET_ROOT / "app" / "services" / "audit_service.py",
        "application": ASSET_ROOT / "app" / "main.py",
        "request middleware": ASSET_ROOT / "app" / "core" / "middleware" / "request_logging.py",
        "database": ASSET_ROOT / "app" / "db" / "postgres_db.py",
        "settings": ASSET_ROOT / "app" / "core" / "config.py",
        "model": ASSET_ROOT / "app" / "models" / "postgres" / "operation_audit.py",
        "migration": ASSET_ROOT
        / "alembic"
        / "versions"
        / "0001_single_project_rbac.py",
        "bootstrap": ASSET_ROOT / "sql" / "bootstrap_super_admin.sql",
        "logging tests": ASSET_ROOT / "tests" / "test_logging.py",
        "logging formatter tests": ASSET_ROOT
        / "tests"
        / "test_logging_formatter.py",
        "request logging tests": ASSET_ROOT / "tests" / "test_request_logging.py",
        "audit tests": ASSET_ROOT / "tests" / "test_audit.py",
        "database tests": ASSET_ROOT
        / "tests"
        / "integration"
        / "test_rbac_constraints.py",
    }
    if any(not path.is_file() for path in paths.values()):
        return

    require_semantics(
        errors,
        path=paths["entrypoint"],
        checks=(
            (
                "entrypoint routes logging and RBAC audit work to their references",
                (r"references/operational-logging\.md.*references/audit-module\.md",),
            ),
        ),
    )
    required_markers = {
        "logging reference": (
            "## Non-Negotiable Boundary",
            "## Request Completion Contract",
            "## Safe Exception Telemetry",
            "## Formatter And Emitter Safety",
            "## Forbidden Data",
            "## Required Verification",
            "http.request.completed",
            "http.request.post_response_failed",
        ),
        "audit reference": (
            "## `operation_audit_events` Schema",
            "## Transaction Outcomes",
            "## Integrity And Database Access",
            "## Retention, Partitioning, And Recovery",
            "## Verification",
        ),
        "logging implementation": (
            "class SafeJsonFormatter(logging.Formatter):",
            "def request_log_level(",
            "def safe_exception_metadata(",
            "def safe_log(",
        ),
        "logging context": (
            "def bind_request_context(",
            "def deactivate_request_context(",
            "def reset_request_context(",
            "def current_request_id(",
        ),
        "logging output": (
            "class SafeStreamHandler(logging.StreamHandler[TextIO]):",
            "def configure_logging(",
            '"uvicorn.access"',
            'logging.getLogger("uvicorn.access").disabled = True',
        ),
        "audit implementation": (
            "class AuditSource(StrEnum):",
            "def sanitize_audit_state(",
            "def validate_audit_action(",
            "def validate_audit_reason(",
            "def validate_audit_request_id(",
            "def get_audit_request_id(",
        ),
        "audit service": (
            "class AuditService:",
            "def audit_success(",
            "async def audit_denied(",
            "def _build_event(",
            "def _response_snapshot(",
        ),
        "application": (
            "configure_logging(",
            "title=settings.service_name",
            "version=settings.service_version",
        ),
        "request middleware": (
            "bind_request_context(",
            "reset_request_context(",
            '"http.request.completed"',
            '"business_code"',
            '"duration_ms"',
            '"response_started"',
            '"response_completed"',
            '"client_disconnected"',
            '"http.request.post_response_failed"',
        ),
        "database": ("hide_parameters=True",),
        "settings": (
            "log_level: str",
            "log_include_exception_details: bool",
        ),
        "model": (
            "source IN ('http', 'service', 'job', 'operator', 'migration')",
            '@validates("request_data", "response_data", "before_state", "after_state")',
            'Index("ix_operation_audit_created_id"',
            'Index("ix_operation_audit_request_id"',
        ),
        "migration": (
            "CREATE FUNCTION reject_rbac_audit_event_mutation()",
            "CREATE TRIGGER trg_rbac_audit_events_append_only",
            "BEFORE UPDATE OR DELETE ON rbac_audit_events",
            '"ix_rbac_audit_created_id"',
        ),
        "bootstrap": ("'operator'",),
        "logging tests": (
            "test_json_log_contains_stable_context_and_redacts_nested_secrets",
            "test_request_completion_log_uses_response_request_id",
        ),
        "logging formatter tests": (
            "test_safe_exception_metadata_is_unique_and_omits_message_and_locals",
            "test_safe_log_contains_logger_failures",
        ),
        "request logging tests": (
            "test_stream_failure_emits_one_error_completion_with_started_status",
            "test_multichunk_stream_emits_one_successful_completion",
            "test_send_failure_records_the_observed_response_boundary",
            "test_client_disconnect_without_response_is_recorded",
        ),
        "audit tests": (
            "test_audit_state_rejects_credentials_tokens_and_direct_identifiers",
        ),
        "database tests": ("test_operation_audit_rows_are_append_only",),
    }
    for name, markers in required_markers.items():
        content = paths[name].read_text(encoding="utf-8")
        for marker in markers:
            if marker not in content:
                relative = paths[name].relative_to(REPO_ROOT)
                fail(
                    errors,
                    f"{relative} is missing logging/audit marker: {marker!r}",
                )

    # 统一表只保留已确认的 16 个字段；避免旧版本计数或操作人类型随重构被加回来。
    audit_tree = _parse_python(errors, paths["model"], label="operation audit")
    audit_model = _class_node(
        audit_tree, "OperationAuditEvent") if audit_tree is not None else None
    audit_fields = {
        node.target.id for node in audit_model.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    } if audit_model is not None else set()
    expected_fields = {
        "id", "category", "action", "outcome", "reason_code", "user_id",
        "target_user_id", "target_role_id", "source", "request_data", "response_data",
        "password_fingerprint", "before_state", "after_state", "request_id", "created_at",
    }
    if audit_fields != expected_fields:
        fail(errors, "operation audit fields must match the approved 16-field contract: "
             f"missing={sorted(expected_fields - audit_fields)!r}, "
             f"extra={sorted(audit_fields - expected_fields)!r}")
    # 业务只使用两个 audit_ 入口；旧构造器或重复包装不能以兼容别名重新暴露。
    service_tree = _parse_python(
        errors, paths["audit service"], label="audit service")
    service_class = _class_node(
        service_tree, "AuditService") if service_tree is not None else None
    methods = {node.name for node in service_class.body
               if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))} if service_class else set()
    obsolete_methods = {"build_event", "response_snapshot",
                        "write_denied_event", "write_client_denial"}
    if methods.intersection(obsolete_methods):
        fail(errors, "AuditService must expose audit_success/audit_denied without old public wrappers")


def validate_business_audit(errors: list[str]) -> None:
    paths = {
        "entrypoint": SKILL_ROOT / "SKILL.md",
        "policy reference": SKILL_ROOT / "references" / "business-audit-module.md",
        "postgresql reference": SKILL_ROOT
        / "references"
        / "business-audit-postgresql.md",
        "operations reference": SKILL_ROOT
        / "references"
        / "business-audit-operations.md",
        "implementation": ASSET_ROOT / "app" / "services" / "business_audit_service.py",
        "contract": ASSET_ROOT / "app" / "core" / "business_audit.py",
        "model": ASSET_ROOT / "app" / "models" / "postgres" / "business_audit.py",
        "migration": ASSET_ROOT / "alembic" / "versions" / "0003_business_audit.py",
        "alembic environment": ASSET_ROOT / "alembic" / "env.py",
        "model registry": ASSET_ROOT / "app" / "models" / "postgres" / "__init__.py",
        "unit tests": ASSET_ROOT / "tests" / "test_business_audit.py",
        "database tests": ASSET_ROOT
        / "tests"
        / "integration"
        / "test_business_audit.py",
        "database fixtures": ASSET_ROOT / "tests" / "integration" / "conftest.py",
        "test configuration": ASSET_ROOT / "pyproject.toml",
    }
    missing = False
    for name, path in paths.items():
        if not path.is_file():
            relative = path.relative_to(REPO_ROOT)
            fail(errors, f"missing business-audit {name}: {relative}")
            missing = True
    if missing:
        return

    require_semantics(
        errors,
        path=paths["entrypoint"],
        checks=(
            (
                "all three business-audit references are routed by task",
                (
                    r"references/business-audit-module\.md.*references/business-audit-postgresql\.md.*references/business-audit-operations\.md",
                ),
            ),
        ),
    )
    required_markers = {
        "policy reference": (
            "`operation_audit_events`",
            "business_audit_events",
            "## Core Event Contract",
            "## Outcome Semantics",
            "## Starter Event Catalog",
            "## Trusted Event Construction",
            "## Safe Snapshots And Context",
            "## Transaction Decision Table",
        ),
        "postgresql reference": (
            "## PostgreSQL Model Baseline",
            "The Skill delivers models and application code.",
            "BusinessAuditEvent",
            "BusinessAuditActionSpec",
            "BusinessAuditService",
            "action_specs=BUSINESS_AUDIT_CATALOG",
            "source_type=BusinessAuditSourceType.USER",
            "user_id=authenticated_user.user_id",
            "target_user_id=refund.user_id",
            "entrypoint=AuditSource.HTTP",
            'event_id=new_audit_id("BA")',
            "event_id=command.audit_event_id",
            "add_succeeded(",
            "add_after_savepoint_rollback(",
            "write_after_rollback(",
            "## Append-Only Controls",
            "writers receive `INSERT`, not `UPDATE`, `DELETE`, or `TRUNCATE`",
            "row mutation and table truncation",
            "ORM metadata does not generate those",
        ),
        "operations reference": (
            "append-only source of truth",
            "## Read And Export Access",
            "## Retention And Partitioning",
            "## Legal Hold And Privacy",
            "## Backup And Recovery",
        ),
        "contract": (
            "class BusinessAuditOutcome(StrEnum):",
            "class BusinessAuditSourceType(StrEnum):",
            "class BusinessAuditActionSpec:",
            "class BusinessAuditFacts:",
            "source_type: BusinessAuditSourceType",
            "user_id: str | None",
            "source_id: str | None",
            "target_user_id:",
            "target_type:",
            "target_id:",
            "entrypoint: AuditSource",
            "source_types:",
        ),
        "model": (
            "class BusinessAuditEvent(Base):",
            '__tablename__ = "business_audit_events"',
            'name=conv("ck_business_audit_id_format")',
            'name=conv("ck_business_audit_source_identity")',
            'name=conv("ck_business_audit_user_id_format")',
            'name=conv("ck_business_audit_target_user_id_format")',
            'name=conv("ck_business_audit_user_target")',
            'name=conv("ck_business_audit_entrypoint")',
            'name=conv("ck_business_audit_non_success_after")',
        ),
        "implementation": (
            "class BusinessAuditService:",
            "def add_succeeded(",
            "def add_after_savepoint_rollback(",
            "async def write_after_rollback(",
            "if not session.in_transaction():",
            "async with self._session_factory() as session:",
        ),
        "migration": (
            'revision: str = "0003_business_audit"',
            'down_revision: str | None = "0002_system_roles"',
            '"business_audit_events"',
            'name=op.f("ck_business_audit_id_uuid4")',
            'name=op.f("ck_business_audit_outcome")',
            # 历史迁移保留旧 actor 字段，当前模型使用明确的用户、来源和目标字段。
            'name=op.f("ck_business_audit_actor_presence")',
            'name=op.f("ck_business_audit_non_success_after")',
            "CREATE FUNCTION reject_business_audit_mutation()",
            "CREATE TRIGGER trg_business_audit_no_update_delete",
            "BEFORE UPDATE OR DELETE ON business_audit_events",
            "CREATE TRIGGER trg_business_audit_no_truncate",
            "BEFORE TRUNCATE ON business_audit_events",
        ),
        "alembic environment": (
            "from app.models.postgres import Base",
            "target_metadata = Base.metadata",
        ),
        "unit tests": (
            "test_writer_builds_catalog_owned_event_shape",
            "test_writer_rejects_non_allowlisted_or_sensitive_snapshots",
            "test_writer_rejects_nested_email_and_network_values",
            "test_non_success_event_cannot_claim_after_state",
            "test_successful_event_requires_caller_owned_transaction",
            "test_savepoint_event_requires_finished_nested_rollback",
            "test_string_success_cannot_use_after_rollback_writer",
        ),
        "database tests": (
            "pytestmark = pytest.mark.postgresql",
            "test_successful_business_mutation_and_audit_commit_together",
            "test_unsafe_required_audit_rolls_back_business_mutation",
            "test_non_success_is_written_only_after_business_rollback",
            "test_required_denial_commits_after_nested_savepoint_rollback",
            "test_business_audit_rows_are_append_only",
            "test_database_rejects_invalid_raw_business_audit_events",
            "TRUNCATE TABLE business_audit_events",
        ),
        "database fixtures": (
            "pytestmark = pytest.mark.postgresql",
            "DISABLE TRIGGER",
            "trg_business_audit_no_truncate",
            "TRUNCATE TABLE business_audit_events",
        ),
        "test configuration": (
            "[tool.pytest.ini_options]",
            '"postgresql: requires the PostgreSQL and Redis services',
        ),
    }
    text = {name: path.read_text(encoding="utf-8")
            for name, path in paths.items()}
    for name, markers in required_markers.items():
        for marker in markers:
            if marker not in text[name]:
                relative = paths[name].relative_to(REPO_ROOT)
                fail(
                    errors,
                    f"{relative} is missing business-audit marker: {marker!r}",
                )

    removed_delivery_markers = (
        "## Optional Delivery Outbox",
        "build_business_outbox_rows(",
        "lease_token",
        "lease_expires_at",
        "lost the lease",
    )
    for name in (
        "entrypoint",
        "policy reference",
        "postgresql reference",
        "operations reference",
    ):
        for marker in removed_delivery_markers:
            if marker in text[name]:
                relative = paths[name].relative_to(REPO_ROOT)
                fail(
                    errors,
                    f"{relative} reintroduces the removed business-audit "
                    f"delivery subsystem: {marker!r}",
                )

    for name in (
        "implementation",
        "contract",
        "model",
        "migration",
        "alembic environment",
    ):
        if "business_audit_delivery_outbox" in text[name]:
            relative = paths[name].relative_to(REPO_ROOT)
            fail(
                errors,
                f"{relative} implements the removed business-audit delivery table",
            )

    if (
        "Never put unrelated business activity into `operation_audit_events`"
        not in text["policy reference"]
    ):
        fail(errors, "business and default operation audit catalogs must remain separate")

    # 可选模型保留为 Skill 资源，但默认注册会让用户误以为必须创建第三张审计表。
    registry_tree = ast.parse(text["model registry"])
    if any(isinstance(node, ast.ImportFrom) and node.module == "app.models.postgres.business_audit"
           for node in registry_tree.body):
        fail(errors, "default model registry must not import optional business audit")
    exporter = SKILL_ROOT / "scripts" / "create_project.py"
    exporter_tree = _parse_python(errors, exporter, label="project exporter")
    optional_files = _module_literals(exporter_tree).get(
        "OPTIONAL_RUNTIME_FILES") if exporter_tree else None
    # 集合由 frozenset 构造，直接读取其语法参数而不执行导出器或导入应用。
    if exporter_tree is not None:
        optional_node = next((node.value for node in exporter_tree.body
                              if isinstance(node, ast.Assign)
                              and any(isinstance(target, ast.Name) and target.id == "OPTIONAL_RUNTIME_FILES"
                                      for target in node.targets)), None)
        if isinstance(optional_node, ast.Call) and optional_node.args:
            optional_files = ast.literal_eval(optional_node.args[0])
    expected_optional = {
        "app/core/business_audit.py", "app/models/postgres/business_audit.py",
        "app/services/business_audit_service.py",
    }
    if not isinstance(optional_files, (set, frozenset)) or not expected_optional.issubset(optional_files):
        fail(errors, "project exporter must explicitly omit all optional business audit resources")

    outcome_values = ("succeeded", "failed", "denied")
    for name in ("policy reference", "contract", "migration"):
        for outcome in outcome_values:
            if outcome not in text[name]:
                relative = paths[name].relative_to(REPO_ROOT)
                fail(
                    errors, f"{relative} is missing business-audit outcome: {outcome}")


def validate_country_catalog(errors: list[str]) -> None:
    paths = {
        "entrypoint": SKILL_ROOT / "SKILL.md",
        "contract": SKILL_ROOT / "references" / "country-catalog.md",
        "implementation": SKILL_ROOT / "references" / "country-catalog-postgresql.md",
        "validator": SKILL_ROOT / "scripts" / "validate_country_csv.py",
        "validator tests": SKILL_ROOT / "scripts" / "test_validate_country_csv.py",
        "readme": REPO_ROOT / "README.md",
        "Chinese readme": REPO_ROOT / "README.zh-CN.md",
        "changelog": REPO_ROOT / "CHANGELOG.md",
        "Chinese changelog": REPO_ROOT / "CHANGELOG.zh-CN.md",
        "release checklist": REPO_ROOT / "RELEASE_CHECKLIST.md",
        "Chinese release checklist": REPO_ROOT / "RELEASE_CHECKLIST.zh-CN.md",
        "CI": REPO_ROOT / ".github" / "workflows" / "ci.yml",
    }
    if any(not path.is_file() for path in paths.values()):
        return

    text = {name: path.read_text(encoding="utf-8")
            for name, path in paths.items()}
    require_semantics(
        errors,
        path=paths["entrypoint"],
        checks=(
            (
                "country policy and PostgreSQL implementation are routed only on explicit request",
                (
                    r"Explicitly requested country/region catalog.*references/country-catalog\.md.*"
                    r"references/country-catalog-postgresql\.md",
                ),
            ),
        ),
    )
    required_markers = {
        "contract": (
            "This module is optional",
            "country_code,calling_code,name_zh,name_en,flag_url",
            "calling_code` is a string",
            "It is not unique.",
            "Every ordinary runtime removal sets `is_active=false` and `deleted_at`",
            "Never reactivate a disabled row, restore a deleted row",
            "Do not put a source data file into a public Skill",
            "python -B scripts/validate_country_csv.py",
            "Formal import with any non-empty `flag_url` requires",
            "approved ASCII DNS hostnames",
            "`--structure-only` is never import approval",
            "`membership_checked=false`",
        ),
        "implementation": (
            '__tablename__ = "countries"',
            "pg_advisory_xact_lock",
            "on_conflict_do_update",
            "Country.deleted_at.is_not(None)",
            "Country.version + 1",
            "The import intentionally does not update `is_active`",
            "Do not mount a write or import",
        ),
        "validator": (
            "EXPECTED_HEADER",
            "MAX_CSV_BYTES",
            "MAX_DATA_ROWS",
            "MAX_EXPECTED_CODES_BYTES",
            "_read_bounded_bytes",
            "handle.read(limit + 1)",
            'raw_source.decode("utf-8-sig", errors="strict")',
            "expected_codes",
            "structure_only",
            "_normalize_dns_hostname",
            "allowed_flag_hosts",
            "non-empty flag URLs require an approved allowed_flag_hosts set",
            "structure-only result is not import approval",
            "membership_checked=expected_codes is not None and not structure_only",
            "CSV must contain at least one data row",
            "shared_calling_codes",
            "calling_code must not be unique",
            'payload["valid"]',
            "parsed.username is not None",
            "parsed.password is not None",
            "or parsed.fragment",
        ),
        "validator tests": (
            "test_valid_csv_accepts_shared_calling_codes_and_utf8_bom",
            "test_header_only_csv_is_rejected",
            "test_expected_code_set_is_required_unless_structure_only_is_explicit",
            "test_file_size_limit_is_enforced_before_csv_parsing",
            "test_data_row_limit_is_enforced",
            "test_expected_code_manifest_size_limit_is_enforced",
            "test_expected_code_manifest_detects_missing_and_unexpected_codes",
            "test_invalid_ascii_dns_hostnames_are_rejected",
            "test_flag_host_allowlist_matching_is_case_insensitive",
            "test_control_characters_are_rejected",
            "test_unsafe_flag_url_is_rejected",
            "test_import_ready_flag_urls_require_an_approved_host",
            "test_cli_json_includes_valid_and_membership_status",
            "test_cli_validation_failure_returns_one_and_json_report",
            "test_cli_requires_an_authoritative_or_structure_only_mode",
        ),
        "readme": (
            "country catalog guide",
            "The country dataset is not bundled.",
        ),
        "Chinese readme": (
            "国家目录",
            "仓库不捆绑第三方国家数据集",
        ),
        "changelog": (
            "Release validation rejects bundled CSV/TSV country",
            "ASCII DNS",
            "`membership_checked=false`",
        ),
        "Chinese changelog": (
            "发布校验会",
            "CSV/TSV 国家数据",
            "ASCII DNS",
            "`membership_checked=false`",
        ),
        "release checklist": (
            "country catalog remains opt-in",
            "source CSV/TSV or flag asset",
            "ASCII DNS",
            "`membership_checked=false`",
        ),
        "Chinese release checklist": (
            "国家目录保持按需启用",
            "CSV/TSV 或旗帜资产",
            "ASCII DNS",
            "`membership_checked=false`",
        ),
        "CI": (
            "python -B skills/fastapi-templates-xtn/scripts/test_validate_country_csv.py",
            "python -B scripts/validate_release.py",
            'python -B -m pytest -p no:cacheprovider -m "not postgresql"',
            "python -B -m pytest -p no:cacheprovider -m postgresql",
            'test "$(alembic heads)" = "0004_password_auth (head)"',
        ),
    }
    for name, markers in required_markers.items():
        for marker in markers:
            if marker not in text[name]:
                relative = paths[name].relative_to(REPO_ROOT)
                fail(
                    errors,
                    f"{relative} is missing country-catalog marker: {marker!r}",
                )

    python_command_re = re.compile(r"^\s*(?:run:\s*)?python\s+(?!-B(?:\s|$))")
    for name in (
        "contract",
        "implementation",
        "readme",
        "Chinese readme",
        "release checklist",
        "Chinese release checklist",
        "CI",
    ):
        if any(python_command_re.match(line) for line in text[name].splitlines()):
            relative = paths[name].relative_to(REPO_ROOT)
            fail(
                errors,
                f"{relative} contains a Python command that does not use python -B",
            )

    if any(
        re.match(r"^\s*run:\s*pytest(?:\s|$)", line) for line in text["CI"].splitlines()
    ):
        fail(errors, "CI contains a bare pytest invocation")


def validate_ci_and_current_documentation(errors: list[str]) -> None:
    ci_path = REPO_ROOT / ".github" / "workflows" / "ci.yml"
    pyproject_path = ASSET_ROOT / "pyproject.toml"
    limiter_path = ASSET_ROOT / "app" / "dependencies" / "rate_limit.py"
    limiter_tests_path = ASSET_ROOT / "tests" / "test_rate_limit_dependencies.py"
    openai_path = SKILL_ROOT / "agents" / "openai.yaml"
    if any(
        not path.is_file()
        for path in (
            ci_path,
            pyproject_path,
            limiter_path,
            limiter_tests_path,
            openai_path,
        )
    ):
        return

    ci = ci_path.read_text(encoding="utf-8")
    action_pins = {
        "actions/checkout": "11d5960a326750d5838078e36cf38b85af677262",
        "actions/setup-python": "a26af69be951a213d495a4c3e4e4022e16d87065",
    }
    for action, commit in action_pins.items():
        references = re.findall(rf"uses:\s*{re.escape(action)}@([^\s#]+)", ci)
        if not references or any(reference != commit for reference in references):
            fail(
                errors, f"CI must pin every {action} use to full commit {commit}")

    for command in (
        'python -B -m pip install --upgrade "pip==26.2.1" "setuptools==84.0.0"',
        'python -B -m pip install -c constraints-ci-py312.txt -e ".[test]"',
        "python -B ../../../../scripts/validate_asset_wheel.py . ../../VERSION",
        "python -B -m autopep8 --diff --exit-code --recursive .",
        "ruff check --no-cache .",
        'python -B -m mypy --cache-dir "$RUNNER_TEMP/fastapi-templates-xtn-mypy" app tests',
        "pip-audit --local --skip-editable --progress-spinner off",
    ):
        if command not in ci:
            fail(errors, f"CI is missing required quality command: {command}")

    pyproject = pyproject_path.read_text(encoding="utf-8")
    if (
        'license-files = ["LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"]'
        not in pyproject
    ):
        fail(errors, "asset wheel metadata must include every legal notice file")
    if '"pip-audit>=2.7,<3"' not in pyproject:
        fail(errors, "asset test dependencies must include bounded pip-audit")
    if '"pytest>=9.0.3,<10"' not in pyproject:
        fail(
            errors, "asset test dependencies must require the fixed pytest release line"
        )
    if '"pytest-asyncio>=1.4,<2"' not in pyproject:
        fail(
            errors,
            "asset test dependencies must use a pytest-asyncio line compatible with pytest 9",
        )

    limiter = limiter_path.read_text(encoding="utf-8")
    limiter_tests = limiter_tests_path.read_text(encoding="utf-8")
    for retired_marker in (
        "AUTHENTICATED_RATE_LIMIT_RULES",
        "AUTHENTICATED_RATE_LIMIT_EXEMPT_OPERATIONS",
        "rate_limit_enabled",
        "RATE_LIMIT_ENABLED",
    ):
        if retired_marker in limiter:
            fail(
                errors,
                "route-local rate limiting must not retain hidden registry or disable "
                f"marker {retired_marker!r}",
            )
    for marker in (
        'getattr(request.scope.get("route"), "name", None)',
        'key_parts=[str(login_info.user_id)]',
        "protected operation needs a stable route name",
    ):
        if marker not in limiter:
            fail(errors, f"route-local rate limiting is missing {marker!r}")
    for marker in (
        "test_each_operation_gets_its_own_key_and_class_quota",
        "test_allowed_user_check_hides_user_id_in_redis_key",
        "test_missing_route_name_fails_closed",
        "test_denied_user_check_raises_rate_limit_exceeded",
        "test_authenticated_captcha_charges_its_exact_window_once",
    ):
        if marker not in limiter_tests:
            fail(
                errors, f"route-local rate-limit tests are missing {marker!r}")

    openai = openai_path.read_text(encoding="utf-8")
    for marker in (
        "all five required graphical CAPTCHA flows",
        "do not implement anonymous password recovery",
        "email/SMS verification or MFA only when explicitly requested",
    ):
        if marker not in openai:
            fail(
                errors, f"agents/openai.yaml is missing current behavior: {marker!r}")
    for stale in ("optional verification", "authentication and recovery"):
        if stale in openai.casefold():
            fail(
                errors, f"agents/openai.yaml retains stale wording: {stale!r}")

    active_references = (
        SKILL_ROOT / "references" / "jwt-session-security.md",
        SKILL_ROOT / "references" / "jwt-session-implementation.md",
        SKILL_ROOT / "references" / "postgresql-rbac-implementation.md",
    )
    stale_patterns = (
        re.compile(r"\bUnreleased\b", re.IGNORECASE),
        re.compile(
            r"(?:login|token issuance).{0,80}(?:not wired|not implemented)",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:尚未|仍未).{0,30}(?:接入|实现).{0,30}(?:登录|Token)",
            re.IGNORECASE,
        ),
    )
    for path in active_references:
        content = path.read_text(encoding="utf-8")
        for pattern in stale_patterns:
            if pattern.search(content):
                fail(
                    errors,
                    f"{path.relative_to(REPO_ROOT)} retains stale release-state wording",
                )

    readme_requirements = {
        "README.md": (
            "references/architecture-overview.zh-CN.md",
            "Python 3.12",
            "PostgreSQL 17",
            "Redis 7",
            "python -B -m autopep8 --diff --exit-code --recursive",
            "pip-audit --local --skip-editable --progress-spinner off",
            "constraints-ci-py312.txt",
            "INSTALL.md",
        ),
        "README.zh-CN.md": (
            "references/architecture-overview.zh-CN.md",
            "Python 3.12",
            "PostgreSQL 17",
            "Redis 7",
            "python -B -m autopep8 --diff --exit-code --recursive",
            "pip-audit --local --skip-editable --progress-spinner off",
            "constraints-ci-py312.txt",
            "INSTALL.zh-CN.md",
        ),
    }
    for readme_name, markers in readme_requirements.items():
        readme_path = REPO_ROOT / readme_name
        if not readme_path.is_file():
            continue
        readme = readme_path.read_text(encoding="utf-8")
        for marker in markers:
            if marker not in readme:
                fail(
                    errors, f"{readme_name} is missing current documentation: {marker}"
                )

    security_requirements = {
        "SECURITY.md": (
            "pip-audit",
            "--ignore-vuln",
            "vulnerability identifier",
            "impact",
            "reason",
            "responsible owner",
            "review date",
        ),
        "SECURITY.zh-CN.md": (
            "pip-audit",
            "--ignore-vuln",
            "漏洞编号",
            "影响",
            "原因",
            "负责人",
            "复查日期",
        ),
    }
    for security_name, markers in security_requirements.items():
        security_path = REPO_ROOT / security_name
        if not security_path.is_file():
            continue
        security = security_path.read_text(encoding="utf-8")
        for marker in markers:
            if marker not in security:
                fail(
                    errors,
                    f"{security_name} is missing audit-exception field: {marker}",
                )

    old_design_path = REPO_ROOT / "DESIGN_REVIEW.zh-CN.md"
    archived_design_path = (
        REPO_ROOT / "docs" / "history" / "v0.4.0" / "DESIGN_REVIEW.zh-CN.md"
    )
    if old_design_path.exists():
        fail(errors, "the v0.4.0 design review must not remain at the repository root")
    if archived_design_path.is_file():
        archived_design = archived_design_path.read_text(encoding="utf-8")
        if not re.search(
            r"^# .*v0\.4\.0.*不代表当前实现", archived_design, re.MULTILINE
        ):
            fail(errors, "the archived v0.4.0 design review lacks a historical warning")


def _validate_runtime_entrypoint(tree: ast.Module, errors: list[str]) -> None:
    """
        检查启动先校验路由，并显式装配独立异常、中间件和业务模块。

    :param tree: 应用入口语法树，不执行其中的启动、查询或资源创建代码。
    :param errors: 本次校验发现的具体边界问题列表。
    :return: 无返回值；发现的问题追加到 errors。
    """
    lifespan = _function_node(tree.body, "lifespan")
    body = list(lifespan.body) if lifespan is not None else []
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        body = body[1:]
    if not (
        body and isinstance(body[0], ast.Expr) and isinstance(
            body[0].value, ast.Call)
        and ast.unparse(body[0].value.func) == "validate_v1_api_routes"
        and len(body[0].value.args) == 1 and ast.unparse(body[0].value.args[0]) == "app"
    ):
        fail(errors, "lifespan must validate_v1_api_routes(app) before creating any resources")

    # 既检查实现来自正确模块，也检查入口确实执行装配，避免移动代码后漏接到应用。
    expected_imports = {
        "register_exception_handlers": ("app.core.exception_handlers", "register_exception_handlers"),
        "RequestLoggingMiddleware": (
            "app.core.middleware", "RequestLoggingMiddleware"
        ),
        "RequestBodyLimitMiddleware": (
            "app.core.middleware", "RequestBodyLimitMiddleware"
        ),
        "SecurityHeadersMiddleware": (
            "app.core.middleware", "SecurityHeadersMiddleware"
        ),
        "v1_router": ("app.api.v1.router", "router"),
        "validate_v1_api_routes": ("app.api.v1.route_validation", "validate_v1_api_routes"),
        "configure_logging": ("app.core.logging.output", "configure_logging"),
    }
    actual_imports = {
        alias.asname or alias.name: (node.module, alias.name)
        for node in tree.body if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }
    for name, source in expected_imports.items():
        if actual_imports.get(name) != source:
            fail(
                errors, f"application entrypoint must import {name} from {source[0]}")

    app_factory = next(
        (
            node.value
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "app"
                for target in node.targets
            )
            and isinstance(node.value, ast.Call)
            and ast.unparse(node.value.func) == "FastAPI"
        ),
        None,
    )
    disabled_routes = {"docs_url", "redoc_url", "openapi_url"}
    disabled_route_values = (
        {
            keyword.arg: keyword.value
            for keyword in app_factory.keywords
            if keyword.arg in disabled_routes
        }
        if app_factory is not None
        else {}
    )
    if any(
        not isinstance(disabled_route_values.get(name), ast.Constant)
        or disabled_route_values[name].value is not None
        for name in disabled_routes
    ):
        fail(
            errors,
            "application FastAPI constructor must disable docs_url, redoc_url and "
            "openapi_url by default",
        )

    assembly_calls = {
        ast.unparse(node.value) for node in tree.body
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
    }
    for call in (
        "register_exception_handlers(app)",
        "app.add_middleware(RequestBodyLimitMiddleware, max_body_bytes=settings.request_body_max_bytes)",
        "app.add_middleware(SecurityHeadersMiddleware)",
        "app.add_middleware(RequestLoggingMiddleware, "
        "log_hmac_key=settings.log_hmac_key.get_secret_value().encode('utf-8'))",
        "app.include_router(v1_router)",
    ):
        if call not in assembly_calls:
            fail(errors, f"application entrypoint must assemble {call}")
    _validate_no_runtime_schema_writes(tree, errors)


def _validate_no_runtime_schema_writes(tree: ast.Module, errors: list[str]) -> None:
    """
        对拆分后的运行模块保持相同的禁止自动建表与迁移边界。

    :param tree: 入口或请求处理模块的源码语法树。
    :param errors: 接收未经允许的运行时建表或迁移代码问题。
    :return: 无返回值；发现禁止的调用或导入时追加错误。
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and ast.unparse(node.func).rsplit(".", 1)[-1] in {
            "create_all", "drop_all", "run_migrations", "upgrade", "downgrade",
        }:
            fail(
                errors, "application runtime must not create tables or execute migrations")
        if isinstance(node, ast.ImportFrom) and (node.module or "").split(".", 1)[0] == "alembic":
            fail(
                errors, "application runtime must not import the user-owned migration tool")


def _validate_exception_handler_registration(tree: ast.Module, errors: list[str]) -> None:
    """
        核对独立异常模块仍将所有已支持异常绑定到原有处理函数。

    :param tree: 异常处理模块的源码语法树。
    :param errors: 接收遗漏或错误绑定的异常注册问题。
    :return: 无返回值；缺失任一种异常处理关系时追加错误。
    """
    registration = _function_node(tree.body, "register_exception_handlers")
    registrations = {
        (ast.unparse(node.func.args[0]), ast.unparse(node.args[0]))
        for node in ast.walk(registration) if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Call) and ast.unparse(node.func.func) == "app.exception_handler"
        and len(node.func.args) == 1 and len(node.args) == 1
    } if registration is not None else set()
    expected = {
        "RequestValidationError": "handle_request_validation_error",
        "AppError": "handle_access_error",
        "RateLimitExceeded": "handle_rate_limit_exceeded",
        "RateLimitUnavailable": "handle_rate_limit_unavailable",
        "PasswordBusyError": "handle_password_busy",
        "StarletteHTTPException": "handle_http_error",
        "Exception": "handle_unexpected_error",
        "SQLAlchemyError": "handle_database_unavailable",
        "DatabaseUnavailableError": "handle_database_unavailable",
    }
    for exception, handler in expected.items():
        if (exception, handler) not in registrations or _function_node(tree.body, handler) is None:
            fail(
                errors, f"exception registration must bind {exception} to {handler}")
    _validate_no_runtime_schema_writes(tree, errors)


def validate_project_delivery_boundaries(errors: list[str]) -> None:
    """
        核对精选交付和启动合同的源码及真实测试入口，不生成项目或操作数据库。

    :param errors: 本次校验发现的缺失合同或测试覆盖问题列表。
    :return: 无返回值；发现的问题追加到 errors。
    """
    main_tree = _parse_python(
        errors, ASSET_ROOT / "app/main.py", label="runtime entrypoint")
    if main_tree is not None:
        _validate_runtime_entrypoint(main_tree, errors)
    handlers_tree = _parse_python(
        errors, ASSET_ROOT / "app/core/exception_handlers.py", label="exception handlers")
    if handlers_tree is not None:
        _validate_exception_handler_registration(handlers_tree, errors)
    middleware_tree = _parse_python(
        errors, ASSET_ROOT / "app/core/middleware/request_logging.py", label="request middleware"
    )
    if middleware_tree is not None:
        _validate_no_runtime_schema_writes(middleware_tree, errors)
    for relative, label in (
        ("app/core/middleware/request_body_limit.py", "request-body middleware"),
        ("app/core/middleware/security_headers.py", "security-header middleware"),
    ):
        middleware_tree = _parse_python(
            errors, ASSET_ROOT / relative, label=label)
        if middleware_tree is not None:
            _validate_no_runtime_schema_writes(middleware_tree, errors)

    route_validation_path = ASSET_ROOT / "app/core/route_validation.py"
    route_validation_tests = ASSET_ROOT / "tests/test_route_validation.py"
    generator_tests = REPO_ROOT / "scripts/test_create_project.py"
    for path, names in (
        (route_validation_path, (
            "iter_route_contexts",
            "_uses_dependency",
            "route.name",
            "duplicate route name",
            "authenticated_dependencies",
            "special_routes",
        )),
        (ASSET_ROOT / "app/api/v1/route_validation.py", (
            "_PUBLIC_ROUTES",
            "check_token",
            "get_current_user",
            "require_permission",
            "get_captcha_user",
            "validate_v1_api_routes",
        )),
        (ASSET_ROOT / "app/api/v1/router.py", (
            "router = APIRouter(prefix=\"/api/v1\")",
            "router.include_router(auth.router)",
            "router.include_router(users.router)",
            "router.include_router(roles.router)",
            "router.include_router(permissions.router)",
        )),
        (route_validation_tests, (
            "test_new_nested_business_route_needs_no_extra_registry",
            "test_duplicate_route_names_are_rejected",
            "test_authenticated_captcha_requires_scene_authorization_dependency",
            "test_real_lifespan_rejects_missing_auth_before_external_resources",
        )),
        (generator_tests, (
            "test_export_is_minimal_without_auxiliary_manifests",
            "test_existing_file_and_nonempty_directory_are_not_overwritten",
            "test_complete_models_and_catalog_import_without_database_configuration",
            "test_openapi_import_and_project_identity_need_no_running_services",
            "test_delivered_small_tests_run_without_database_or_redis",
            "sys.addaudithook(reject_network)",
            "sqlalchemy.MetaData.create_all = reject_ddl",
        )),
    ):
        if not path.is_file():
            continue
        content = path.read_text(encoding="utf-8")
        for name in names:
            if name not in content:
                fail(
                    errors, f"{path.relative_to(REPO_ROOT)} must retain starter boundary coverage: {name}")


def validate_distribution_tooling(errors: list[str]) -> None:
    paths = {
        "constraints": ASSET_ROOT / "constraints-ci-py312.txt",
        "pyproject": ASSET_ROOT / "pyproject.toml",
        "CI": REPO_ROOT / ".github" / "workflows" / "ci.yml",
        "updater": REPO_ROOT / "scripts" / "update_installed_skill.py",
        "updater tests": REPO_ROOT / "scripts" / "test_update_installed_skill.py",
        "wheel validator": REPO_ROOT / "scripts" / "validate_asset_wheel.py",
        "CI environment validator": REPO_ROOT
        / "scripts"
        / "validate_ci_environment.py",
        "install guide": REPO_ROOT / "INSTALL.md",
        "Chinese install guide": REPO_ROOT / "INSTALL.zh-CN.md",
    }
    if any(not path.is_file() for path in paths.values()):
        return
    text = {name: path.read_text(encoding="utf-8")
            for name, path in paths.items()}

    constraint_lines = [
        line.strip()
        for line in text["constraints"].splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    invalid_constraints = [
        line
        for line in constraint_lines
        if not re.fullmatch(r"[A-Za-z0-9_.-]+==[A-Za-z0-9_.+!-]+", line)
    ]
    if invalid_constraints:
        fail(
            errors,
            "CI constraints must use exact package==version pins: "
            f"{invalid_constraints[:3]}",
        )
    normalized_names = {
        re.split(r"==", line, maxsplit=1)[0].lower().replace("_", "-")
        for line in constraint_lines
        if "==" in line
    }
    for required in (
        "fastapi",
        "redis",
        "sqlalchemy",
        "pytest",
        "pytest-asyncio",
        "pip-audit",
        "ruff",
        "pip",
        "setuptools",
        "uvicorn",
        "uvloop",
    ):
        if required not in normalized_names:
            fail(
                errors, f"CI constraints are missing exact pin for {required}")

    pyproject = tomllib.loads(text["pyproject"])
    for dependency in list(pyproject.get("project", {}).get("dependencies", [])) + list(
        pyproject.get("project", {}).get(
            "optional-dependencies", {}).get("test", [])
    ):
        if ">=" not in dependency or "<" not in dependency:
            fail(
                errors,
                "adaptable project dependencies must retain bounded ranges: "
                f"{dependency!r}",
            )

    ci_markers = (
        'tags: ["v*"]',
        "PIP_CONSTRAINT: constraints-ci-py312.txt",
        "PIP_BUILD_CONSTRAINT: constraints-ci-py312.txt",
        'python -B -m pip install --upgrade "pip==26.2.1" "setuptools==84.0.0"',
        'python -B -m pip install -c constraints-ci-py312.txt -e ".[test]"',
        "python -B -m pip check",
        "python -B ../../../../scripts/validate_ci_environment.py",
        "python -B scripts/test_update_installed_skill.py",
        "python -B scripts/test_validate_ci_environment.py",
        "python -B ../../../../scripts/validate_asset_wheel.py . ../../VERSION",
        "python -B scripts/validate_release.py --release-ready",
    )
    for marker in ci_markers:
        if marker not in text["CI"]:
            fail(
                errors, f"CI is missing reproducible-release marker: {marker!r}")

    updater_markers = (
        'target_parent.parent / "skill-backups"',
        "--backup-dir",
        "--dry-run",
        "shutil.copytree(",
        "_manifest(staging) != source_manifest",
        "backup.rename(target)",
        "IGNORED_DIRECTORY_NAMES",
        'path.name == ".env"',
    )
    for marker in updater_markers:
        if marker not in text["updater"]:
            fail(errors, f"safe Skill updater is missing behavior: {marker!r}")
    for test_name in (
        "test_fresh_install_uses_staged_exact_copy",
        "test_update_retains_complete_backup",
        "test_dry_run_changes_nothing",
        "test_generated_artifacts_are_not_installed",
        "test_failed_replacement_restores_previous_installation",
        "test_rejects_overlapping_source_and_target",
    ):
        if test_name not in text["updater tests"]:
            fail(errors, f"Skill updater tests are missing {test_name}")

    for marker in (
        "/licenses/LICENSE",
        "/licenses/NOTICE",
        "/licenses/THIRD_PARTY_NOTICES.md",
        "/app/assets/locales/en.json",
        "/app/assets/locales/zh-CN.json",
    ):
        if marker not in text["wheel validator"]:
            fail(
                errors, f"wheel validator is missing artifact check: {marker}")

    closure_validator_markers = (
        'sys.platform != "linux"',
        "sys.version_info[:2] != (3, 12)",
        'project.get("dependencies", [])',
        'get("optional-dependencies", {}).get("test", [])',
        "distribution.requires or ()",
        "_index_installed_distributions(importlib.metadata.distributions())",
        "_require_unique_distribution(installed, name)",
        "expected exactly one",
        "requirement.marker.evaluate",
        "requirement.extras",
        '"uvicorn" in visited and "uvloop" not in visited',
    )
    for marker in closure_validator_markers:
        if marker not in text["CI environment validator"]:
            fail(
                errors,
                f"CI dependency-closure validator is missing behavior: {marker!r}",
            )

    install_markers = {
        "install guide": (
            "intentionally refuses to overwrite",
            "--dry-run",
            "skill-backups",
            "VERSION",
        ),
        "Chinese install guide": (
            "$skill-installer` 会主动拒绝覆盖",
            "--dry-run",
            "skill-backups",
            "VERSION",
        ),
    }
    for name, markers in install_markers.items():
        for marker in markers:
            if marker not in text[name]:
                fail(
                    errors, f"{paths[name].name} is missing update guidance: {marker!r}"
                )


def validate_tree_hygiene(errors: list[str]) -> None:
    for path in REPO_ROOT.rglob("*"):
        if ".git" in path.parts:
            continue
        forbidden_directory = next(
            (
                part
                for part in path.parts
                if part in FORBIDDEN_DIRECTORY_NAMES
                or part.endswith(FORBIDDEN_DIRECTORY_SUFFIXES)
            ),
            None,
        )
        if forbidden_directory is not None:
            if path.name == forbidden_directory:
                fail(
                    errors,
                    f"release package contains generated directory: "
                    f"{path.relative_to(REPO_ROOT)}",
                )
            continue
        if path.is_symlink():
            fail(
                errors,
                f"release package contains a symlink: {path.relative_to(REPO_ROOT)}",
            )
        if not path.is_file():
            continue
        try:
            skill_relative = path.relative_to(SKILL_ROOT)
        except ValueError:
            skill_relative = None

        suffix = path.suffix.lower()
        top_level = ""
        path_has_country_or_flag_hint = False
        if skill_relative is not None:
            top_level = skill_relative.parts[0].casefold()
            path_has_country_or_flag_hint = any(
                COUNTRY_OR_FLAG_PATH_RE.search(part) is not None
                for part in skill_relative.parts
            )

        if (
            skill_relative is not None
            and suffix in FORBIDDEN_SKILL_TABULAR_SUFFIXES
            and (top_level in {"data", "datasets"} or path_has_country_or_flag_hint)
        ):
            fail(
                errors,
                "distributable Skill contains a potential bundled country CSV/TSV "
                f"dataset: {path.relative_to(REPO_ROOT)}",
            )

        if skill_relative is not None and suffix in COUNTRY_OR_FLAG_MEDIA_SUFFIXES:
            if top_level in {"data", "datasets", "references", "scripts"} or (
                path_has_country_or_flag_hint
            ):
                fail(
                    errors,
                    "distributable Skill contains a potential bundled country/flag "
                    f"media asset: {path.relative_to(REPO_ROOT)}",
                )
        if (
            path.name in FORBIDDEN_FILE_NAMES
            or path.suffix.lower() in FORBIDDEN_FILE_SUFFIXES
        ):
            fail(
                errors,
                f"release package contains generated data: {path.relative_to(REPO_ROOT)}",
            )
        if path.name == ".env" or (
            path.name.startswith(
                ".env.") and not path.name.endswith(".example")
        ):
            fail(
                errors,
                f"release package contains a real environment file: {path.relative_to(REPO_ROOT)}",
            )

        if path.suffix.lower() in TEXT_SUFFIXES:
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                fail(
                    errors, f"expected UTF-8 text: {path.relative_to(REPO_ROOT)}")
                continue
            if LOCAL_HOME_PATH_RE.search(text):
                fail(
                    errors, f"local home path leaked in {path.relative_to(REPO_ROOT)}")
            if SECRET_MATERIAL_RE.search(text):
                fail(
                    errors, f"secret material detected in {path.relative_to(REPO_ROOT)}"
                )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--release-ready",
        action="store_true",
        help="require dated changelogs and completed READY pre-tag evidence",
    )
    args = parser.parse_args(argv)
    errors: list[str] = []
    validate_required_files(errors)
    validate_frontmatter(errors)
    validate_identity_and_row_lifecycle(errors)
    validate_links(errors)
    validate_bilingual_docs(errors)
    validate_legal_mirrors(errors)
    validate_release_metadata(errors, release_ready=args.release_ready)
    validate_single_project_scope(errors)
    validate_access_token_baseline(errors)
    validate_local_password_authentication(errors)
    validate_rate_limiting_and_verification(errors)
    validate_simplified_authentication_and_administration(errors)
    validate_user_role_limit(errors)
    validate_administrative_read_visibility(errors)
    validate_super_admin_bootstrap(errors)
    validate_rbac_database_naming(errors)
    validate_api_internationalization(errors)
    validate_api_response_contract(errors)
    validate_logging_and_audit(errors)
    validate_business_audit(errors)
    validate_country_catalog(errors)
    validate_ci_and_current_documentation(errors)
    validate_project_delivery_boundaries(errors)
    validate_distribution_tooling(errors)
    validate_tree_hygiene(errors)

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(
            f"Release validation failed with {len(errors)} error(s).", file=sys.stderr
        )
        return 1

    file_count = sum(
        path.is_file() and ".git" not in path.parts for path in REPO_ROOT.rglob("*")
    )
    readiness = "release-ready" if args.release_ready else "development"
    print(
        f"Release package is valid for {readiness} validation: "
        f"{file_count} files checked."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
