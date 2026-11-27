#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 说明:
#    从使用者视角验证精选项目交付，只使用系统临时目录和离线 Python 子进程。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/27    XTN       V1.000        补充文件职责记录并验证限流无关闭配置
# 2026/09/29    XTN       V1.001        验证真实生成项目不包含健康路由或探针配置
# 2026/09/29    XTN       V1.002        实际导入独立权限和角色配置并检查权限描述的双语映射
# 2026/09/29    XTN       V1.003        验证业务路由校验及拆分后的 core 模块随项目交付
# 2026/09/29    XTN       V1.004        从独立的 v1 路由校验模块检查生成项目
# 2026/09/30    XTN       V1.005        验证生成项目的语言与参数错误模块可直接导入
# 2026/09/30    XTN       V1.006        验证 PostgreSQL 连接代码只交付一个入口文件
# 2026/09/30    XTN       V1.007        验证生成项目不再输出密码模式配置
# 2026/10/02    XTN       V1.008        验证数据库故障文件及维护命令专用逻辑的导出边界
# 2026/10/02    XTN       V1.009        登录凭据异常随统一业务错误模块交付
# 2026/10/02    XTN       V1.010        生成配置示例不得包含程序不读取的过时参数
# 2026/10/02    XTN       V1.011        确认新项目不再交付独立 PostgreSQL 错误文件
# 2026/10/02    XTN       V1.012        校验生成函数的参数说明与声明顺序一致
# 2026/10/08    XTN       V1.013        验证新文件只记录当天新建且无重复的模块说明
# 2026/10/09    XTN       V1.014        实际生成项目检查模型归属、共用校验及请求冻结配置
# 2026/10/09    XTN       V1.015        实际生成项目检查审计动作目录及原有字符串值
# 2026/10/09    XTN       V1.016        实际生成项目检查数据库约束名提取与用户名冲突判断
# 2026/10/09    XTN       V1.017        实际生成项目检查默认成功码与创建显式覆盖
# 2026/10/09    XTN       V1.018        注册字段变量统一命名并验证成功消息新成员保留双语协议值
# 2026/10/09    XTN       V1.019        生成项目会话模型检查统一使用 Response 后缀
# 2026/10/10    XTN       V1.020        检查生成项目所有接口模型的公共基类和参数规则
# 2026/10/10    XTN       V1.021        检查用户主键、接口字段及 JWT 会话统一使用 user_id
# 2026/10/10    XTN       V1.022        检查生成审计区分操作用户、目标用户、非用户来源和业务对象
# 2026/10/10    XTN       V1.023        确认生成验证码服务返回业务模型，完整响应由路由负责
# 2026/10/10    XTN       V1.024        确认所有密码请求共用 Password 及直接的 8～60 位字段约束
# 2026/10/12    XTN       V1.025        实际生成项目检查五种验证码依赖及共享限流、认证接线
# 2026/10/12    XTN       V1.026        验证码依赖不内嵌业务前置依赖，路由按顺序各执行一次
# 2026/10/12    XTN       V1.027        生成验证码依赖直接读取参数并统一用户 ID 字段
# 2026/10/13    XTN       V1.028        实际生成验证码验证保持 GETDEL 单次消费及摘要绑定
# 2026/10/13    XTN       V1.029        实际生成验证码使用 captcha 加 UUID 键并保持单次消费
# 2026/10/13    XTN       V1.030        生成配置不再包含限流命名空间，核对新限流键及摘要输入
# 2026/10/13    XTN       V1.031        生成会话键和 JTI 字段只使用用户 ID 与登录编号摘要
# 2026/10/13    XTN       V1.032        生成会话只保留登录记录和登录顺序两键
# 2026/10/13    XTN       V1.033        生成会话键保留业务用户 ID，登录字段使用 UUID.hex
# 2026/10/14    XTN       V1.034        实际生成验证码服务直接接收用途枚举并保持原摘要及单次消费
# 2026/10/14    XTN       V1.035        实际生成密码字段与双语提示共享 8～32 位长度常量
# 2026/10/14    XTN       V1.036        实际生成项目验证默认日志落盘及请求 ID 关联
# 2026/10/14    XTN       V1.037        验证生成项目日志文件大小读取环境配置并传给处理器
# 2026/10/14    XTN       V1.038        不注入运行环境标识并验证日志省略服务名、版本和环境
# 2026/10/14    XTN       V1.039        离线生成检查提供独立日志指纹密钥
# 2026/10/14    XTN       V1.040        实际文件验证重置目标、脱敏正文和新密码指纹
# 2026/10/14    XTN       V1.041        实际交付日志保留响应业务提示并统一北京时间
# 2026/10/15    XTN       V1.042        实际生成日志通过统一响应登记业务结果并自动读取路由动作
# 2026/10/15    XTN       V1.043        实际文件日志从请求提取目标，无需路由手写目标字段
# 2026/10/15    XTN       V1.044        实际生成项目移除用户权限版本并保留登录撤销和角色版本
# 2026/10/15    XTN       V1.045        实际生成的两类绑定模型统一操作人和绑定时间字段
# 2026/10/15    XTN       V1.046        实际生成的用户响应使用 bound_role_ids 并清理旧字段
# 2026/10/15    XTN       V1.047        实际生成项目复用 UserService 创建账号且无独立创建服务
# 2026/10/16    XTN       V1.048        确认生成项目的用户创建接口不接受外部用户 ID
# 2026/10/16    XTN       V1.049        验证审计自动读取关联 ID 且业务入口不再逐层传参
# 2026/10/16    XTN       V1.050        共享创建直接处理用户名冲突后移除过时分类函数检查
# 2026/10/16    XTN       V1.051        移除运行时权限版本预期，保留协调锁与历史迁移契约
# 2026/10/20    XTN       V1.052        实际生成项目收紧新密码长度后仍可提交登录及原密码改密
# 2026/10/20    XTN       V1.053        实际生成的角色列为 level，用户最高角色等级为 role_level
# 2026/10/20    XTN       V1.054        验证直写认证依赖及账号读取前的单次限流
# 2026/10/20    XTN       V1.055        实际生成验证同步本人及内部管理上下文依赖名称
# 2026/10/20    XTN       V1.056        生成项目的 Token 信息变量统一使用 token_info 名称
# 2026/10/20    XTN       V1.057        生成验证使用简化后的登录记录构建和解析入口
# 2026/10/22    XTN       V1.058        生成项目识别直接执行管理检查的权限依赖回调
# 2026/10/22    XTN       V1.059        实际生成验证权限默认普通额度及管理业务显式选择
# 2026/10/22    XTN       V1.060        实际生成确认用户权限查询归用户仓储并移除独立权限仓储
# 2026/10/22    XTN       V1.061        实际生成确认密码保存使用 update_password 方法
# 2026/10/22    XTN       V1.062        实际生成确认简化权限入口及启用、全部角色双结果无旧别名
# 2026/10/23    XTN       V1.063        实际生成确认一名或多名用户共用 users 权限入口和固定映射
# 2026/10/23    XTN       V1.064        生成接口允许当前用户信息使用固定 user_info 路径
# 2026/10/24    XTN       V1.065        实际生成项目通过 user_info 字段构建当前用户上下文
# 2026/10/24    XTN       V1.066        生成项目验证码跨用户检查使用 user_change_password 场景
# 2026/10/24    XTN       V1.067        生成用户仓储使用直观展示信息名称及 user_info 字段
# 2026/10/24    XTN       V1.068        生成用户仓储的列表和详情入口采用简短业务名称
# 2026/10/24    XTN       V1.069        生成角色仓储对齐简短查询名称及统一权限读取入口
# 2026/10/24    XTN       V1.070        生成用户管理资料使用 UserDetails 和 get_users_info
# 2026/10/26    XTN       V1.071        用户权限信息类型统一使用 UserInfo，保持原有验证行为
# 2026/10/26    XTN       V1.072        权限结果字段明确区分有效用户信息与包含停用角色的信息
# 2026/10/26    XTN       V1.073        生成验证区分本人基础权限和管理权限，并保持单次前置检查
# 2026/10/26    XTN       V1.074        实际生成确认角色列表六项筛选及未删除默认范围
# 2026/11/26    XTN       V1.075        验证修改一处用户名规则可同步请求、查询、模型和双语提示
# 2026/11/26    XTN       V1.076        生成项目验证调用 validate_user_name 校验用户名
# 2026/11/26    XTN       V1.077        验证首条横线前误放的旧 History 记录不会进入新项目
# 2026/11/26    XTN       V1.078        生成项目验证集中密码规则及缺少任一类字符时提前拒绝
# 2026/11/27    XTN       V1.079        实际生成项目只保留两个系统角色，admin 可作为普通自定义角色
# 2026/11/28    XTN       V1.080        生成验证权限展示目录、完整示例裁剪和自动接口映射
# --------------------------------------------------------------------------------------------------

from __future__ import annotations

import ast
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest
from datetime import date
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve(
).parents[1] / "skills" / "fastapi-templates-xtn"
GENERATOR_PATH = SKILL_ROOT / "scripts" / "create_project.py"
SPEC = importlib.util.spec_from_file_location("create_project", GENERATOR_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Cannot load project generator")
GENERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATOR)


class CreateProjectTests(unittest.TestCase):
    """检查输出来源、用户选择、代码自洽与现有目录保护。"""

    def setUp(self) -> None:
        """
            为每项测试分配独立的系统临时目录，不写实际业务项目。

        :return: 无返回值；当前测试获得自动清理的交付目标父目录。
        """
        temporary = tempfile.TemporaryDirectory(prefix="xtn-project-test-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)

    def create(self, *, username_case: str = "insensitive") -> Path:
        """
            生成固定虚构业务，复用已经确认的用户选择。

        :param username_case: 当前用例要验证的用户名大小写策略。
        :return: 只包含文件、尚未初始化数据库的新项目目录。
        """
        target = self.base / f"review-orders-{username_case}"
        result = GENERATOR.create_project(target, name="review-orders", username_case=username_case,
                                          max_sessions=3)
        self.assertEqual(result, target.resolve())
        return target

    def run_python(self, target: Path, script: str) -> str:
        """
            在交付目录启动独立 Python 并提供虚构配置，所有网络连接和 DDL 都会被拦截。

        :param target: 本测试创建的新项目目录。
        :param script: 需要执行的离线检查代码。
        :return: 子进程标准输出；非零退出会使测试失败。
        """
        environment = dict(os.environ)
        environment.update({
            "PYTHONDONTWRITEBYTECODE": "1",
            "DATABASE_URL": "postgresql+asyncpg://review:review@127.0.0.1:65533/review_test",
            "REDIS_URL": "redis://127.0.0.1:65534/0", "MAX_ACTIVE_SESSIONS_PER_USER": "3",
            "JWT_SECRET": "D7vL3qN9xR2mK8pT5sW1cF6hJ4yB0uGz",
            "RATE_LIMIT_HMAC_KEY": "vM8qD2kR7pX4cN9sH5wF1jL6tG3yB0uZ",
            "LOG_HMAC_KEY": "N6wR2tY9qH4kF7vD1sL8cB3mJ5xP0uGa",
        })
        for key in ("JWT_ISSUER", "JWT_AUDIENCE", "SERVICE_NAME", "SERVICE_VERSION", "APP_ENVIRONMENT", "PYTHONPATH"):
            environment.pop(key, None)
        guard = '''
import sys
from pathlib import Path
import sqlalchemy

def reject_ddl(*args, **kwargs):
    """
        阻止检查中出现建表和删除表操作。

    :param args: 被阻止操作的位置参数。
    :param kwargs: 被阻止操作的关键字参数。
    :return: 不正常返回，立即终止具有数据库副作用的检查。
    """
    raise AssertionError("offline project review must not execute DDL")

def reject_network(event, args):
    """
        阻止检查连接外部网络，不输出连接参数。

    :param event: Python 审计事件名称。
    :param args: 被忽略的审计事件数据。
    :return: 非连接事件正常返回，连接事件立即失败。
    """
    if event == "socket.connect":
        raise AssertionError("offline project review must not connect to services")

sys.addaudithook(reject_network)
sqlalchemy.MetaData.create_all = reject_ddl
sqlalchemy.MetaData.drop_all = reject_ddl
import app
assert Path(app.__file__).resolve().is_relative_to(Path.cwd().resolve())
'''
        result = subprocess.run([sys.executable, "-B", "-c", guard + script], cwd=target, env=environment,
                                capture_output=True, text=True, check=False, timeout=45)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        return result.stdout

    def test_existing_file_and_nonempty_directory_are_not_overwritten(self) -> None:
        """
            文件目标和包含使用者文件的目录必须拒绝生成，已有内容保持原样。

        :return: 无返回值；两种目标都没有被覆盖或删除。
        """
        for kind in ("file", "directory"):
            with self.subTest(kind=kind):
                target = self.base / kind
                if kind == "directory":
                    target.mkdir()
                    marker = target / "user-content.txt"
                else:
                    marker = target
                marker.write_bytes(b"owned by the user")
                with self.assertRaisesRegex(ValueError, "absent or empty"):
                    GENERATOR.create_project(target, name="review-orders", username_case="insensitive",
                                             max_sessions=3)
                self.assertEqual(marker.read_bytes(), b"owned by the user")
                if kind == "directory":
                    self.assertEqual(list(target.iterdir()), [marker])

    def test_export_is_minimal_without_auxiliary_manifests(self) -> None:
        """
            检查真实输出边界，不带迁移、维护工具、额外辅助文档或缓存。

        :return: 无返回值；根目录仅有运行代码、少量测试及实际使用的项目配置和说明。
        """
        target = self.create()
        relative_files = {path.relative_to(target).as_posix(
        ) for path in target.rglob("*") if path.is_file()}
        self.assertEqual({path.name for path in target.iterdir()},
                         {"app", "tests", ".env.example", ".gitignore", "README.md", "pyproject.toml"})
        self.assertFalse(any(name.startswith(("alembic/", "sql/", "scripts/", "app/commands/"))
                             for name in relative_files))
        cache_parts = {".mypy_cache", ".pytest_cache",
                       ".ruff_cache", "__pycache__"}
        self.assertFalse(any(cache_parts.intersection(Path(name).parts) or name.endswith(".pyc")
                             for name in relative_files))
        self.assertFalse((target / ".env").exists())
        self.assertFalse((target / "compose.dev.yaml").exists())
        self.assertEqual({name for name in relative_files if name.startswith("tests/")},
                         {"tests/test_authorization.py", "tests/test_user_name.py"})
        self.assertTrue(all(Path(name).suffix in {".py", ".json"}
                            for name in relative_files if name.startswith("app/")))
        self.assertTrue({"app/core/codes.py", "app/core/exceptions.py",
                         "app/core/response.py", "app/core/exception_handlers.py"} <= relative_files)
        self.assertNotIn("app/core/errors.py", relative_files)
        self.assertIn("app/db/postgres_db.py", relative_files)
        self.assertNotIn("app/db/postgres_errors.py", relative_files)
        self.assertNotIn("app/db/errors.py", relative_files)
        self.assertIn("app/dependencies/permission.py", relative_files)
        self.assertNotIn("app/db/postgres_pool.py", relative_files)
        self.assertNotIn("app/repositories/postgres/user_authority_repository.py", relative_files)
        for filename in ("SKILL_SOURCE.json", "DATABASE_HANDOFF.md", "LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"):
            self.assertFalse(
                any(Path(name).name == filename for name in relative_files), filename)
        configuration = tomllib.loads(
            (target / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(configuration["project"]["name"], "review-orders")
        self.assertEqual(configuration["project"]["version"], "0.1.0")
        self.assertEqual(configuration["project"]["readme"], "README.md")
        self.assertEqual(configuration["project"]["license-files"], [])
        self.assertNotIn("license", configuration["project"])
        self.assertFalse(any(dependency.startswith("alembic")
                         for dependency in configuration["project"]["dependencies"]))
        self.assertIn("dev", configuration["project"]["optional-dependencies"])
        example = (target / ".env.example").read_text(encoding="utf-8")
        self.assertIn("MAX_ACTIVE_SESSIONS_PER_USER=3", example)
        self.assertNotIn("ADMIN_PASSWORD_RESET_MODE", example)
        self.assertIn("SERVICE_NAME=review-orders", example)
        readme = (target / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("{{", readme)
        self.assertNotIn("SKILL_SOURCE.json", readme)
        self.assertNotIn("DATABASE_HANDOFF.md", readme)
        # 检查使用者真正点击的相对链接，不允许删除文件后留下失效入口。
        for destination in re.findall(r"\[[^\]]*\]\(([^)]+)\)", readme):
            if destination.startswith(("http://", "https://", "mailto:", "#")):
                continue
            self.assertTrue((target / destination.split("#", 1)
                            [0]).exists(), destination)

    def test_generated_user_queries_stay_with_business_repositories(self) -> None:
        """
            实际导入生成的用户和角色仓储，确认查询入口与软删除默认值一起交付。

        :return: 无返回值；用户查询统一，角色可见性仍由角色仓储负责。
        """
        target = self.create()
        self.run_python(target, '''
from inspect import iscoroutinefunction, signature
from app.repositories.postgres.user_repository import UserDetails, UserPermissions, UserRepository, user_repository
from app.repositories.postgres.role_repository import RoleRepository, role_repository
assert not Path("app/repositories/postgres/user_authority_repository.py").exists()
assert isinstance(user_repository, UserRepository)
assert isinstance(role_repository, RoleRepository)
parameters = signature(user_repository.get_user).parameters
assert tuple(parameters) == ("session", "user_id", "user_name", "is_active", "is_deleted")
assert parameters["user_id"].default is None and parameters["user_name"].default is None
assert parameters["is_active"].default is None and parameters["is_deleted"].default is False
for name in ("get_user", "update_password", "check_current_user", "get_user_permissions",
             "get_users_info", "get_user_detail", "list_users"):
    assert iscoroutinefunction(getattr(user_repository, name)), name
for name in ("list_roles", "get_role_detail", "get_role_permissions"):
    assert iscoroutinefunction(getattr(role_repository, name)), name
role_filters = ("role_id", "key", "name", "is_active", "is_system", "is_deleted")
parameters = signature(role_repository.list_roles).parameters
assert tuple(parameters) == ("session", "current_user", "page", "page_size", *role_filters)
assert all(parameters[name].default is None for name in role_filters[:-1])
assert parameters["is_deleted"].default is False
assert signature(role_repository._build_role_query).parameters["is_deleted"].default is False
for name in ("get_live_user", "get_by_user_name", "get_by_user_id", "require_current_user",
             "load_authority_snapshot", "load_authority_snapshots_for_users", "load_user_access_views",
             "load_visible_user", "list_visible_users_page", "get_users_permissions",
             "_select_user_role_permissions", "_get_user_permissions"):
    assert not hasattr(user_repository, name), name
assert UserDetails.__module__ == "app.repositories.postgres.user_repository"
assert tuple(UserDetails.__dataclass_fields__) == ("user_name", "bound_role_ids", "user_info")
assert UserPermissions.__module__ == "app.repositories.postgres.user_repository"
assert tuple(UserPermissions.__dataclass_fields__) == ("user_info", "user_info_with_disabled_roles")
assert tuple(signature(user_repository.get_user_permissions).parameters) == ("session", "users")
''')

    def test_operator_recovery_stays_out_of_the_default_project(self) -> None:
        """
            确认线下密码恢复的服务和专用查询不混入新项目认证、角色代码。

        :return: 无返回值；默认项目只保留业务运行时需要的功能。
        """
        target = self.create()
        self.run_python(target, '''
from app.core.exceptions import AppError, InvalidLoginCredentialsError
assert issubclass(InvalidLoginCredentialsError, AppError)
from app.services.auth_service import AuthService
from app.repositories.postgres.user_role_repository import UserRoleRepository
assert not hasattr(AuthService, "reset_super_admin_password")
assert not hasattr(UserRoleRepository, "load_live_super_admin_holder_ids")
assert not Path("app/commands").exists()
''')

    def test_example_environment_contains_only_live_settings(self) -> None:
        """
            检查生成的 .env.example 不再列出已经删除、程序不会读取的配置项。

        :return: 无返回值；每个有效配置名都能在 Settings 中找到对应字段。
        """
        target = self.create()
        self.run_python(target, '''
from app.core.config import Settings
example = Path(".env.example").read_text(encoding="utf-8")
configured = {
    line.split("=", 1)[0].strip()
    for line in example.splitlines()
    if line.strip() and not line.lstrip().startswith("#") and "=" in line
}
supported = {name.upper() for name in Settings.model_fields}
assert configured <= supported, sorted(configured - supported)
''')

    def test_generated_permission_quota_follows_business_choice(self) -> None:
        """实际生成后，普通权限接口使用普通额度，管理业务保留原额度。"""
        target = self.create()
        self.run_python(target, '''
from inspect import getclosurevars, signature
from types import SimpleNamespace
from fastapi import Request, routing
from fastapi.routing import APIRoute
from app.main import app
from app.api.v1.route_validation import validate_v1_api_routes
from app.core.access.permissions import PermissionKey
from app.core.config import get_settings
from app.dependencies import auth, rate_limit
from app.dependencies.permission import require_permission

validate_v1_api_routes(app)
assert signature(require_permission).parameters["management"].default is False
check_code = require_permission(PermissionKey.USERS_READ).__code__
iter_contexts = getattr(routing, "iter_route_contexts", None)
contexts = list(iter_contexts(app.routes)) if callable(iter_contexts) else app.routes
management_checks = 0
basic_checks = set()
basic_keys = {PermissionKey.ACCOUNT_READ.value, PermissionKey.ACCOUNT_CHANGE_PASSWORD.value}
for item in contexts:
    route = getattr(item, "original_route", item)
    if not isinstance(route, APIRoute):
        continue
    pending = [route.dependant]
    while pending:
        node = pending.pop()
        if getattr(node.call, "__code__", None) is check_code:
            options = getclosurevars(node.call).nonlocals
            if options["required_key"] in basic_keys:
                assert options["management"] is False
                basic_checks.add(options["required_key"])
            else:
                assert options["management"] is True
                management_checks += 1
        pending.extend(node.dependencies)
assert management_checks > 0
assert basic_checks == basic_keys

calls = []
context = SimpleNamespace(permissions={PermissionKey.USERS_READ.value})
async def load_account(*args):
    return context
async def record_quota(*args, **kwargs):
    calls.append(kwargs)
auth._load_current_user = load_account
rate_limit._check_quota = record_quota
settings = get_settings()
for method, management, limit in (
    ("GET", False, settings.rate_limit_user_read),
    ("POST", False, settings.rate_limit_user_write),
    ("GET", True, settings.rate_limit_admin_read),
    ("POST", True, settings.rate_limit_admin_write),
):
    dependency = (require_permission(PermissionKey.USERS_READ, management=True) if management
                  else require_permission(PermissionKey.USERS_READ))
    request = Request({"type": "http", "method": method, "headers": [],
                       "route": SimpleNamespace(name="business_demo")})
    coroutine = dependency(request, SimpleNamespace(user_id="U123456789ABCDE"), settings)
    try:
        coroutine.send(None)
    except StopIteration as completed:
        assert completed.value is context
    else:
        coroutine.close()
        raise AssertionError("Offline quota check unexpectedly suspended")
    assert calls[-1]["limit"] == limit and calls[-1]["window_seconds"] == 60
assert len(calls) == 4
''')

    def test_username_choices_change_normalization_and_model_constraint_together(self) -> None:
        """
            两种用户名策略分别生成独立项目，API 规范化与模型约束必须使用同一种选择。

        :return: 无返回值；大小写策略没有只改文档或只改单层。
        """
        for choice in ("sensitive", "insensitive"):
            with self.subTest(choice=choice):
                target = self.create(username_case=choice)
                raw = self.run_python(target, '''
import json
from app.core.security.user_name import validate_user_name
from app.models.postgres import User
print(json.dumps({"value": validate_user_name("  Alice_Name  "),
                  "checks": [str(item.sqltext) for item in User.__table__.constraints
                             if isinstance(item, sqlalchemy.CheckConstraint)]}))
''')
                data = json.loads(raw)
                self.assertEqual(
                    data["value"], "alice_name" if choice == "insensitive" else "Alice_Name")
                self.assertEqual(
                    "user_name = lower(user_name)" in data["checks"], choice == "insensitive")

    def test_username_rule_edit_updates_all_consumers(self) -> None:
        """只修改生成项目的用户名规则，验证请求、查询、数据库模型和提示一起变化。"""
        for choice in ("sensitive", "insensitive"):
            with self.subTest(choice=choice):
                target = self.create(username_case=choice)
                rule_file = target / "app/core/security/user_name.py"
                source = rule_file.read_text(encoding="utf-8")
                for before, after in (
                    ("MIN_USER_NAME_LENGTH = 3", "MIN_USER_NAME_LENGTH = 4"),
                    ("MAX_USER_NAME_LENGTH = 32", "MAX_USER_NAME_LENGTH = 24"),
                    ('USER_NAME_CHARACTERS = r"A-Za-z0-9_"', 'USER_NAME_CHARACTERS = r"A-Za-z0-9"'),
                    ('USER_NAME_CHARACTERS_ZH = "英文字母、数字或下划线"',
                     'USER_NAME_CHARACTERS_ZH = "英文字母或数字"'),
                    ('USER_NAME_CHARACTERS_EN = "ASCII letters, digits or underscores"',
                     'USER_NAME_CHARACTERS_EN = "ASCII letters or digits"'),
                ):
                    self.assertEqual(source.count(before), 1)
                    source = source.replace(before, after, 1)
                rule_file.write_text(source, encoding="utf-8")
                self.run_python(target, '''
from pydantic import TypeAdapter
from app.api.v1.endpoints.users import UserNameQuery
from app.core.i18n.messages import MessageKey, translate_for_locale
from app.core.security.user_name import validate_user_name
from app.main import app
from app.models.postgres import User
from app.schemas.common import UsernameRequest

query_parser = TypeAdapter(UserNameQuery)
for value, accepted in (("abc", False), ("abcd", True), ("a" * 24, True),
                        ("a" * 25, False), ("ab_c", False)):
    for parse in (validate_user_name, query_parser.validate_python,
                  lambda value: UsernameRequest(user_name=value).user_name):
        try:
            parsed = parse("  " + value + "  ")
        except ValueError:
            assert not accepted, value
        else:
            assert accepted and parsed == value, value
assert User.__table__.c.user_name.type.length == 24
assert "user_name ~ '^[A-Za-z0-9]{4,24}$'" in {
    str(item.sqltext) for item in User.__table__.constraints
    if isinstance(item, sqlalchemy.CheckConstraint)
}
schema = app.openapi()
for name in ("RegisterRequest", "LoginRequest", "UserCreateRequest"):
    field = schema["components"]["schemas"][name]["properties"]["user_name"]
    assert (field["minLength"], field["maxLength"]) == (4, 24)
    assert field["pattern"] == "^[A-Za-z0-9]{4,24}$"
    assert "4～24 位英文字母或数字" in field["description"]
query = next(item for item in schema["paths"]["/api/v1/users/list"]["get"]["parameters"]
             if item["name"] == "user_name")
assert "4 至 24 位英文字母或数字" in query["description"]
for locale, expected in (
    ("zh-CN", "去掉首尾空白后，用户名须为 4～24 位英文字母或数字"),
    ("en", "After trimming surrounding whitespace, the username must be 4-24 ASCII letters or digits"),
    ("unsupported", "去掉首尾空白后，用户名须为 4～24 位英文字母或数字"),
):
    assert translate_for_locale(locale, MessageKey.VALIDATION_USER_NAME_FORMAT) == expected
''')

    def test_complete_models_and_catalog_import_without_database_configuration(self) -> None:
        """
            实际导入模型、权限和角色配置，确认无数据库配置副作用及双语权限描述完整。

        :return: 无返回值；未采用的 projects 演示权限没有进入生成项目。
        """
        target = self.create()
        raw = self.run_python(target, '''
import json
from app.models.postgres import Base
assert not any(name.startswith("app.db.") for name in sys.modules)
assert "app.core.config" not in sys.modules
role_columns = set(Base.metadata.tables["roles"].columns.keys())
assert "level" in role_columns and "management_tier" not in role_columns
for table_name in ("user_roles", "role_permissions"):
    columns = Base.metadata.tables[table_name].columns
    assert {"bound_by_user_id", "bound_at"} <= set(columns.keys())
    assert not {"assigned_by_user_id", "assigned_at"} & set(columns.keys())
    assert columns.bound_by_user_id.nullable
    assert {fk.target_fullname for fk in columns.bound_by_user_id.foreign_keys} == {"users.user_id"}
    assert not columns.bound_at.nullable and columns.bound_at.type.timezone
    assert columns.bound_at.server_default is not None
from app.schemas.user import UserAccessResponse, UserResponse
from app.schemas.role import RoleCreateRequest, RoleResponse
user_properties = UserResponse.model_json_schema()["properties"]
assert "bound_role_ids" in user_properties and "assigned_role_ids" not in user_properties
assert "effective_role_ids" in user_properties
for response_model in (UserResponse, UserAccessResponse):
    assert "role_level" in response_model.model_fields
    assert not {"management_tier", "effective_management_tier"} & set(response_model.model_fields)
for role_model in (RoleCreateRequest, RoleResponse):
    assert "level" in role_model.model_fields and "management_tier" not in role_model.model_fields
from app.core.i18n.messages import MessageKey, translate_for_locale
from app.core.i18n.language import select_locale
from app.core.i18n.validation_messages import validation_field
from app.core.access.permissions import (
    PermissionKey, PermissionGroup, PermissionSpec, PERMISSION_CATALOG,
    PERMISSION_GROUP_NAMES, get_permission_description,
)
import app.core.access.roles as role_defaults
from app.core.access.roles import SystemRoleKey, SYSTEM_ROLE_SPECS, RESERVED_ROLE_KEYS
from app.core.access import authorization, role_policy, user_policy
from app.core.security import jwt_tokens
from app.repositories.redis import login_session_repository
assert PermissionKey.__module__ == "app.core.access.permissions"
assert SystemRoleKey.__module__ == "app.core.access.roles"
assert select_locale("en-US") == "en"
assert validation_field({"loc": ("body", "user_name"), "type": "missing"}) == "body.user_name"
assert not any(hasattr(authorization, name)
               for name in ("PermissionKey", "PERMISSION_CATALOG", "SystemRoleKey", "SYSTEM_ROLE_SPECS"))
catalog = {key.value for key in PermissionKey}
assert catalog == {key.value for key in PERMISSION_CATALOG}
assert set(PERMISSION_GROUP_NAMES) == set(PermissionGroup)
for key, spec in PERMISSION_CATALOG.items():
    assert isinstance(spec, PermissionSpec)
    assert isinstance(spec.name, MessageKey) and isinstance(spec.description, MessageKey)
    assert isinstance(spec.group_key, PermissionGroup)
    assert translate_for_locale("zh-CN", spec.name) != translate_for_locale("en", spec.name)
    assert translate_for_locale("zh-CN", PERMISSION_GROUP_NAMES[spec.group_key]) != (
        translate_for_locale("en", PERMISSION_GROUP_NAMES[spec.group_key]))
    chinese = get_permission_description(key)
    english = get_permission_description(key, locale="en")
    assert chinese == translate_for_locale("zh-CN", spec.description)
    assert english == translate_for_locale("en", spec.description)
    assert chinese and english and chinese != english
assert get_permission_description("custom:read", stored_description="Custom project description", locale="en") == (
    "Custom project description")
for spec in SYSTEM_ROLE_SPECS.values():
    assert spec.permissions <= catalog
    assert not hasattr(spec, "name") and not hasattr(spec, "description")
assert {spec.level for spec in SYSTEM_ROLE_SPECS.values()} == {0, 1000}
assert set(SystemRoleKey) == {SystemRoleKey.SUPER_ADMIN, SystemRoleKey.USER}
assert RESERVED_ROLE_KEYS == {"super_admin", "user"}
assert not hasattr(role_defaults, "ADMIN_PERMISSION_KEYS")
assert RoleCreateRequest(key="admin", name="自定义管理员", level=500).key == "admin"
role_constraints = {constraint.name: str(constraint.sqltext)
                    for constraint in Base.metadata.tables["roles"].constraints
                    if hasattr(constraint, "sqltext")}
assert role_constraints["ck_roles_system_role_key_fixed"] == (
    "NOT is_system OR key IN ('super_admin', 'user')")
assert "ck_roles_admin_role_shape" not in role_constraints
assert authorization.UserInfo.build(
    user_id="U123456789ABCDE", user_is_active=True, user_is_protected=False, roles=(),
).role_level == 0
assert all(module.__file__ and Path(module.__file__).resolve().is_relative_to(Path.cwd().resolve())
           for module in (jwt_tokens, role_policy, login_session_repository, user_policy))
print(json.dumps({"tables": sorted(Base.metadata.tables), "permissions": sorted(catalog),
                  "roles": sorted(key.value for key in SYSTEM_ROLE_SPECS)}))
''')
        data = json.loads(raw)
        self.assertEqual(set(data["tables"]), {"users", "roles", "permissions", "user_roles", "role_permissions",
                                               "rbac_state", "operation_audit_events"})
        self.assertEqual(data["roles"], ["super_admin", "user"])
        self.assertFalse(any(permission.startswith("projects:")
                         for permission in data["permissions"]))

    def test_example_permission_export_rejects_incomplete_template_changes(self) -> None:
        """
            示例权限移动或少一份定义时停止导出，避免生成半套目录或保留示例授权。

        :return: 无返回值；只在内存修改模板，不生成数据库结构。
        """
        for relative, before, after in (
            ("app/core/access/permissions.py", '    PROJECTS_UPDATE = "projects:update"',
             '    PROJECTS_EDIT = "projects:update"'),
            ("app/core/access/permissions.py", "PERMISSION_CATALOG: dict[", "OTHER_CATALOG: dict["),
            ("app/core/access/roles.py", "SUPER_ADMIN_PERMISSION_KEYS = frozenset(",
             "OTHER_PERMISSION_KEYS = frozenset("),
        ):
            with self.subTest(relative=relative, change=before):
                source = (GENERATOR.ASSET_ROOT / relative).read_text(encoding="utf-8")
                self.assertIn(before, source)
                with self.assertRaisesRegex(ValueError, "Example permission catalog changed"):
                    GENERATOR.project_content(
                        Path(relative), source.replace(before, after, 1), name="review-orders",
                        username_case="insensitive",
                    )

    def test_permission_directory_and_api_mapping_work_in_generated_project(self) -> None:
        """
            实际生成并导入项目，核对权限名称、分组、接口映射及未知权限的回退。

        :return: 无返回值；新增嵌套路由会自动进入目录，全程不连接数据库或 Redis。
        """
        target = self.create()
        self.run_python(target, '''
from typing import Annotated
from unittest.mock import AsyncMock, patch
from fastapi import APIRouter, Depends, FastAPI
from app.main import app
from app.api.v1.route_validation import validate_v1_api_routes
from app.core.access.authorization import AuthorizationContext
from app.core.access.permissions import (
    PERMISSION_CATALOG, PERMISSION_GROUP_NAMES, PermissionGroup, PermissionKey,
)
from app.core.i18n.messages import translate_for_locale
from app.dependencies.permission import require_permission
from app.models.postgres.permission import Permission
from app.schemas.permission import PermissionApiRouteResponse, PermissionResponse
from app.services.permission_service import permission_repository, permission_service

assert set(PermissionResponse.model_fields) == {
    "id", "key", "name", "group_key", "group_name", "description", "api_routes",
}
assert set(PermissionApiRouteResponse.model_fields) == {"method", "path"}
assert len(PERMISSION_CATALOG) == 17
assert not hasattr(PermissionKey, "PROJECTS_READ") and not hasattr(PermissionKey, "PROJECTS_UPDATE")
# 分组只是展示标识；保留 projects 不会生成其权限或角色授权。
assert PermissionGroup.PROJECTS in PERMISSION_GROUP_NAMES
assert all(spec.group_key != PermissionGroup.PROJECTS for spec in PERMISSION_CATALOG.values())

validate_v1_api_routes(app)
api_routes = app.state.permission_api_routes
assert sum(len(routes) for routes in api_routes.values()) == 23
assert api_routes["account:read"] == (("GET", "/api/v1/me/user_info"),)
assert api_routes["permissions:read"] == (
    ("GET", "/api/v1/permissions/detail"), ("GET", "/api/v1/permissions/list"),
)
assert ("POST", "/api/v1/users/password/reset") in api_routes["users:password:reset"]
assert all(routes == tuple(sorted(set(routes))) for routes in api_routes.values())

# 新增接口只声明真实权限依赖；不用另外维护一份权限和接口对照表。
permission_check = require_permission(PermissionKey.USERS_READ)
assert permission_check.permission_key == "users:read"
UserReadContext = Annotated[AuthorizationContext, Depends(permission_check)]
inner = APIRouter(prefix="/records")
@inner.get("/list", dependencies=[Depends(permission_check)])
async def list_nested_records(context: UserReadContext):
    return None
outer = APIRouter(prefix="/reports")
outer.include_router(inner)
other_app = FastAPI()
other_app.include_router(outer, prefix="/api/v1")
validate_v1_api_routes(other_app)
assert other_app.state.permission_api_routes == {
    "users:read": (("GET", "/api/v1/reports/records/list"),),
}
assert app.state.permission_api_routes is api_routes
assert ("GET", "/api/v1/reports/records/list") not in api_routes["users:read"]

async def verify_response_metadata():
    permission = Permission(id="P123456789ABCDE", key="users:read", description="数据库原说明")
    with patch.object(permission_repository, "get_live_permission", AsyncMock(return_value=permission)):
        chinese = await permission_service.get_permission_detail(
            object(), permission_id=permission.id, permission_api_routes=api_routes,
        )
        english = await permission_service.get_permission_detail(
            object(), permission_id=permission.id, permission_api_routes=api_routes, locale="en",
        )
    spec = PERMISSION_CATALOG[PermissionKey.USERS_READ]
    assert chinese.name == translate_for_locale("zh-CN", spec.name)
    assert english.name == translate_for_locale("en", spec.name) and english.name != chinese.name
    assert chinese.group_key == english.group_key == "users"
    assert chinese.group_name != english.group_name
    assert chinese.description != english.description
    assert [(route.method, route.path) for route in chinese.api_routes] == list(api_routes["users:read"])
    assert chinese.api_routes == english.api_routes
    assert chinese.model_dump(mode="json")["api_routes"] == [
        {"method": method, "path": path} for method, path in api_routes["users:read"]
    ]
    permission.key = "custom:read"
    with patch.object(permission_repository, "get_live_permission", AsyncMock(return_value=permission)):
        custom = await permission_service.get_permission_detail(
            object(), permission_id=permission.id, permission_api_routes=api_routes,
        )
    assert custom.name == "custom:read" and custom.group_key == "other"
    assert custom.group_name == translate_for_locale("zh-CN", PERMISSION_GROUP_NAMES[PermissionGroup.OTHER])
    assert custom.description == "数据库原说明" and custom.api_routes == ()

# AsyncMock 会立即返回；直接跑完协程，不创建 Windows 事件循环的本机 socketpair。
verification = verify_response_metadata()
try:
    verification.send(None)
except StopIteration:
    pass
else:
    verification.close()
    raise AssertionError("offline permission checks must not wait for external I/O")
''')

    def test_generated_project_keeps_prefixed_id_contract(self) -> None:
        """
            生成一次新项目，确认八张表和 JWT 主体使用同一套新 ID 规则。

        :return: 无返回值；项目无需连接数据库或 Redis。
        """
        target = self.create()
        raw = self.run_python(target, '''
import json
import uuid
import jwt
from app.core.config import get_settings
from app.core.ids import new_audit_id, new_entity_id
from app.core.security.jwt_tokens import decode_access_token, encode_access_token
from app.repositories.redis.login_session_repository import (
    _build_session_record, _parse_session_record, _user_session_keys,
)
from app.models.postgres import Base
from app.schemas.user import UserResponse, UserTargetRequest
user_id = new_entity_id("U")
assert UserTargetRequest(user_id=user_id).user_id == user_id
assert list(Base.metadata.tables["users"].primary_key.columns.keys()) == ["user_id"]
assert "user_id" in UserResponse.model_fields and "id" not in UserResponse.model_fields
settings = get_settings()
token, token_info = encode_access_token(user_id=user_id, token_id=uuid.uuid4(), settings=settings)
payload = jwt.decode(token, settings.jwt_secret.get_secret_value(), algorithms=["HS256"])
assert payload["user_id"] == user_id and "sub" not in payload
assert decode_access_token(token, settings).user_id == user_id
session_value = _build_session_record(token_info, user_token_version=0)
assert json.loads(session_value)["user_id"] == user_id and "sub" not in json.loads(session_value)
assert _parse_session_record(session_value)[0] == user_id
assert _user_session_keys(user_id=user_id) == (
    f"login:sessions:{user_id}", f"login:sequence:{user_id}",
)
lengths = {name: list(table.primary_key.columns)[0].type.length
           for name, table in Base.metadata.tables.items() if name != "rbac_state"}
print(json.dumps({"lengths": lengths, "user_id": user_id, "audit_id": new_audit_id("OA")}))
''')
        data = json.loads(raw)
        self.assertEqual(len(data["user_id"]), 15)
        self.assertEqual(len(data["audit_id"]), 22)
        self.assertEqual(set(data["lengths"].values()), {15, 22})
        self.assertEqual(
            sum(length == 15 for length in data["lengths"].values()), 5)
        self.assertEqual(
            sum(length == 22 for length in data["lengths"].values()), 1)

    def test_generated_operation_audit_separates_users_and_omits_optional_business_audit(self) -> None:
        """
            在实际生成项目中构造审计，确认操作人与被操作人不会混用，且无需连接数据库。

        :return: 无返回值；操作人与被操作人分开，默认只交付统一操作审计。
        """
        target = self.create()
        raw = self.run_python(target, '''
import json
import uuid
from pathlib import Path
from unittest.mock import Mock
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.access.authorization import AuthorizationContext, LoginInfo, UserInfo
from app.core.audit import AccountAuditAction, AuditSource, get_audit_request_id
from app.core.ids import new_entity_id
from app.core.logging.context import (
    bind_request_context, current_request_id, deactivate_request_context, reset_request_context,
)
from app.models.postgres.operation_audit import OperationAuditEvent
from app.models.postgres import Base
from app.services.audit_service import AuditService
user_id, target_user_id = new_entity_id("U"), new_entity_id("U")
login_info = LoginInfo(user_id=user_id, token_version=0, token_id=uuid.uuid4(), issued_at=1, expires_at=2)
context = AuthorizationContext(
    login_info=login_info,
    user_info=UserInfo.build(user_id=user_id, user_is_active=True, user_is_protected=False,
                                      token_version=0, roles=()),
    audit_source=AuditSource.HTTP,
)
session = Mock(spec=AsyncSession)
operation_id = str(uuid.uuid4())
context_token = bind_request_context(operation_id)
try:
    event = AuditService.audit_success(
        session, action=AccountAuditAction.ADMIN_RESET_PASSWORD, context=context,
        reason_code="password_reset", target_user_id=target_user_id,
    )
    session.add.assert_called_once_with(event)
    session.commit.assert_not_called()
    assert event.request_id == get_audit_request_id() == operation_id
finally:
    deactivate_request_context()
    reset_request_context(context_token)
assert current_request_id() is None
assert event.user_id == user_id and event.target_user_id == target_user_id
assert event.user_id != event.target_user_id
assert event.source == "http" and event.id.startswith("OA") and len(event.id) == 22
columns = set(OperationAuditEvent.__table__.columns.keys())
assert len(columns) == 16
assert {"request_data", "response_data", "password_fingerprint", "before_state", "after_state"} <= columns
assert not columns & {"operator_type", "schema_version", "target_type", "target_id"}
assert not Path("app/models/postgres/business_audit.py").exists()
assert not Path("app/services/business_audit_service.py").exists()
assert set(Base.metadata.tables) == {
    "users", "roles", "permissions", "user_roles", "role_permissions", "rbac_state", "operation_audit_events",
}
print(json.dumps({"separate_users": True}))
''')
        self.assertEqual(json.loads(raw), {"separate_users": True})

    def test_openapi_import_and_project_identity_need_no_running_services(self) -> None:
        """
            在不连接服务的情况下加载应用和文档，检查实际请求契约与项目默认标识。

        :return: 无返回值；文档与身份配置不会回落到维护模板的名称。
        """
        target = self.create()
        raw = self.run_python(target, '''
import json
from app.main import app
from app.core.config import get_settings
from app.core.audit import AccountAuditAction, RbacAuditAction, validate_audit_action
from app.core.captcha import CaptchaScene
from app.api.v1.route_validation import validate_v1_api_routes
from app.schemas import auth, captcha, common, permission, role, user
from app.core.access.authorization import AuthorizationContext, UserInfo
from app.models.postgres.user import User
from app.models.postgres.role import Role
from dataclasses import fields
assert "authz_version" not in User.__table__.columns
assert "token_version" in User.__table__.columns and "version" in Role.__table__.columns
assert "authz_version" not in {field.name for field in fields(UserInfo)}
assert "authz_version" not in user.UserResponse.model_fields
assert "authz_version" not in user.UserAccessResponse.model_fields
assert "authorization_epoch" not in user.UserAccessResponse.model_fields
from typing import get_type_hints
from app.services.captcha_service import CaptchaService
from app.dependencies import captcha as captcha_dependency
import uuid
from app.core.exceptions import AppError
assert get_type_hints(CaptchaService.create_captcha)["return"] is captcha.CaptchaResponse
for captcha_method in (
    CaptchaService.create_captcha, CaptchaService.verify_captcha,
    CaptchaService.hash_captcha_code, CaptchaService.validate_scene_user,
):
    hints = get_type_hints(captcha_method)
    assert "user_id" in hints and "owner_id" not in hints
    assert hints["scene"] is CaptchaScene
assert get_type_hints(CaptchaService.validate_scene_user)["return"] is type(None)
assert not hasattr(captcha_dependency, "issue_captcha_response")
assert not hasattr(captcha_dependency, "verify_and_consume_captcha")
assert not hasattr(CaptchaService, "parse_captcha_record")
import hashlib
import hmac
from app.core.rate_limit.limiter import RateLimitPolicy, build_rate_limit_key
settings = get_settings()
assert (settings.password_max_running, settings.password_max_waiting,
        settings.password_wait_timeout_seconds) == (2, 4, 0.5)
configured_password_limits = type(settings).model_validate({
    **settings.model_dump(), "password_max_running": 1, "password_max_waiting": 0,
    "password_wait_timeout_seconds": 0.25,
})
assert (configured_password_limits.password_max_running, configured_password_limits.password_max_waiting,
        configured_password_limits.password_wait_timeout_seconds) == (1, 0, 0.25)
assert "rate_limit_namespace" not in type(settings).model_fields
assert "RATE_LIMIT_NAMESPACE" not in Path(".env.example").read_text(encoding="utf-8")
policy = RateLimitPolicy(name="captcha_create_login", limit=10, window_seconds=300)
message = bytes([0]).join((b"captcha_create_login", b"ip", b"192.0.2.7"))
secret = settings.rate_limit_hmac_key.get_secret_value().encode("utf-8")
expected_digest = hmac.new(secret, message, hashlib.sha256).hexdigest()
assert build_rate_limit_key(policy=policy, subject_type="ip", subject="192.0.2.7", key_secret=secret) == (
    f"rate_limit:captcha_create_login:ip:{expected_digest}"
)
class MemoryCaptchaRedis:
    """仅提供一次读取删除；生成检查不会连接真实 Redis。"""
    def __init__(self, digest):
        """
            保存一份等待消费的摘要。

        :param digest: 本次验证码预先生成的摘要。
        :return: 无返回值；模拟记录和命令次数已初始化。
        """
        self.digest, self.calls = digest, 0
        self.keys = []
    async def getdel(self, key):
        """
            模拟 GETDEL：读取摘要的同时清空记录。

        :param key: 调用者构造的验证码记录键。
        :return: 首次调用返回摘要，再次调用返回 None。
        """
        self.calls += 1
        self.keys.append(key)
        digest, self.digest = self.digest, None
        return digest
async def verify_generated_captcha():
    """
        在实际生成项目中证明对错、跨业务和跨用户提交均只有一次机会。

    :return: 无返回值；第二次提交即使答案和绑定正确也必须拒绝。
    """
    service, settings = CaptchaService(), get_settings()
    for issued_scene, issued_user, submitted_scene, submitted_user, answer, admitted in (
        (CaptchaScene.LOGIN, None, CaptchaScene.LOGIN, None, "abc23", True),
        (CaptchaScene.LOGIN, None, CaptchaScene.LOGIN, None, "wrong", False),
        (CaptchaScene.LOGIN, None, CaptchaScene.REGISTER, None, "ABC23", False),
        (CaptchaScene.USER_CHANGE_PASSWORD, "U123", CaptchaScene.USER_CHANGE_PASSWORD, "U456", "ABC23", False),
    ):
        captcha_id = uuid.uuid4()
        digest = service.hash_captcha_code(settings, captcha_id, "ABC23",
                                           scene=issued_scene, user_id=issued_user)
        assert len(digest) == 64 and all(letter in "0123456789abcdef" for letter in digest)
        redis = MemoryCaptchaRedis(digest)
        try:
            await service.verify_captcha(redis, settings, captcha_id=captcha_id, answer=answer,
                                         scene=submitted_scene, user_id=submitted_user)
        except AppError as error:
            assert not admitted and error.status_code == 400
        else:
            assert admitted
        assert redis.calls == 1 and redis.digest is None
        assert redis.keys == [f"captcha:{captcha_id}"]
        try:
            await service.verify_captcha(redis, settings, captcha_id=captcha_id, answer="ABC23",
                                         scene=issued_scene, user_id=issued_user)
        except AppError as error:
            assert error.status_code == 400
        else:
            raise AssertionError("Consumed CAPTCHA was accepted again")
        assert redis.keys == [f"captcha:{captcha_id}"] * 2
# 内存 GETDEL 不挂起协程；直接完成它，避免 Windows 事件循环创建内部 socket。
coroutine = verify_generated_captcha()
try:
    coroutine.send(None)
except StopIteration:
    pass
else:
    coroutine.close()
    raise AssertionError("Offline CAPTCHA verification unexpectedly suspended")
from fastapi import routing
from fastapi.routing import APIRoute
from app.dependencies.permission import require_permission
from app.dependencies.rate_limit import rate_limit_login, rate_limit_register
captcha_prerequisites = {
    "/api/v1/auth/login": rate_limit_login,
    "/api/v1/auth/register": rate_limit_register,
    "/api/v1/me/password/change": require_permission,
    "/api/v1/users/create": require_permission,
    "/api/v1/users/password/reset": require_permission,
}
iter_contexts = getattr(routing, "iter_route_contexts", None)
contexts = list(iter_contexts(app.routes)) if callable(iter_contexts) else app.routes
routes = {str(getattr(context, "path", getattr(context, "original_route", context).path)):
          getattr(context, "original_route", context) for context in contexts
          if isinstance(getattr(context, "original_route", context), APIRoute)}
for path, prerequisite in captcha_prerequisites.items():
    route = routes[path]
    dependency_names = [item.name for item in route.dependant.dependencies]
    first_check = "rate_limited" if path.startswith("/api/v1/auth/") else "context"
    assert dependency_names.index(first_check) < dependency_names.index("captcha_checked"), path
    captcha_check = next(item for item in route.dependant.dependencies if item.name == "captcha_checked")
    assert captcha_check.call.__module__ == "app.dependencies.captcha"
    assert captcha_check.call.__qualname__ == "require_captcha.<locals>.check_captcha"
    assert len(captcha_check.dependencies) == 1, path
    assert captcha_check.dependencies[0].call is get_settings, path
    prerequisite_nodes = []
    pending = [route.dependant]
    while pending:
        node = pending.pop()
        if node.call is prerequisite or (
            getattr(node.call, "__module__", None) == prerequisite.__module__
            and getattr(node.call, "__qualname__", "").startswith(f"{prerequisite.__qualname__}.<locals>.")
        ):
            prerequisite_nodes.append(node)
        pending.extend(node.dependencies)
    assert len(prerequisite_nodes) == 1, path
assert len(RbacAuditAction) == 12 and len(AccountAuditAction) == 5
assert RbacAuditAction.CREATE_ROLE.value == "role.create"
assert AccountAuditAction.ADMIN_RESET_PASSWORD.value == "account_security.password.admin_reset"
validate_audit_action("api.custom_write")
validate_audit_action("orders.confirm")
from inspect import signature
from sqlalchemy.exc import IntegrityError
from app.db.postgres_db import get_constraint_name
from app.services.user_service import UserService
assert not Path("app/services/user_create_service.py").exists()
assert callable(UserService.create_user) and callable(UserService.admin_create_user)
assert "user_id" not in signature(UserService.create_user).parameters
assert "request_id" not in signature(UserService.create_user).parameters
from app.services.auth_service import AuthService
from app.services.audit_service import AuditService
assert "request_id" not in signature(AuthService.register).parameters
assert "request_id" not in signature(AuditService.audit_success).parameters
assert "request_id" not in signature(AuditService.audit_denied).parameters
assert not any(hasattr(AuditService, name) for name in (
    "build_event", "response_snapshot", "write_denied_event", "write_client_denial",
))
assert "request_id" not in AuthorizationContext.__dataclass_fields__
driver_error = RuntimeError("offline constraint check")
driver_error.constraint_name = "uq_users_user_name"
integrity_error = IntegrityError(None, None, driver_error)
assert get_constraint_name(integrity_error) == "uq_users_user_name"
assert get_constraint_name(IntegrityError(None, None, RuntimeError("no structured name"))) is None
from fastapi import Request
from app.core.codes import BusinessCode
from app.core.i18n.messages import MessageKey, translate
from app.core.response import ApiResponse, PageResponse, ResponseBase, ValidationErrorItem, api_response
response_request = Request({"type": "http", "headers": []})
assert MessageKey.AUTH_REGISTER_SUCCEEDED.value == "auth.registration_succeeded"
assert "AUTH_REGISTRATION_SUCCEEDED" not in MessageKey.__members__
assert translate(response_request, MessageKey.AUTH_REGISTER_SUCCEEDED) == "注册成功"
english_request = Request({"type": "http", "headers": [(b"accept-language", b"en")]})
assert translate(english_request, MessageKey.AUTH_REGISTER_SUCCEEDED) == "Registration successful"
assert translate(response_request, MessageKey.ERROR_PASSWORD_LENGTH) == "密码长度须为 8～32 位"
assert translate(english_request, MessageKey.ERROR_PASSWORD_LENGTH) == "The password must be 8-32 characters long"
ordinary = api_response(response_request, message_key=MessageKey.COMMON_OPERATION_SUCCESS, data=None)
assert ordinary.code == 20000 and response_request.state.business_code == 20000
created = api_response(response_request, code=BusinessCode.CREATED,
                       message_key=MessageKey.COMMON_OPERATION_SUCCESS, data=None)
assert created.code == 20100 and response_request.state.business_code == 20100
assert ordinary.request_id == created.request_id
assert auth.RegisterRequest.__bases__ == (common.UsernameRequest, captcha.CaptchaAnswer)
assert user.UserCreateRequest.__bases__ == (common.UsernameRequest, captcha.CaptchaAnswer)
assert not any(hasattr(common, name) for name in (
    "ExistingPassword", "_validate_new_password_length",
))
password_fields = (
    (auth.RegisterRequest, "password", common.NewPassword), (auth.LoginRequest, "password", common.Password),
    (auth.PasswordChangeRequest, "current_password", common.Password),
    (auth.PasswordChangeRequest, "new_password", common.NewPassword),
    (user.UserCreateRequest, "password", common.NewPassword),
    (user.UserPasswordResetRequest, "new_password", common.NewPassword),
)
for model, field, contract in password_fields:
    assert get_type_hints(model, include_extras=True)[field] == contract
assert captcha.CaptchaCreateRequest.__bases__ == (common.RequestBase,)
assert user.ActiveSessionsResponse.__module__ == "app.schemas.user"
for module in (auth, captcha, common, permission, role, user):
    for name, model in vars(module).items():
        if not isinstance(model, type) or model.__module__ != module.__name__:
            continue
        if name.endswith("Request"):
            assert issubclass(model, common.RequestBase), name
        elif name.endswith("Response"):
            assert issubclass(model, ResponseBase), name
        else:
            continue
        assert model.model_config["extra"] == "forbid" and model.model_config["frozen"] is True, name
for model in (ApiResponse, PageResponse, ValidationErrorItem):
    assert issubclass(model, ResponseBase)
validate_v1_api_routes(app)
assert not Path("app/api/health.py").exists()
assert "readiness_timeout_seconds" not in type(get_settings()).model_fields
assert "READINESS_TIMEOUT_SECONDS" not in Path(".env.example").read_text(encoding="utf-8")
schema = app.openapi()
for create_path in ("/api/v1/auth/register", "/api/v1/users/create", "/api/v1/roles/create"):
    assert "201" in schema["paths"][create_path]["post"]["responses"]
assert all(path.startswith("/api/v1/") for path in schema["paths"])
register_fields = schema["components"]["schemas"]["RegisterRequest"]["properties"]
for model, field, contract in password_fields:
    password_field = schema["components"]["schemas"][model.__name__]["properties"][field]
    expected_bounds = (8, 32) if contract == common.NewPassword else (1, 1024)
    assert (password_field["minLength"], password_field["maxLength"]) == expected_bounds
    assert password_field["writeOnly"] is True
assert "/api/v1/auth/registration/detail" not in schema["paths"]
assert "/api/v1/auth/registration/update" not in schema["paths"]
assert "RegistrationStatusData" not in schema["components"]["schemas"]
from app.models.postgres.rbac_state import RbacState
assert set(RbacState.__table__.columns.keys()) == {"scope"}
for path, operations in schema["paths"].items():
    if path.startswith("/api/"):
        assert "{" not in path
        assert set(operations) <= {"get", "post"}
        if "get" in operations:
            assert path == "/api/v1/me/user_info" or path.endswith(("/list", "/detail"))
detail = schema["paths"]["/api/v1/roles/detail"]["get"]
assert any(item["name"] == "role_id" and item["in"] == "query" and item["required"]
           for item in detail["parameters"])
disable = schema["paths"]["/api/v1/users/disable"]["post"]
body = disable["requestBody"]
assert body["required"]
body_name = body["content"]["application/json"]["schema"]["$ref"].rsplit("/", 1)[-1]
assert "user_id" in schema["components"]["schemas"][body_name]["required"]
assert not any(item["in"] in {"path", "query"} for item in disable.get("parameters", []))
assert {file.stem for file in Path("app/api/v1/endpoints").glob("*.py")} == {
    "__init__", "auth", "me", "users", "roles", "permissions"
}
# 模拟维护者同时提高最短长度、降低最长长度，并像重启应用一样重新加载请求模型。
# 子进程只运行本用例，调整不会污染其他测试或访问数据库。
from importlib import reload
from pydantic import ValidationError
from app.core.security import password_rules as password_security
password_security.MIN_PASSWORD_CHARACTERS = 10
password_security.MAX_PASSWORD_CHARACTERS = 24
reload(common)
reload(auth)
reload(user)
challenge = {"captcha_id": uuid.uuid4(), "captcha_answer": "AB234"}
for old_password in ("Ab1!xyZ?", "Ab1!" + "x" * 28):
    login = auth.LoginRequest.model_validate({"user_name": "Alice", "password": old_password, **challenge})
    change = auth.PasswordChangeRequest.model_validate({
        "current_password": old_password, "new_password": "Safe-New-Password1!", **challenge,
    })
    assert login.password.get_secret_value() == old_password
    assert change.current_password.get_secret_value() == old_password
    assert password_security.validate_login_password_input(old_password) == old_password
    for model, field in ((auth.RegisterRequest, "password"), (auth.PasswordChangeRequest, "new_password"),
                         (user.UserCreateRequest, "password"), (user.UserPasswordResetRequest, "new_password")):
        payload = {**challenge, field: old_password}
        if "user_name" in model.model_fields:
            payload["user_name"] = "Alice"
        if "current_password" in model.model_fields:
            payload["current_password"] = "Current-password"
        if "user_id" in model.model_fields:
            payload["user_id"] = "UABCDEFGHIJKLMN"
        try:
            model.model_validate(payload)
        except ValidationError as error:
            assert [item["loc"] for item in error.errors()] == [(field,)]
        else:
            raise AssertionError(f"{model.__name__}.{field} ignored the updated new-password policy")
print(json.dumps({"service_name": get_settings().service_name,
                  "username_min": register_fields["user_name"]["minLength"],
                  "username_max": register_fields["user_name"]["maxLength"],
                  "password_min": register_fields["password"]["minLength"],
                  "password_max": register_fields["password"]["maxLength"],
                  "has_register": "/api/v1/auth/register" in schema["paths"]}))
''')
        self.assertEqual(json.loads(raw), {"service_name": "review-orders", "username_min": 3, "username_max": 32,
                                           "password_min": 8, "password_max": 32, "has_register": True})

    def test_generated_new_password_policy_rejects_each_missing_character_type(self) -> None:
        """真实生成后检查四类密码要求，非法值不算哈希，原有密码不追加新规则。"""
        target = self.create()
        self.run_python(target, '''
import uuid
from types import SimpleNamespace
from app.core.security import password_rules
from app.core.security.passwords import PasswordManager
from app.schemas.auth import LoginRequest, PasswordChangeRequest
from app.core.i18n.messages import MessageKey, translate_for_locale

missing_type_passwords = ("lowercase1!", "UPPERCASE1!", "MixedCase!!", "MixedCase12")
valid_password = "Valid-Pass9!"
manager = PasswordManager()
hashed_values = []
def hash_password(value):
    hashed_values.append(value)
    return "test-hash"
manager._hasher = SimpleNamespace(hash=hash_password)
async def run_hash(operation):
    return operation()
manager._run_bounded = run_hash

async def check_policy():
    for password in missing_type_passwords:
        try:
            await manager.hash_new_password(password)
        except password_rules.PasswordPolicyError as error:
            assert error.reason_code == "password_missing_character_types"
        else:
            raise AssertionError("a new password was accepted without every required character type")
    assert hashed_values == [], "invalid passwords reached the hash operation"
    assert await manager.hash_new_password(valid_password) == "test-hash"
    assert hashed_values == [valid_password]
    for old_password in ("legacy", "UPPERCASEONLY", "旧密码 含空格"):
        assert password_rules.validate_login_password_input(old_password) == old_password
        challenge = {"captcha_id": uuid.uuid4(), "captcha_answer": "AB234"}
        login = LoginRequest.model_validate({"user_name": "Alice", "password": old_password, **challenge})
        change = PasswordChangeRequest.model_validate({
            "current_password": old_password, "new_password": valid_password, **challenge,
        })
        assert login.password.get_secret_value() == old_password
        assert change.current_password.get_secret_value() == old_password
        assert await manager.hash_verified_password(old_password) == "test-hash"

# 内存替身不会挂起；直接完成协程，不创建 Windows 事件循环的内部 socket。
check = check_policy()
try:
    check.send(None)
except StopIteration:
    pass
else:
    check.close()
    raise AssertionError("offline password policy review unexpectedly suspended")
assert password_rules.PASSWORD_REQUIRED_CHARACTERS_ZH in password_rules.NEW_PASSWORD_DESCRIPTION_ZH
assert password_rules.PASSWORD_REQUIRED_CHARACTERS_ZH in translate_for_locale(
    "zh-CN", MessageKey.ERROR_PASSWORD_COMPOSITION)
assert password_rules.PASSWORD_REQUIRED_CHARACTERS_EN in translate_for_locale(
    "en", MessageKey.ERROR_PASSWORD_COMPOSITION)
''')

    def test_generated_project_saves_request_logs_to_project_directory(self) -> None:
        """
            在真实交付项目中启动应用，验证请求日志默认保存到项目自己的 logs 目录。
            连接工厂和连接池只用内存替身，继续禁止网络连接和数据库操作。

        :return: 无返回值；请求 ID、文件输出和退出清理均已断言。
        """
        target = self.create()
        raw = self.run_python(target, '''
import io
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch
from types import SimpleNamespace

from fastapi import Request

import app.main as main_module
from app.core.i18n.messages import MessageKey
from app.core.logging.output import LOG_ROOT_DIR
from app.core.middleware.request_logging import RequestLoggingMiddleware
from app.core.response import api_response

assert "APP_ENVIRONMENT" not in os.environ
assert "APP_ENVIRONMENT" not in Path(".env.example").read_text(encoding="utf-8")
assert "app_environment" not in type(main_module.get_settings()).model_fields

async def sample_app(scope, receive, send):
    """
        读取固定的管理员重置提交，发送脱敏日志需要观察的统一响应。

    :param scope: 当前测试请求的连接信息。
    :param receive: 未被此固定响应使用的请求读取函数。
    :param send: 中间件提供的响应发送函数。
    :return: 无返回值；200 响应已完整发送。
    """
    # 离线模拟已完成认证的管理员和服务成功结果，不调用实际认证、数据库或 Redis。
    await receive()
    scope["state"]["user_id"] = "U5N9B2LK7QR4X6D"
    # 使用真正的统一响应入口，不在路由重复登记动作、业务码或业务结果。
    content = api_response(Request(scope), message_key=MessageKey.AUTH_PASSWORD_RESET_SUCCEEDED,
                           data=None).model_dump(mode="json")
    await send({"type": "http.response.start", "status": 200,
                "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": json.dumps(content).encode()})

async def receive():
    """
        提供一份含新密码与验证码的有限 JSON 请求消息。

    :return: 固定的完整重置请求体，敏感值不得进入实际文件。
    """
    body = {"user_id": "U1N2B3LK7QR4X6D", "new_password": "Example-New-Pass7!",
            "captcha_id": "b445ed1a-0d52-401e-8c63-51d5d9669ae0", "captcha_answer": "A7XQ"}
    return {"type": "http.request", "body": json.dumps(body).encode(), "more_body": False}

async def check_request_file():
    """
        启动生成的应用，通过真实请求日志中间件发送一份固定响应。

    :return: 已核对文件日志的数量与本次请求 ID。
    """
    # 资源替身不连接任何服务；真实的日志配置、应用中间件和清理流程照常运行。
    redis_client = AsyncMock()
    engine = MagicMock()
    engine.dispose = AsyncMock()
    with patch.dict(os.environ, {"LOG_FILE_MAX_MB": "1"}):
        main_module.get_settings.cache_clear()
        settings = main_module.get_settings().model_copy(update={"rate_limit_redis_url": None})
    assert settings.log_file_max_mb == 1
    console = io.StringIO()
    messages = []

    async def send(message):
        """
            收集实际发送的响应消息，用来核对请求 ID 和响应结果。

        :param message: 中间件即将发送的 ASGI 响应消息。
        :return: 无返回值；响应消息已经收集。
        """
        messages.append(message)

    with patch.object(main_module, "engine", engine), \\
            patch.object(main_module, "create_redis_client", return_value=redis_client), \\
            patch.object(main_module, "get_settings", return_value=settings), \\
            patch("sys.stdout", console):
        async with main_module.lifespan(main_module.app):
            handlers = main_module.app.state.log_handlers
            assert handlers[1].max_file_bytes == 1024 * 1024
            log_key = settings.log_hmac_key.get_secret_value().encode("utf-8")
            configured = next(item for item in main_module.app.user_middleware
                              if item.cls is RequestLoggingMiddleware)
            assert configured.kwargs["log_hmac_key"] == log_key
            await RequestLoggingMiddleware(sample_app, log_hmac_key=log_key)({
                "type": "http", "method": "POST", "path": "/api/v1/users/password/reset",
                "query_string": b"password=never-save-this", "headers": [(b"content-type", b"application/json")],
                "route": SimpleNamespace(path="/api/v1/users/password/reset", name="reset_user_password"),
            }, receive, send)
            assert messages[0]["status"] == 200 and json.loads(messages[1]["body"])["data"] is None
        assert all(handler._closed for handler in handlers)
    # 默认目录根据项目源码确定；文件保留请求关联 ID，不保存查询字符串中的敏感值。
    assert LOG_ROOT_DIR == Path.cwd() / "logs"
    files = list(LOG_ROOT_DIR.glob("*/app.log"))
    assert len(files) == 1
    content = files[0].read_text(encoding="utf-8")
    events = [json.loads(line) for line in content.splitlines()]
    assert all({"service", "service_version", "environment", "target_type", "target_id"}.isdisjoint(event)
               for event in events)
    request_events = [event for event in events if event["event"] == "http.request.completed"]
    assert len(request_events) == 1
    response_request_id = dict(messages[0]["headers"])[b"x-request-id"].decode()
    assert request_events[0]["request_id"] == response_request_id
    assert request_events[0]["http_status_code"] == 200
    event = request_events[0]
    assert event["user_id"] == "U5N9B2LK7QR4X6D"
    assert event["target_user_id"] == "U1N2B3LK7QR4X6D"
    assert event["request_data"]["new_password"] == "[REDACTED]"
    assert len(event["password_fingerprint"]) == 32
    assert event["response_data"]["data"] is None
    assert event["response_data"]["message"] == "密码重置成功"
    assert event["action"] == "reset_user_password"
    assert event["operation_outcome"] == "success"
    assert all(item["timestamp"].endswith("+08:00") for item in events)
    assert event["timestamp"][:10] == files[0].parent.name
    for secret in ("never-save-this", "Example-New-Pass7!", "A7XQ", "b445ed1a-0d52-401e-8c63-51d5d9669ae0"):
        assert secret not in content
    assert [event["event"] for event in events] == [
        "application.started", "http.request.completed", "application.stopped",
    ]
    assert len(console.getvalue().splitlines()) == 3
    assert all(json.loads(line)["timestamp"].endswith("+08:00") for line in console.getvalue().splitlines())
    assert all({"service", "service_version", "environment"}.isdisjoint(json.loads(line))
               for line in console.getvalue().splitlines())
    redis_client.aclose.assert_awaited_once()
    engine.dispose.assert_awaited_once()
    return {"saved_request_events": len(request_events), "request_log": request_events[0]}

# 本检查的所有 await 都立即完成；直接驱动协程，避免 Windows 事件循环创建内部网络管道。
# 网络守卫保持开启；若意外出现需要调度器的异步工作，此检查会立即失败。
check = check_request_file()
try:
    check.send(None)
except StopIteration as completed:
    print(json.dumps(completed.value))
else:
    check.close()
    raise AssertionError("offline logging check unexpectedly suspended")
''')
        result = json.loads(raw)
        self.assertEqual(result["saved_request_events"], 1)
        self.assertEqual(result["request_log"]["event"],
                         "http.request.completed")

    def test_delivered_small_tests_run_without_database_or_redis(self) -> None:
        """
            直接运行使用者收到的小测试，检查未复制维护 conftest 后仍可独立使用。

        :return: 无返回值；附带测试在全部网络和 DDL 被拦截的进程中通过。
        """
        target = self.create()
        raw = self.run_python(target, '''
import pytest
raise SystemExit(pytest.main(["-q", "-p", "no:cacheprovider", "tests"]))
''')
        self.assertRegex(raw, r"\b[1-9]\d* passed\b")

    def test_generated_package_builds_offline_with_readme_and_both_locales(self) -> None:
        """
            实际构建生成项目，确认移除独立许可文件后依赖配置仍能正确打包。

        :return: 无返回值；包包含运行代码、双语资源和 README 来源说明，不替业务项目指定许可。
        """
        target = self.create()
        raw = self.run_python(target, '''
import json
import zipfile
from email import message_from_bytes
from setuptools.build_meta import build_wheel

wheel_directory = Path.cwd().parent / "wheelhouse"
wheel_directory.mkdir()
wheel_name = build_wheel(str(wheel_directory))
with zipfile.ZipFile(wheel_directory / wheel_name) as wheel:
    names = wheel.namelist()
    assert "app/main.py" in names, "Application entry point is missing from wheel"
    for locale in ("zh-CN", "en"):
        relative = f"app/assets/locales/{locale}.json"
        assert json.loads(wheel.read(relative)) == json.loads(Path(relative).read_text(encoding="utf-8")), relative
    assert not any(name.startswith(("tests/", "alembic/", "sql/", "app/commands/")) for name in names), names
    metadata_name = next(name for name in names if name.endswith(".dist-info/METADATA"))
    metadata = message_from_bytes(wheel.read(metadata_name))
    assert metadata["Name"] == "review-orders", metadata["Name"]
    assert metadata["Version"] == "0.1.0", metadata["Version"]
    assert metadata["Description-Content-Type"] == "text/markdown", metadata["Description-Content-Type"]
    assert all(metadata[field] is None for field in ("License", "License-Expression", "License-File")), metadata.items()
    description = metadata.get_payload(decode=True).decode("utf-8")
    assert Path("README.md").read_text(encoding="utf-8").strip().splitlines() == description.strip().splitlines(), (
        "README is not preserved")
print(json.dumps({"built": True}))
''')
        self.assertEqual(json.loads(raw.splitlines()[-1]), {"built": True})

    def test_project_identity_is_runtime_default_without_copying_example_environment(self) -> None:
        """
            用户未复制示例环境文件时，运行标识仍应反映明确选择。

        :return: 无返回值；应用标识与交付选项一致。
        """
        target = self.create()
        raw = self.run_python(target, '''
import json
from app.core.config import get_settings
settings = get_settings()
print(json.dumps({"name": settings.service_name, "version": settings.service_version}))
''')
        self.assertEqual(json.loads(raw), {
                         "name": "review-orders", "version": "0.1.0"})

    def test_history_rows_before_first_separator_are_not_copied(self) -> None:
        """
            模板旧记录即使误放在首条横线前，也不能带入新项目。

        :return: 无返回值；生成后只剩当天的新建记录，函数说明仍然保留。
        """
        source = ("# 说明:\n#    示例文件。\n# History:\n"
                  "# Date          Author    Version       Modification\n"
                  "# 2020/01/01    XTN       V1.002        错位旧记录\n"
                  f"{GENERATOR.HISTORY_SEPARATOR}\n"
                  "# 2019/01/01    XTN       V1.000        旧记录\n"
                  f"{GENERATOR.HISTORY_SEPARATOR}\n\n"
                  'def example():\n    """保留函数说明。"""\n    return None\n')
        generated = GENERATOR.document_file(
            Path("example.py"), source, author="项目作者", generated_on="2026/11/26",
        )
        rows = re.findall(r"^# (\d{4}/\d{2}/\d{2})\s+(\S+)\s+(V\d+\.\d{3})\s+(.+)$",
                          generated, re.MULTILINE)
        self.assertEqual(rows, [("2026/11/26", "项目作者", "V1.000", "新建")])
        self.assertIn('"""保留函数说明。"""', generated)
        self.assertEqual(generated.count("# Date          Author"), 1)

    def test_new_files_have_only_today_creation_and_keep_valid_data_formats(self) -> None:
        """
            新项目每个文件仅记录生成当天的新建，语言资源保持原格式。

        :return: 无返回值；文件职责说明只写一份，来源许可仍在 README，JSON 不增加元数据。
        """
        target = self.base / "documented-project"
        GENERATOR.create_project(target, name="documented-project", username_case="sensitive",
                                 max_sessions=3, author="项目作者")
        asset_root = SKILL_ROOT / "assets" / "postgresql-rbac"
        for path in target.rglob("*"):
            if not path.is_file():
                continue
            relative = path.relative_to(target)
            text = path.read_text(encoding="utf-8")
            if path.suffix == ".json":
                self.assertEqual(
                    text, (asset_root / relative).read_text(encoding="utf-8"))
                self.assertEqual(json.loads(text), json.loads(
                    (asset_root / relative).read_text(encoding="utf-8")))
                continue
            self.assertIn("说明:", text, relative)
            self.assertIn("History:", text, relative)
            rows = re.findall(r"^(?:# )?(\d{4}/\d{2}/\d{2})\s+(\S+)\s+(V\d+\.\d{3})\s+(.+)$",
                              text, re.MULTILINE)
            self.assertEqual(rows, [(date.today().strftime("%Y/%m/%d"), "项目作者", "V1.000", "新建")],
                             relative)
            self.assertEqual(text.count("说明:"), 1, relative)
            self.assertEqual(text.count("History:"), 1, relative)
            if path.suffix == ".py":
                self.assertTrue(text.startswith(
                    "#!/usr/bin/env python\n# -*- coding: utf-8 -*-\n"))
                self.assertIsNone(ast.get_docstring(ast.parse(text)), relative)
        readme = (target / "README.md").read_text(encoding="utf-8")
        self.assertIn(
            (asset_root / "LICENSE").read_text(encoding="utf-8").strip(), readme)
        notices = (
            asset_root / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
        upstream_mit = notices.split("### MIT License text", 1)[1].split(
            "## Alembic project templates", 1)[0].strip()
        self.assertIn(upstream_mit, readme)
        self.assertIn(
            "https://github.com/xtnkking/fastapi-templates-xtn", readme)
        self.assertIn("Copyright 2026 XTN", readme)
        self.assertIn("47a5dbc3f9c2661c6afb13638f80d4a4d4449040", readme)
        package_entry = (target / "app" /
                         "__init__.py").read_text(encoding="utf-8")
        self.assertIn("README.md", package_entry)
        tomllib.loads((target / "pyproject.toml").read_text(encoding="utf-8"))

    def test_generated_function_parameters_follow_signature_order(self) -> None:
        """
            核对交付代码的参数说明，避免读者在函数签名和注释间来回寻找。

        :return: 无返回值；缺失、过时或顺序错误的参数说明会使测试失败。
        """
        target = self.create()
        for path in (target / "app").rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                arguments = node.args
                declared = [argument.arg for argument in (
                    *arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs
                ) if argument.arg not in {"self", "cls"}]
                if arguments.vararg is not None:
                    declared.append(arguments.vararg.arg)
                if arguments.kwarg is not None:
                    declared.append(arguments.kwarg.arg)
                docstring = ast.get_docstring(node) or ""
                documented = re.findall(
                    r"^\s*:param\s+(\w+)\s*:", docstring, re.MULTILINE)
                self.assertEqual(
                    documented, declared,
                    f"{path.relative_to(target)}:{node.lineno} {node.name}",
                )

    def test_invalid_author_cannot_inject_code_or_comments(self) -> None:
        """
            拒绝带换行或注释结束标记的署名，避免文件头破坏交付代码和文档。

        :return: 无返回值；非法署名在创建目标目录前失败。
        """
        target = self.base / "invalid-author"
        for author in ("", "author\nmalicious", "-->", "a" * 65):
            with self.subTest(author=author), self.assertRaisesRegex(ValueError, "Author"):
                GENERATOR.create_project(target, name="review-orders", username_case="sensitive",
                                         max_sessions=3, author=author)
            self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
