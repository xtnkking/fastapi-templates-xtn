#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 说明:
#    离线验证发布检查不会误报接口文档，也不会放过密码、字段约束或建表边界回归。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充维护记录及静态文档、严格字段约束的正反向验证
# 2026/09/23    XTN       V1.001        验证入口拆分后的模块装配、异常注册与健康探针安全边界
# 2026/09/26    XTN       V1.002        同步 auth/response 路径并校验认证入口的直接执行顺序
# 2026/09/26    XTN       V1.003        改用限流和路由校验的直接测试名称
# 2026/09/27    XTN       V1.004        对齐统一限流服务与验证码一次性消费名称
# 2026/09/29    XTN       V1.005        验证文档入口关闭、路由名称限流和认证依赖完整接线
# 2026/09/29    XTN       V1.006        删除默认健康探针校验，保留业务装配和禁止建表测试
# 2026/09/29    XTN       V1.007        路由接线校验同步 API 层公开与特殊认证规则
# 2026/09/29    XTN       V1.008        路由接线校验改读独立 v1 规则模块
# 2026/09/30    XTN       V1.009        校验独立权限依赖仍使用管理身份与限流入口
# 2026/10/02    XTN       V1.010        当前会话路由与简化语言协商须通过发布校验
# 2026/10/04    XTN       V1.011        路由名称校验跟随直接读取的限流策略入口
# 2026/10/08    XTN       V1.012        限流接线测试同步 Service 持有的策略构造
# 2026/10/08    XTN       V1.013        删除已移除的 Service 引用，对齐显式限流依赖
# 2026/10/09    XTN       V1.014        模型契约负向测试覆盖共用字段和验证码所属文件
# 2026/10/09    XTN       V1.015        核对账号审计枚举值与实际调用的正反向合同
# 2026/10/10    XTN       V1.016        验证普通和验证码额度均在查库前单次计数
# 2026/10/10    XTN       V1.017        限流接线合同统一使用 user_id 和当前用户名称
# 2026/10/10    XTN       V1.018        验证单一 Password 合同拒绝明文类型、长度漂移和重复校验
# 2026/10/12    XTN       V1.019        验证场景验证码依赖不可遗漏、改绑或绕过业务前置检查
# 2026/10/12    XTN       V1.020        验证码仅校验码字段，路由前置保护不可后移或内嵌
# 2026/10/12    XTN       V1.021        验证直接提取验证码字段和统一用户 ID 的依赖合同
# 2026/10/13    XTN       V1.022        验证单次 GETDEL 及业务、用户摘要绑定不可回退
# 2026/10/14    XTN       V1.023        验证码合同同步直接传枚举及摘要中的用途值
# 2026/10/14    XTN       V1.024        验证日志环境配置已取消且不会在运行设置和示例中恢复
# 2026/10/16    XTN       V1.025        验证审计读取当前上下文的共同入口不可遗漏
# 2026/10/16    XTN       V1.026        异常构造器名称统一标明固定 HTTP 状态
# 2026/10/16    XTN       V1.027        拒绝路由自行签发令牌和登录业务在锁内登记会话
# 2026/10/20    XTN       V1.028        校验新旧密码各自的字段约束及独立传输上限
# 2026/10/20    XTN       V1.029        验证直写认证依赖及账号读取前的单次限流
# 2026/10/20    XTN       V1.030        接线验证同步用户上下文及内部管理上下文名称
# 2026/10/20    XTN       V1.031        管理接线检查同步集中选择次数的限流参数
# 2026/10/22    XTN       V1.032        验证权限回调直接检查 Token、管理次数和当前账号
# 2026/10/22    XTN       V1.033        验证权限默认普通额度并传递业务所选额度
# 2026/10/22    XTN       V1.034        账号读取必须复用状态和登录版本检查后才加载权限
# 2026/10/22    XTN       V1.035        认证接线检查同步 check_current_user 并拒绝直接读取权限
# 2026/10/24    XTN       V1.036        验证码维护用例使用完整的三个私有场景名称
# 2026/11/26    XTN       V1.037        验证用户名字段不能脱离统一长度规则
# 2026/11/26    XTN       V1.038        验证历史结构说明与跨行禁令，拒绝实际新增多项目范围
# 2026/11/26    XTN       V1.039        验证密码四类必需字符不可遗漏且旧密码不得套用新规则
# 2026/11/27    XTN       V1.040        验证只能定义两个系统角色，拒绝恢复默认管理员及模型约束
# 2026/11/28    XTN       V1.041        权限展示目录及自动接口映射增加正向与变异检查
# --------------------------------------------------------------------------------------------------

"""离线检查发布校验器能接受当前合同，并拒绝密码泄露及自动迁移等回归。"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path
from unittest.mock import patch

import validate_release


class ReleaseContractTests(unittest.TestCase):
    """仅解析源码，不导入运行应用，不生成或执行任何迁移。"""

    @classmethod
    def setUpClass(cls) -> None:
        """读取本次维护的真实身份模型和应用入口，作为负向变体的基准。"""
        cls.authentication_schema = (validate_release.ASSET_ROOT / "app/schemas/auth.py").read_text(
            encoding="utf-8"
        )
        cls.user_schema = (validate_release.ASSET_ROOT /
                           "app/schemas/user.py").read_text(encoding="utf-8")
        cls.common_schema = (validate_release.ASSET_ROOT /
                             "app/schemas/common.py").read_text(encoding="utf-8")
        cls.password_rules = (validate_release.ASSET_ROOT /
                              "app/core/security/password_rules.py").read_text(encoding="utf-8")
        cls.password_manager = (validate_release.ASSET_ROOT /
                                "app/core/security/passwords.py").read_text(encoding="utf-8")
        cls.captcha_schema = (validate_release.ASSET_ROOT /
                              "app/schemas/captcha.py").read_text(encoding="utf-8")
        cls.schema = "\n".join((cls.common_schema, cls.captcha_schema,
                                cls.authentication_schema, cls.user_schema))
        cls.entrypoint = (validate_release.ASSET_ROOT /
                          "app/main.py").read_text(encoding="utf-8")
        cls.auth_routes = (validate_release.ASSET_ROOT /
                           "app/api/v1/endpoints/auth.py").read_text(encoding="utf-8")
        cls.me_routes = (validate_release.ASSET_ROOT /
                         "app/api/v1/endpoints/me.py").read_text(encoding="utf-8")
        cls.user_routes = (validate_release.ASSET_ROOT /
                           "app/api/v1/endpoints/users.py").read_text(encoding="utf-8")
        cls.captcha_dependency = (validate_release.ASSET_ROOT /
                                  "app/dependencies/captcha.py").read_text(encoding="utf-8")
        cls.captcha_service = (validate_release.ASSET_ROOT /
                               "app/services/captcha_service.py").read_text(encoding="utf-8")
        cls.exception_handlers = (validate_release.ASSET_ROOT / "app/core/exception_handlers.py").read_text(
            encoding="utf-8"
        )
        cls.role_schema = (validate_release.ASSET_ROOT /
                           "app/schemas/role.py").read_text(encoding="utf-8")
        cls.response_contract = (
            validate_release.ASSET_ROOT / "app/core/response.py").read_text(encoding="utf-8")
        cls.rate_limit_dependency = (
            validate_release.ASSET_ROOT / "app/dependencies/rate_limit.py"
        ).read_text(encoding="utf-8")
        cls.authorization_dependency = (
            validate_release.ASSET_ROOT / "app/dependencies/auth.py"
        ).read_text(encoding="utf-8")
        cls.permission_dependency = (
            validate_release.ASSET_ROOT / "app/dependencies/permission.py"
        ).read_text(encoding="utf-8")
        cls.route_validation = (
            validate_release.ASSET_ROOT / "app/core/route_validation.py"
        ).read_text(encoding="utf-8")
        cls.api_route_rules = (
            validate_release.ASSET_ROOT / "app/api/v1/route_validation.py"
        ).read_text(encoding="utf-8")

    def test_current_session_routes_and_language_contract_are_accepted(self) -> None:
        """
            用当前真实代码核对管理员会话路由和简化后的语言选择规则。

        :return: 无返回值；发布校验不再要求已经删除的接口或匹配函数。
        """
        errors: list[str] = []
        validate_release.validate_local_password_authentication(errors)
        validate_release.validate_api_internationalization(errors)
        self.assertEqual(errors, [])

    def test_system_role_catalog_accepts_two_defaults_and_rejects_admin_restore(self) -> None:
        """
            两个系统角色通过检查，恢复默认管理员的枚举、规格、权限或模型约束都要拒绝。

        :return: 无返回值；只替换内存里的读取内容，不修改真实角色代码。
        """
        errors: list[str] = []
        validate_release.validate_system_role_catalog(errors)
        self.assertEqual(errors, [])
        role_path = validate_release.ASSET_ROOT / "app/core/access/roles.py"
        model_path = validate_release.ASSET_ROOT / "app/models/postgres/role.py"
        read_text = Path.read_text
        role_source = read_text(role_path, encoding="utf-8")
        model_source = read_text(model_path, encoding="utf-8")
        variants = (
            (role_path, role_source.replace('    USER = "user"', '    ADMIN = "admin"\n    USER = "user"', 1)),
            (role_path, role_source + '\nADMIN_PERMISSION_KEYS = frozenset()\n'),
            (role_path, role_source.replace(
                "SYSTEM_ROLE_SPECS: dict[SystemRoleKey, SystemRoleSpec] = {",
                "SYSTEM_ROLE_SPECS: dict[SystemRoleKey, SystemRoleSpec] = {\n"
                "    'admin': SystemRoleSpec(key='admin', level=500, is_protected=False, "
                "is_super_admin=False, permissions=frozenset()),", 1)),
            (model_path, model_source.replace(
                "NOT is_system OR key IN ('super_admin', 'user')",
                "NOT is_system OR key IN ('super_admin', 'admin', 'user')", 1)),
            (model_path, model_source + '\nCheckConstraint("level = 500", name="admin_role_shape")\n'),
        )
        for target, changed_source in variants:
            with self.subTest(target=target, variant=changed_source[-80:]):
                self.assertNotEqual(changed_source, read_text(target, encoding="utf-8"))

                def read_variant(path: Path, *args: object, target_path: Path = target,
                                 content: str = changed_source, **kwargs: object) -> str:
                    """
                        返回本轮角色目录或模型变体，其他文件仍读取原文。

                    :param path: 校验器正在读取的源码路径。
                    :param args: 原读取函数的位置参数。
                    :param target_path: 本轮固定替换的角色定义或模型路径。
                    :param content: 本轮固定返回的源码变体。
                    :param kwargs: 原读取函数的编码等关键字参数。
                    :return: 目标文件的内存变体，或其他文件的原始内容。
                    """
                    # 不落盘，避免负向测试影响同时进行的业务测试。
                    return content if path == target_path else read_text(path, *args, **kwargs)

                errors = []
                with patch.object(Path, "read_text", autospec=True, side_effect=read_variant):
                    validate_release.validate_system_role_catalog(errors)
                self.assertTrue(any("system-role" in error for error in errors), errors)

    def test_permission_directory_accepts_current_source_and_rejects_missing_wiring(self) -> None:
        """
            当前权限目录通过检查，删掉元数据、响应字段或实际接口收集接线都会被发现。

        :return: 无返回值；变体只存在内存，不修改运行时源码或既有认证检查。
        """
        errors: list[str] = []
        validate_release.validate_permission_directory(errors)
        self.assertEqual(errors, [])
        read_text = Path.read_text
        variants = (
            ("metadata type", "app/core/access/permissions.py", "    group_key: PermissionGroup",
             "    group_key: str"),
            ("metadata entry", "app/core/access/permissions.py",
             "        name=MessageKey.PERMISSION_ACCOUNT_READ_NAME,\n", ""),
            ("group translation", "app/core/access/permissions.py",
             "    PermissionGroup.OTHER: MessageKey.PERMISSION_GROUP_OTHER,\n", ""),
            ("response name", "app/schemas/permission.py", "    name: str = Field(", "    title: str = Field("),
            ("response routes", "app/schemas/permission.py", "    api_routes: tuple[",
             "    endpoints: tuple["),
            ("route path", "app/schemas/permission.py", "    path: str = Field(", "    url: str = Field("),
            ("callback marker", "app/dependencies/permission.py",
             'setattr(dependency, "permission_key", required_key)',
             'setattr(dependency, "other_marker", required_key)'),
            ("callback key", "app/dependencies/permission.py",
             'setattr(dependency, "permission_key", required_key)',
             'setattr(dependency, "permission_key", "users:read")'),
            ("actual collection", "app/core/route_validation.py",
             "permission_api_routes.setdefault(permission_key, set()).add((method, path))", "pass"),
            ("collected return", "app/core/route_validation.py",
             "return {key: tuple(sorted(routes)) for key, routes in sorted(permission_api_routes.items())}",
             "return {}"),
            ("application map", "app/api/v1/route_validation.py",
             "app.state.permission_api_routes = permission_api_routes", "app.state.permission_api_routes = {}"),
            ("map storage", "app/api/v1/route_validation.py",
             "app.state.permission_api_routes = permission_api_routes",
             "app.state.other_routes = permission_api_routes"),
        )
        for label, relative, before, after in variants:
            target = validate_release.ASSET_ROOT / relative
            source = read_text(target, encoding="utf-8")
            self.assertIn(before, source, label)
            changed_source = source.replace(before, after, 1)
            with self.subTest(variant=label):
                def read_variant(path: Path, *args: str | None, target_path: Path = target,
                                 content: str = changed_source, **kwargs: str | None) -> str:
                    """
                        仅返回本轮权限目录变体，其他源码照常读取。

                    :param path: 校验器读取的文件路径。
                    :param args: 原读取操作的位置参数。
                    :param target_path: 本轮要替换的源码文件。
                    :param content: 本轮固定使用的变体文本。
                    :param kwargs: 编码等原读取选项。
                    :return: 目标变体或真实文件原文。
                    """
                    # 不落盘，防止负向验证干扰其他测试正在读取的源码。
                    return content if path == target_path else read_text(path, *args, **kwargs)

                errors = []
                with patch.object(Path, "read_text", autospec=True, side_effect=read_variant):
                    validate_release.validate_permission_directory(errors)
                self.assertTrue(any("permission directory" in error for error in errors), errors)

    def test_version_metadata_accepts_historical_schema_notes(self) -> None:
        """
            文档可以如实区分已发布版本与当前模型，不强迫它声称当前结构未变。

        :return: 无返回值；当前版本说明通过，删除版本标记仍会被拒绝。
        """
        errors: list[str] = []
        validate_release.validate_release_metadata(errors, release_ready=False)
        self.assertEqual(errors, [])
        read_text = Path.read_text
        target = validate_release.SKILL_ROOT / "references/migrations.md"

        def read_variant(path: Path, *args: object, **kwargs: object) -> str:
            """
                仅移除内存里的迁移文档版本号，实际文件保持原样。

            :param path: 校验器正在读取的文件。
            :param args: 原读取方法的位置参数。
            :param kwargs: 原读取方法的编码等命名参数。
            :return: 目标文档的无版本变体，或其他文件的原文。
            """
            content = read_text(path, *args, **kwargs)
            return content.replace(f"`{validate_release.RELEASE_TAG}`", "旧版本") if path == target else content

        errors = []
        with patch.object(Path, "read_text", autospec=True, side_effect=read_variant):
            validate_release.validate_release_metadata(errors, release_ready=False)
        self.assertTrue(any("migrations.md is missing current version marker" in error for error in errors), errors)

    def test_single_project_scope_distinguishes_wrapped_bans_from_new_scope(self) -> None:
        """
            换行的禁止清单应当通过，实际引入的多项目范围仍必须拒绝。

        :return: 无返回值；前一句、前一条列表或同文件中的禁令都不能掩盖后续新增范围。
        """
        read_text = Path.read_text
        target = validate_release.SKILL_ROOT / "SKILL.md"
        variants = (
            ("Do not silently add caches,\nmulti-tenancy or background systems.\n", False),
            ("禁止新增缓存、\n多租户或后台系统。\n", False),
            ("Add multi-tenancy.\n", True),
            ("No background jobs. Add multi-tenancy.\n", True),
            ("- No background jobs\n- Add multi-tenancy\n", True),
            ("Do not add multi-tenancy.\nAdd tenant_id to accounts.\n", True),
        )
        for text, rejected in variants:
            with self.subTest(text=text):
                def read_variant(path: Path, *args: object, content: str = text, **kwargs: object) -> str:
                    """
                        只替换入口文档的内存文本，其他真实文件照常检查。

                    :param path: 校验器正在读取的文件。
                    :param args: 原读取方法的位置参数。
                    :param content: 本轮测试的禁止清单或新增范围。
                    :param kwargs: 原读取方法的编码等命名参数。
                    :return: 入口文档变体，或其他文件的原文。
                    """
                    return content if path == target else read_text(path, *args, **kwargs)

                errors: list[str] = []
                with patch.object(Path, "read_text", autospec=True, side_effect=read_variant):
                    validate_release.validate_single_project_scope(errors)
                self.assertEqual(bool(errors), rejected, errors)

    def test_runtime_logging_environment_is_no_longer_required(self) -> None:
        """
            当前运行配置不要求环境标识，限流和验证码仍保持原有强制保护。

        :return: 无返回值；简化后的真实配置通过现有业务合同。
        """
        errors: list[str] = []
        validate_release.validate_rate_limiting_and_verification(errors)
        self.assertEqual(errors, [])

    def test_runtime_logging_environment_cannot_be_restored(self) -> None:
        """
            拒绝把已取消的环境标识重新加回 Settings 或示例配置。

        :return: 无返回值；内存变体被拒绝，测试夹具的环境保护不受影响。
        """
        read_text = Path.read_text
        variants = (
            ("app/core/config.py", "    app_environment: str = Field(default='development')\n",
             "retired app_environment logging field"),
            (".env.example", "APP_ENVIRONMENT=development\n",
             "retired APP_ENVIRONMENT logging setting"),
        )
        for relative, extra_line, expected_error in variants:
            with self.subTest(source=relative):
                target = validate_release.ASSET_ROOT / relative

                def read_variant(path: Path, *args: object,
                                 target_path: Path = target,
                                 added_line: str = extra_line,
                                 **kwargs: object) -> str:
                    """
                        只给本轮源码添加旧配置，实际仓库和测试服务保持不变。

                    :param path: 校验器正在读取的源码文件。
                    :param args: 原读取方法的位置参数。
                    :param target_path: 本轮需要构造回归的文件。
                    :param added_line: 需要恢复的旧字段或环境配置。
                    :param kwargs: 原读取方法的编码等命名参数。
                    :return: 指定文件的内存变体，或其他文件的原文。
                    """
                    content = read_text(path, *args, **kwargs)
                    # 字段插入 Settings 类；环境变量直接追加在示例文件末尾。
                    if path != target_path:
                        return content
                    if target_path.name == "config.py":
                        return content.replace("class Settings(BaseSettings):\n",
                                               f"class Settings(BaseSettings):\n{added_line}", 1)
                    return content + added_line

                errors: list[str] = []
                with patch.object(Path, "read_text", autospec=True, side_effect=read_variant):
                    validate_release.validate_rate_limiting_and_verification(
                        errors)
                self.assertTrue(
                    any(expected_error in error for error in errors), errors)

    def test_audit_request_id_context_entrypoint_is_required(self) -> None:
        """
            接受当前审计上下文入口，并拒绝删除该入口的源码变体。

        :return: 无返回值；校验器保留共同入口，测试不导入应用或连接服务。
        """
        errors: list[str] = []
        validate_release.validate_logging_and_audit(errors)
        self.assertEqual(errors, [])
        read_text = Path.read_text
        target = validate_release.ASSET_ROOT / "app/core/audit.py"
        marker = "def get_audit_request_id("
        self.assertIn(marker, read_text(target, encoding="utf-8"))

        def read_variant(path: Path, *args: object, **kwargs: object) -> str:
            """
                仅在内存中移除审计入口名称，保留真实仓库文件。

            :param path: 校验器正在读取的文件。
            :param args: 原读取方法的位置参数。
            :param kwargs: 原读取方法的编码等命名参数。
            :return: 审计模块的缺失入口变体，或其他文件的原文。
            """
            # 只改变目标定义名称，让静态检查确认共同入口不能丢失。
            content = read_text(path, *args, **kwargs)
            return content.replace(marker, "def removed_audit_request_id(", 1) if path == target else content

        errors = []
        with patch.object(Path, "read_text", autospec=True, side_effect=read_variant):
            validate_release.validate_logging_and_audit(errors)
        self.assertTrue(any(marker in error for error in errors), errors)

    def test_account_audit_actions_keep_catalog_and_business_calls(self) -> None:
        """
            接受集中定义的账号审计动作，拒绝动作值漂移或调用重新写死字符串。

        :return: 无返回值；校验器同时覆盖固定目录与实际业务引用。
        """
        errors: list[str] = []
        validate_release.validate_local_password_authentication(errors)
        self.assertEqual(errors, [])
        read_text = Path.read_text
        variants = (
            ("app/core/audit.py", 'ADMIN_RESET_PASSWORD = "account_security.password.admin_reset"',
             'ADMIN_RESET_PASSWORD = "account_security.password.reset"',
             "account-security audit catalog must retain ADMIN_RESET_PASSWORD"),
            ("app/services/user_service.py", "AccountAuditAction.ADMIN_CREATE_USER",
             '"account_security.registration.admin_created"',
             "user service must use AccountAuditAction.ADMIN_CREATE_USER"),
        )
        for relative, original, replacement, expected_error in variants:
            with self.subTest(source=relative):
                target = validate_release.ASSET_ROOT / relative

                def read_variant(path: Path, *args: object,
                                 target_path: Path = target,
                                 original_text: str = original,
                                 replacement_text: str = replacement,
                                 **kwargs: object) -> str:
                    """
                        只在内存中替换指定源码，避免修改仓库或访问任何运行服务。

                    :param path: 校验器正在读取的文件。
                    :param args: 原读取方法的位置参数。
                    :param target_path: 本轮需要替换的源码路径。
                    :param original_text: 待替换的原定义或调用。
                    :param replacement_text: 用于检查回归的变体。
                    :param kwargs: 原读取方法的编码等命名参数。
                    :return: 指定文件的变体或其他文件的原文。
                    """
                    content = read_text(path, *args, **kwargs)
                    return content.replace(original_text, replacement_text) if path == target_path else content

                errors = []
                with patch.object(Path, "read_text", autospec=True, side_effect=read_variant):
                    validate_release.validate_local_password_authentication(
                        errors)
                self.assertTrue(
                    any(expected_error in error for error in errors), errors)

    def test_multiline_field_contracts_keep_required_types_and_bounds(self) -> None:
        """
            中文说明和多行 Field 不应影响必填类型、严格整数或数量边界的检查。

        :return: 无返回值；断言当前真实模型通过同一发布校验。
        """
        errors: list[str] = []
        validate_release._validate_role_schema_contract(
            ast.parse(self.role_schema), errors)
        validate_release._validate_field_contract(
            ast.parse(self.response_contract), "ApiResponse", "code", "int",
            {"strict": "True", "ge": "10000", "le": "59999"}, errors,
        )
        self.assertEqual(errors, [])

    def test_each_role_version_must_keep_strict_integer_validation(self) -> None:
        """
            每一种角色请求都独立要求严格非负整数，不能用其他类的字段冒充。

        :return: 无返回值；断言去掉严格校验、放宽下界或改成字符串类型均被拒绝。
        """
        for class_name in ("RoleUpdateRequest", "RoleVersionRequest", "RolePermissionIdsRequest"):
            for mutation in ("strict", "ge", "annotation"):
                with self.subTest(model=class_name, mutation=mutation):
                    tree = ast.parse(self.role_schema)
                    model = validate_release._class_node(tree, class_name)
                    self.assertIsNotNone(model)
                    field = next(
                        node for node in model.body
                        if isinstance(node, ast.AnnAssign) and node.target.id == "expected_version"
                    )
                    if mutation == "annotation":
                        field.annotation = ast.Name(id="str", ctx=ast.Load())
                    else:
                        keyword = next(
                            item for item in field.value.keywords if item.arg == mutation)
                        keyword.value = ast.Constant(
                            value=False if mutation == "strict" else -1)
                    errors: list[str] = []
                    validate_release._validate_role_schema_contract(
                        tree, errors)
                    self.assertTrue(
                        any(f"{class_name}.expected_version" in error for error in errors), errors)

    def test_permission_batch_bounds_cannot_be_changed(self) -> None:
        """
            多行 Field 中的权限列表边界仍必须是 1～100 项。

        :return: 无返回值；断言放开空列表或扩大上限均被拒绝。
        """
        for name, invalid in (("min_length", 0), ("max_length", 101)):
            with self.subTest(bound=name):
                tree = ast.parse(self.role_schema)
                model = validate_release._class_node(
                    tree, "RolePermissionIdsRequest")
                field = next(
                    node for node in model.body
                    if isinstance(node, ast.AnnAssign) and node.target.id == "permission_ids"
                )
                keyword = next(
                    item for item in field.value.keywords if item.arg == name)
                keyword.value = ast.Constant(value=invalid)
                errors: list[str] = []
                validate_release._validate_role_schema_contract(tree, errors)
                self.assertTrue(
                    any(f"permission_ids must keep {name}" in error for error in errors), errors)

    def test_response_code_must_keep_strictness_and_requiredness(self) -> None:
        """
            响应业务码不能退化为宽松整数，或在省略字段时使用默认成功码。

        :return: 无返回值；断言错误严格值以及新增默认值被拒绝。
        """
        for mutation in ("strict", "default"):
            with self.subTest(mutation=mutation):
                tree = ast.parse(self.response_contract)
                model = validate_release._class_node(tree, "ApiResponse")
                field = next(
                    node for node in model.body
                    if isinstance(node, ast.AnnAssign) and node.target.id == "code"
                )
                if mutation == "strict":
                    keyword = next(
                        item for item in field.value.keywords if item.arg == "strict")
                    keyword.value = ast.Constant(value=1)
                else:
                    field.value.keywords.append(ast.keyword(
                        arg="default", value=ast.Constant(value=20000)))
                errors: list[str] = []
                validate_release._validate_field_contract(
                    tree, "ApiResponse", "code", "int",
                    {"strict": "True", "ge": "10000", "le": "59999"}, errors,
                )
                self.assertTrue(errors)

    def test_static_chinese_openapi_descriptions_are_allowed(self) -> None:
        """
            实际字段、查询参数、响应文档与角色 schema 回调中的中文说明不属于运行时文案。

        :return: 无返回值；断言各类静态文档位置均被准确识别。
        """
        sources = (
            self.authentication_schema,
            self.common_schema,
            self.captcha_schema,
            self.user_schema,
            self.role_schema,
            self.response_contract,
            'page: int = Query(default=1, ge=1, description="从 1 开始的页码。")',
        )
        for index, source in enumerate(sources):
            with self.subTest(source=index):
                errors: list[str] = []
                validate_release._validate_runtime_message_literals(
                    ast.parse(source), errors, label="example.py")
                self.assertEqual(errors, [])

    def test_chinese_runtime_values_are_not_hidden_by_documentation(self) -> None:
        """
            文档豁免只能覆盖说明值，不能放过同文件的错误响应、返回内容或默认运行值。

        :return: 无返回值；断言硬编码运行时中文仍由发布校验拒绝。
        """
        sources = (
            'def endpoint():\n    return {"message": "登录失败"}',
            'def endpoint():\n    raise ValueError("登录失败")',
            'name: str = Field(default="默认名称", description="名称说明")',
            'REQUEST_ID_OPENAPI_HEADER: dict = {"description": "字段说明", "message": "运行内容"}',
            'def _role_update_json_schema(schema):\n    return {"message": "运行内容"}',
            'def _role_update_json_schema(schema):\n    return {"description": "运行内容"}',
            'def endpoint():\n    return {"description": "运行内容"}',
        )
        for index, source in enumerate(sources):
            with self.subTest(source=index):
                errors: list[str] = []
                validate_release._validate_runtime_message_literals(
                    ast.parse(source), errors, label="example.py")
                self.assertTrue(
                    any("outside catalogs" in error for error in errors), errors)

    def test_username_character_label_does_not_exempt_other_runtime_text(self) -> None:
        """只允许用户名规则文件维护字符标签，其他文件或同文件的错误文案仍须使用翻译。"""
        label = "skills/fastapi-templates-xtn/assets/postgresql-rbac/app/core/security/user_name.py"
        source = 'USER_NAME_CHARACTERS_ZH = "英文字母、数字或下划线"\n'
        for path, text, accepted in (
            (label, source, True),
            ("example.py", source, False),
            (label, source + 'def endpoint():\n    raise ValueError("登录失败")', False),
        ):
            with self.subTest(path=path, accepted=accepted):
                errors: list[str] = []
                validate_release._validate_runtime_message_literals(ast.parse(text), errors, label=path)
                self.assertEqual(not errors, accepted)

    def test_current_secret_alias_and_input_contract_is_accepted(self) -> None:
        """保密类型别名不应再被旧的直接 SecretStr 字面检查误拒绝。"""
        errors: list[str] = []
        validate_release._validate_authentication_schema_contract(
            ast.parse(self.schema), errors)
        self.assertEqual(errors, [])

    def test_password_composition_cannot_drop_a_required_character_type(self) -> None:
        """删掉任一类字符要求时，维护校验必须拒绝，不能悄悄放松新密码规则。"""
        for index in range(4):
            with self.subTest(removed_type=index):
                tree = ast.parse(self.password_rules)
                character_rules = next(
                    node.value for node in tree.body if isinstance(node, (ast.Assign, ast.AnnAssign))
                    and any(isinstance(target, ast.Name) and target.id == "PASSWORD_REQUIRED_CHARACTERS"
                            for target in (node.targets if isinstance(node, ast.Assign) else (node.target,)))
                )
                character_rules.elts.pop(index)
                errors: list[str] = []
                validate_release._validate_password_policy_contract(
                    tree, ast.parse(self.password_manager), errors)
                self.assertTrue(any("must require uppercase" in item for item in errors), errors)

    def test_existing_password_verification_cannot_apply_new_password_policy(self) -> None:
        """登录和哈希升级误用新密码规则时必须拒绝，避免旧账号因策略升级无法登录。"""
        for method_name in ("verify_or_dummy", "hash_verified_password"):
            with self.subTest(method=method_name):
                tree = ast.parse(self.password_manager)
                manager = validate_release._class_node(tree, "PasswordManager")
                method = validate_release._function_node(manager.body, method_name)
                call = next(node for node in ast.walk(method) if isinstance(node, ast.Call)
                            and ast.unparse(node.func) == "validate_login_password_input")
                call.func = ast.Name(id="validate_new_password", ctx=ast.Load())
                errors: list[str] = []
                validate_release._validate_password_policy_contract(
                    ast.parse(self.password_rules), tree, errors)
                self.assertTrue(any(f"PasswordManager.{method_name}" in item for item in errors), errors)

    def test_password_rule_documentation_does_not_allow_arbitrary_runtime_chinese(self) -> None:
        """集中规则中的中文说明可交付，额外写死的中文接口错误仍必须拒绝。"""
        label = "skills/fastapi-templates-xtn/assets/postgresql-rbac/app/core/security/password_rules.py"
        for extra, accepted in (("", True), ('\ndef endpoint():\n    raise ValueError("登录失败")', False)):
            with self.subTest(accepted=accepted):
                errors: list[str] = []
                validate_release._validate_runtime_message_literals(
                    ast.parse(self.password_rules + extra), errors, label=label)
                self.assertEqual(not errors, accepted)

    def test_secret_alias_cannot_hide_plaintext_type(self) -> None:
        """把公共密码类型改为普通字符串时必须拒绝，避免默认展示密码原文。"""
        self.assertIn("    SecretStr,\n    Field(", self.schema)
        source = self.schema.replace(
            "    SecretStr,\n    Field(", "    str,\n    Field(", 1)
        errors: list[str] = []
        validate_release._validate_authentication_schema_contract(
            ast.parse(source), errors)
        self.assertTrue(any(
            "Password must remain an Annotated SecretStr" in item for item in errors), errors)

    def test_password_fields_must_use_their_existing_or_new_password_contract(self) -> None:
        """原密码和新密码字段都不能绕过各自的公共保密类型。"""
        for class_name, field_name in (
            ("RegisterRequest", "password"), ("LoginRequest", "password"),
            ("PasswordChangeRequest",
             "current_password"), ("PasswordChangeRequest", "new_password"),
            ("UserCreateRequest", "password"), ("UserPasswordResetRequest", "new_password"),
        ):
            with self.subTest(model=class_name, field=field_name):
                tree = ast.parse(self.schema)
                model = validate_release._class_node(tree, class_name)
                field = next(
                    item for item in model.body
                    if isinstance(item, ast.AnnAssign) and item.target.id == field_name
                )
                field.annotation = ast.Name(id="SecretStr", ctx=ast.Load())
                errors: list[str] = []
                validate_release._validate_authentication_schema_contract(
                    tree, errors)
                self.assertTrue(
                    any(f"{class_name}.{field_name}" in item for item in errors), errors)

    def test_password_bounds_must_use_their_runtime_constants(self) -> None:
        """新密码读取策略常量，旧密码仅使用非空和独立的传输上限。"""
        for name, constant, invalid in (
            ("min_length", "MIN_PASSWORD_CHARACTERS", "1"),
            ("max_length", "MAX_PASSWORD_CHARACTERS", "128"),
            ("min_length", "1", "MIN_PASSWORD_CHARACTERS"),
            ("max_length", "MAX_PASSWORD_INPUT_CHARACTERS", "MAX_PASSWORD_CHARACTERS"),
        ):
            with self.subTest(bound=name):
                source = self.schema.replace(
                    f"{name}={constant}", f"{name}={invalid}", 1)
                self.assertNotEqual(source, self.schema)
                errors: list[str] = []
                validate_release._validate_authentication_schema_contract(
                    ast.parse(source), errors)
                self.assertTrue(
                    any("bounds directly in Field" in item for item in errors), errors)

    def test_username_documentation_must_keep_real_character_and_length_rules(self) -> None:
        """用户名字段不能另写长度或字符规则，避免以后修改时各处不一致。"""
        for name, shared_rule, separate_rule in (
            ("min_length", "MIN_USER_NAME_LENGTH", "1"),
            ("max_length", "MAX_USER_NAME_LENGTH", "128"),
            ("pattern", "USER_NAME_PATTERN", 'r"^[A-Za-z]+$"'),
        ):
            with self.subTest(field=name):
                source = self.schema.replace(f"{name}={shared_rule},", f"{name}={separate_rule},", 1)
                self.assertNotEqual(source, self.schema)
                errors: list[str] = []
                validate_release._validate_authentication_schema_contract(
                    ast.parse(source), errors)
                self.assertTrue(
                    any("username OpenAPI contract" in item for item in errors), errors)

    def test_password_does_not_restore_duplicate_validators_or_documentation_bounds(self) -> None:
        """长度只由 Field 负责，不能混同两类密码、恢复旧别名或额外长度回调。"""
        for mutation in (
            "NewPassword = Password", "ExistingPassword = Password",
            "def _validate_new_password_length(value):\n    return value",
            "AfterValidator(_validate_new_password_length)", "json_schema_extra",
        ):
            with self.subTest(mutation=mutation):
                tree = ast.parse(self.schema)
                alias = next(item for item in tree.body if isinstance(item, ast.Assign)
                             and isinstance(item.targets[0], ast.Name) and item.targets[0].id == "Password")
                if mutation == "AfterValidator(_validate_new_password_length)":
                    alias.value.slice.elts.append(
                        ast.parse(mutation, mode="eval").body)
                elif mutation == "json_schema_extra":
                    alias.value.slice.elts[1].keywords.append(
                        ast.keyword(arg=mutation, value=ast.Dict(keys=[], values=[])))
                else:
                    tree.body.extend(ast.parse(mutation).body)
                errors: list[str] = []
                validate_release._validate_authentication_schema_contract(
                    tree, errors)
                self.assertTrue(
                    any("Password" in item or "password inputs" in item for item in errors), errors)

    def test_current_lifespan_and_business_routes_are_accepted(self) -> None:
        """当前先检查路由、只装配业务的入口符合交付边界。"""
        errors: list[str] = []
        validate_release._validate_runtime_entrypoint(
            ast.parse(self.entrypoint), errors)
        validate_release._validate_exception_handler_registration(
            ast.parse(self.exception_handlers), errors)
        self.assertEqual(errors, [])

    def test_documentation_routes_must_stay_disabled_by_default(self) -> None:
        """Swagger、ReDoc 或 OpenAPI 任一默认入口恢复时，发布校验都必须拒绝。"""
        for keyword, path in (
            ("docs_url", "/docs"),
            ("redoc_url", "/redoc"),
            ("openapi_url", "/openapi.json"),
        ):
            with self.subTest(keyword=keyword):
                source = self.entrypoint.replace(
                    f"    {keyword}=None,",
                    f'    {keyword}="{path}",',
                    1,
                )
                self.assertNotEqual(source, self.entrypoint)
                errors: list[str] = []
                validate_release._validate_runtime_entrypoint(
                    ast.parse(source), errors)
                self.assertTrue(
                    any("must disable docs_url" in error for error in errors),
                    errors,
                )

    def test_current_user_rate_limit_and_authorization_wiring_are_accepted(self) -> None:
        """当前路由名称分桶及认证依赖查库前单次计数应通过校验。"""
        errors: list[str] = []
        validate_release._validate_user_rate_limit_wiring(
            ast.parse(self.rate_limit_dependency),
            ast.parse(self.authorization_dependency),
            ast.parse(self.permission_dependency),
            ast.parse(self.route_validation),
            ast.parse(self.api_route_rules),
            errors,
        )
        self.assertEqual(errors, [])

    def test_current_user_load_cannot_skip_account_validation(self) -> None:
        """
            拒绝绕过账号状态及登录版本检查、直接读取权限的认证接线。

        :return: 无返回值；当前账号必须经过用户仓储的统一有效性检查。
        """
        source = self.authorization_dependency.replace(
            "user_repository.check_current_user(",
            "user_repository.get_user_permissions(",
            1,
        )
        self.assertNotEqual(source, self.authorization_dependency)
        errors: list[str] = []
        validate_release._validate_user_rate_limit_wiring(
            ast.parse(self.rate_limit_dependency),
            ast.parse(source),
            ast.parse(self.permission_dependency),
            ast.parse(self.route_validation),
            ast.parse(self.api_route_rules),
            errors,
        )
        self.assertTrue(any("current-user loading" in error for error in errors), errors)

    def test_user_quota_must_count_once_before_database_load(self) -> None:
        """
            拒绝计数移到查库后，或在普通、验证码入口重复计数的回归。

        :return: 无返回值；各错误接线均被现行合同校验拒绝。
        """
        for mutation in ("after_database", "double_ordinary", "double_captcha"):
            with self.subTest(mutation=mutation):
                tree = ast.parse(self.authorization_dependency)
                function_name = "get_captcha_user" if mutation == "double_captcha" else "get_current_user"
                context = validate_release._function_node(
                    tree.body, function_name)
                self.assertIsNotNone(context)
                assert context is not None
                quota_statement = next(
                    node for node in context.body
                    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Await)
                )
                if mutation == "after_database":
                    context.body.remove(quota_statement)
                    context.body.append(quota_statement)
                else:
                    context.body.insert(context.body.index(
                        quota_statement), quota_statement)
                errors: list[str] = []
                validate_release._validate_user_rate_limit_wiring(
                    ast.parse(self.rate_limit_dependency),
                    ast.parse(ast.unparse(tree)),
                    ast.parse(self.permission_dependency),
                    ast.parse(self.route_validation),
                    ast.parse(self.api_route_rules),
                    errors,
                )
                self.assertTrue(
                    any("count exactly once" in error for error in errors), errors)

    def test_user_rate_limit_must_use_matched_route_name(self) -> None:
        """限流键退回 OpenAPI operation_id 时必须拒绝。"""
        source = self.rate_limit_dependency.replace(
            'getattr(request.scope.get("route"), "name", None)',
            'getattr(request.scope.get("route"), "operation_id", None)',
            1,
        )
        self.assertNotEqual(source, self.rate_limit_dependency)
        errors: list[str] = []
        validate_release._validate_user_rate_limit_wiring(
            ast.parse(source),
            ast.parse(self.authorization_dependency),
            ast.parse(self.permission_dependency),
            ast.parse(self.route_validation),
            ast.parse(self.api_route_rules),
            errors,
        )
        self.assertTrue(
            any("route and user_id key parts" in error for error in errors), errors)

    def test_authenticated_rate_limit_dependencies_cannot_be_incomplete(self) -> None:
        """权限回调不能忽略业务选择，验证码认证依赖不能误用普通额度。"""
        mutations = (
            (
                "permission",
                'await rate_limit_user(request, login_info, settings, management=management)',
                'await rate_limit_user(request, login_info, settings)',
                "require_permission",
            ),
            (
                "auth",
                'await rate_limit_private_captcha(request, login_info, settings, scene=scene)',
                'await rate_limit_user(request, login_info, settings)',
                "get_captcha_user",
            ),
        )
        for owner, original, replacement, dependency_name in mutations:
            with self.subTest(dependency=dependency_name):
                original_source = (
                    self.permission_dependency if owner == "permission" else self.authorization_dependency
                )
                source = original_source.replace(original, replacement, 1)
                self.assertNotEqual(source, original_source)
                errors: list[str] = []
                validate_release._validate_user_rate_limit_wiring(
                    ast.parse(self.rate_limit_dependency),
                    ast.parse(source if owner == "auth" else self.authorization_dependency),
                    ast.parse(source if owner == "permission" else self.permission_dependency),
                    ast.parse(self.route_validation),
                    ast.parse(self.api_route_rules),
                    errors,
                )
                self.assertTrue(
                    any(dependency_name in error for error in errors), errors)

    def test_permission_dependency_cannot_assume_management_quota(self) -> None:
        """权限工厂不能默认管理额度，也不能忽略路由选择而固定使用管理额度。"""
        for original, replacement in (
            ("management: bool = False", "management: bool = True"),
            ("management=management", "management=True"),
        ):
            with self.subTest(replacement=replacement):
                source = self.permission_dependency.replace(original, replacement, 1)
                self.assertNotEqual(source, self.permission_dependency)
                errors: list[str] = []
                validate_release._validate_user_rate_limit_wiring(
                    ast.parse(self.rate_limit_dependency),
                    ast.parse(self.authorization_dependency),
                    ast.parse(source),
                    ast.parse(self.route_validation),
                    ast.parse(self.api_route_rules),
                    errors,
                )
                self.assertTrue(any("require_permission" in error for error in errors), errors)

    def test_api_route_rules_must_pass_special_authentication_rules(self) -> None:
        """
            验证 v1 校验模块不能遗漏退出登录和本人验证码的特殊认证规则。

        :return: 无返回值；传入空规则时发布校验必须拒绝。
        """
        source = self.api_route_rules.replace(
            "special_routes=_SPECIAL_ROUTES,", "special_routes={},", 1
        )
        self.assertNotEqual(source, self.api_route_rules)
        errors: list[str] = []
        validate_release._validate_user_rate_limit_wiring(
            ast.parse(self.rate_limit_dependency),
            ast.parse(self.authorization_dependency),
            ast.parse(self.permission_dependency),
            ast.parse(self.route_validation),
            ast.parse(source),
            errors,
        )
        self.assertTrue(
            any("API route rules must supply" in error for error in errors), errors
        )

    def test_permission_dependency_requires_token_and_shared_account_checks(self) -> None:
        """
            防止管理权限检查绕过账号核验和管理接口限流。

        :return: 无返回值；漏检 Token、账号或重复、后置管理限流均被拒绝。
        """
        for mutation in ("wrong_token_dependency", "missing_account_load", "quota_after_database", "double_quota"):
            with self.subTest(mutation=mutation):
                tree = ast.parse(self.permission_dependency)
                factory = validate_release._function_node(tree.body, "require_permission")
                assert factory is not None
                dependency = validate_release._function_node(factory.body, "dependency")
                assert dependency is not None
                quota = next(
                    node for node in dependency.body
                    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Await)
                )
                account_load = next(node for node in dependency.body if isinstance(node, ast.Assign))
                if mutation == "wrong_token_dependency":
                    source = ast.unparse(tree).replace(
                        "Depends(auth.check_token)", "Depends(auth.get_current_user)", 1
                    )
                else:
                    if mutation == "missing_account_load":
                        dependency.body.remove(account_load)
                    elif mutation == "quota_after_database":
                        dependency.body.remove(quota)
                        dependency.body.insert(dependency.body.index(account_load) + 1, quota)
                    else:
                        dependency.body.insert(dependency.body.index(quota), quota)
                    source = ast.unparse(tree)
                errors: list[str] = []
                validate_release._validate_user_rate_limit_wiring(
                    ast.parse(self.rate_limit_dependency),
                    ast.parse(self.authorization_dependency),
                    ast.parse(source),
                    ast.parse(self.route_validation),
                    ast.parse(self.api_route_rules),
                    errors,
                )
                self.assertTrue(any("require_permission" in error for error in errors), errors)

    def test_authentication_captcha_dependencies_are_accepted(self) -> None:
        """
            认证接口通过显式依赖先完成限流及验证码检查，再执行认证业务。

        :return: 无返回值；断言当前登录、注册入口保留原有执行边界。
        """
        errors: list[str] = []
        validate_release._validate_auth_entry_order(
            ast.parse(self.auth_routes), errors)
        self.assertEqual(errors, [])

    def test_authentication_cannot_skip_limit_or_change_captcha_scene(self) -> None:
        """
            登录不能遗漏实际限流依赖、删除验证码依赖或借用注册验证码。

        :return: 无返回值；遗漏或改绑依赖均被拒绝。
        """
        mutations = (
            ("Depends(rate_limit_login)", "Depends(omitted_rate_limit_login)"),
            ("Depends(require_captcha(CaptchaScene.LOGIN))",
             "Depends(omitted_captcha)"),
            ("Depends(require_captcha(CaptchaScene.LOGIN))",
             "Depends(require_captcha(CaptchaScene.REGISTER))"),
        )
        for original, replacement in mutations:
            with self.subTest(original=original, replacement=replacement):
                source = self.auth_routes.replace(
                    original, replacement, 1,
                )
                self.assertNotEqual(source, self.auth_routes)
                errors: list[str] = []
                validate_release._validate_auth_entry_order(
                    ast.parse(source), errors)
                self.assertTrue(
                    any("login must" in error for error in errors), errors)

    def test_login_route_cannot_issue_token_itself(self) -> None:
        """
            防止登录又拆成路由先调业务、再自行签发令牌。

        :return: 无返回值；内存中添加的路由签发调用必须被拒绝。
        """
        tree = ast.parse(self.auth_routes)
        login = validate_release._function_node(tree.body, "login")
        self.assertIsNotNone(login)
        assert login is not None
        login.body.append(ast.Expr(value=ast.Await(value=ast.Call(
            func=ast.Name(id="issue_access_token", ctx=ast.Load()), args=[], keywords=[],
        ))))
        errors: list[str] = []
        validate_release._validate_auth_entry_order(
            ast.fix_missing_locations(tree), errors)
        self.assertTrue(
            any("route must leave Token issuance" in error for error in errors), errors)

    def test_login_service_cannot_omit_issuer_or_call_it_inside_context(self) -> None:
        """
            完整登录必须登记会话，且不能拿着数据库连接和锁等待 Redis。

        :return: 无返回值；删除签发或移进上下文的两个内存变体都被拒绝。
        """
        read_text = Path.read_text
        target = validate_release.ASSET_ROOT / "app/services/auth_service.py"
        source = read_text(target, encoding="utf-8")
        for mutation, expected_error in (
            ("omit", "must await its Token issuer exactly once"),
            ("context", "must issue the Token after leaving database contexts"),
        ):
            with self.subTest(mutation=mutation):
                tree = ast.parse(source)
                service = validate_release._class_node(tree, "AuthService")
                assert service is not None
                login = validate_release._function_node(service.body, "login")
                assert login is not None
                statement = next(
                    node for node in login.body
                    if any(isinstance(child, ast.Call) and ast.unparse(child.func) == "self.issue_access_token"
                           for child in ast.walk(node))
                )
                if mutation == "omit":
                    call = next(child for child in ast.walk(statement)
                                if isinstance(child, ast.Call) and ast.unparse(child.func) == "self.issue_access_token")
                    call.func = ast.Name(id="omitted_issuer", ctx=ast.Load())
                else:
                    position = login.body.index(statement)
                    login.body[position] = ast.AsyncWith(
                        items=[ast.withitem(context_expr=ast.Call(
                            func=ast.Name(id="database_context", ctx=ast.Load()), args=[], keywords=[],
                        ))], body=[statement],
                    )
                changed_source = ast.unparse(ast.fix_missing_locations(tree))

                def read_variant(path: Path, *args: object, content: str = changed_source,
                                 **kwargs: object) -> str:
                    """
                        只替换本轮登录服务的读取结果，不写入磁盘。

                    :param path: 校验器正在读取的路径。
                    :param args: 原读取方法的位置参数。
                    :param content: 固定本轮已经构造好的服务源码变体。
                    :param kwargs: 原读取方法的编码等关键字参数。
                    :return: 登录服务的内存变体，其他文件返回原文。
                    """
                    # 只改目标文件，让其他真实合同继续由校验器读取。
                    return content if path == target else read_text(path, *args, **kwargs)

                errors = []
                with patch.object(Path, "read_text", autospec=True, side_effect=read_variant):
                    validate_release.validate_local_password_authentication(
                        errors)
                self.assertTrue(
                    any(expected_error in error for error in errors), errors)

    def test_captcha_getdel_and_digest_bindings_are_accepted(self) -> None:
        """
            当前验证码服务一次作废后再比较摘要，用途和用户共同参与绑定。

        :return: 无返回值；源码合同无需启动 Redis 即可通过。
        """
        errors: list[str] = []
        validate_release._validate_captcha_service_consumption(
            ast.parse(self.captcha_service), errors)
        self.assertEqual(errors, [])

    def test_captcha_cannot_restore_retry_or_drop_digest_bindings(self) -> None:
        """
            防止消费回退为只读 GET，或从签发、校验及摘要输入中丢失业务和用户。

        :return: 无返回值；各个内存源码变体均被现行合同拒绝。
        """
        mutations = (
            ("redis.getdel(redis_key)", "redis.get(redis_key)", "one GETDEL"),
            ("scene=scene, user_id=user_id",
             "scene=scene", "bind scene and user_id"),
            ('[scene.value, user_id or "", str(captcha_id), answer.upper()]',
             '[str(captcha_id), answer.upper()]', "encode scene, user_id"),
        )
        for original, replacement, expected_error in mutations:
            with self.subTest(original=original):
                source = self.captcha_service.replace(original, replacement)
                self.assertNotEqual(source, self.captcha_service)
                errors: list[str] = []
                validate_release._validate_captcha_service_consumption(
                    ast.parse(source), errors)
                self.assertTrue(
                    any(expected_error in error for error in errors), errors)

    def test_captcha_route_order_fields_and_scenes_are_accepted(self) -> None:
        """
            验证五个真实接口先声明前置保护，验证码依赖仅处理本职字段。

        :return: 无返回值；不导入应用或执行任何请求。
        """
        errors: list[str] = []
        validate_release._validate_captcha_dependency_wiring(
            ast.parse(self.captcha_dependency),
            {"auth": ast.parse(self.auth_routes), "me": ast.parse(self.me_routes),
             "users": ast.parse(self.user_routes)}, errors,
        )
        self.assertEqual(errors, [])

    def test_captcha_dependency_cannot_embed_business_checks_or_skip_user_id(self) -> None:
        """
            防止验证码依赖重新调度业务模型和限流，或使用请求方伪造的所属用户。

        :return: 无返回值；逐个内存变体必须被对应合同拒绝。
        """
        mutations = (
            ("from app.core.captcha import CaptchaScene",
             "from app.core.captcha import CaptchaScene\nfrom app.schemas.auth import LoginRequest",
             "must not import business models"),
            ("from app.dependencies.auth import AppSettings",
             "from app.dependencies.auth import AppSettings\nfrom app.dependencies.rate_limit import rate_limit_login",
             "must not import business models"),
            ("async def check_captcha(request: Request, settings: AppSettings",
             "async def check_captcha(request: Request, settings: AppSettings, embedded=Depends(rate_limit_login)",
             "must not embed business prerequisites"),
            ('read_body_field(body, "captcha_answer")', 'body.get("captcha_answer")',
             "CAPTCHA fields before one verification"),
            ("getattr(request.state, \"user_id\", None)",
             "body.get(\"user_id\")", "trusted request state"),
            ("raise unauthenticated_401(\"missing_captcha_user\")",
             "return", "trusted request state"),
            ("scene=scene", "scene=body.scene", "fixed scene"),
            ("user_id=user_id", "owner_id=user_id", "trusted request state"),
        )
        for original, replacement, expected_error in mutations:
            with self.subTest(original=original):
                source = self.captcha_dependency.replace(
                    original, replacement, 1)
                self.assertNotEqual(source, self.captcha_dependency)
                errors: list[str] = []
                validate_release._validate_captcha_dependency_wiring(
                    ast.parse(source),
                    {"auth": ast.parse(self.auth_routes), "me": ast.parse(self.me_routes),
                     "users": ast.parse(self.user_routes)}, errors,
                )
                self.assertTrue(
                    any(expected_error in error for error in errors), errors)

    def test_captcha_route_prerequisites_cannot_follow_verification(self) -> None:
        """
            登录限流和管理员权限必须在验证码之前执行，不能因排版调整而后移。

        :return: 无返回值；调换前置保护与验证码参数的内存变体必须被拒绝。
        """
        for module, function_name, prerequisite in (
            ("auth", "login", "rate_limited"), ("auth", "register", "rate_limited"),
            ("me", "change_my_password",
             "context"), ("users", "create_user", "context"),
            ("users", "reset_user_password", "context"),
        ):
            with self.subTest(function=function_name):
                trees = {"auth": ast.parse(self.auth_routes), "me": ast.parse(self.me_routes),
                         "users": ast.parse(self.user_routes)}
                function = validate_release._function_node(
                    trees[module].body, function_name)
                self.assertIsNotNone(function)
                assert function is not None
                arguments = function.args.args
                previous = next(index for index, item in enumerate(
                    arguments) if item.arg == prerequisite)
                captcha = next(index for index, item in enumerate(
                    arguments) if item.arg == "captcha_checked")
                arguments[previous], arguments[captcha] = arguments[captcha], arguments[previous]
                errors: list[str] = []
                validate_release._validate_captcha_dependency_wiring(
                    ast.parse(self.captcha_dependency), trees, errors)
                self.assertTrue(
                    any("route prerequisite before CAPTCHA" in error for error in errors), errors)

    def test_private_actions_cannot_skip_their_captcha_dependency(self) -> None:
        """
            管理员新增、重置和本人改密均不能漏掉验证码依赖。

        :return: 无返回值；删除任一个私有场景声明都必须被拒绝。
        """
        for scene, module in (("USER_CHANGE_PASSWORD", "me"), ("ADMIN_CREATE_USER", "users"),
                              ("ADMIN_RESET_USER_PASSWORD", "users")):
            with self.subTest(scene=scene):
                routes = {
                    name: ast.unparse(ast.parse(source))
                    for name, source in {
                        "auth": self.auth_routes, "me": self.me_routes, "users": self.user_routes,
                    }.items()
                }
                original_source = routes[module]
                original = f"Depends(require_captcha(CaptchaScene.{scene}))"
                routes[module] = routes[module].replace(
                    original, "Depends(omitted_captcha)", 1)
                self.assertNotEqual(routes[module], original_source)
                errors: list[str] = []
                validate_release._validate_captcha_dependency_wiring(
                    ast.parse(self.captcha_dependency),
                    {name: ast.parse(source)
                     for name, source in routes.items()}, errors,
                )
                self.assertTrue(
                    any("fixed-scene CAPTCHA dependency" in error for error in errors), errors)

    def test_extracted_modules_must_be_assembled(self) -> None:
        """
            实现被移到独立模块后，入口仍必须实际挂载路由、中间件和异常处理。

        :return: 无返回值；断言删除任一种装配调用都被识别。
        """
        entrypoint = ast.unparse(ast.parse(self.entrypoint))
        for call in (
            "register_exception_handlers(app)",
            "app.add_middleware(\n"
            "    RequestBodyLimitMiddleware,\n"
            "    max_body_bytes=settings.request_body_max_bytes,\n"
            ")",
            "app.add_middleware(SecurityHeadersMiddleware)",
            "app.add_middleware(RequestLoggingMiddleware, "
            "log_hmac_key=settings.log_hmac_key.get_secret_value().encode('utf-8'))",
            "app.include_router(v1_router)",
        ):
            with self.subTest(call=call):
                normalized_call = ast.unparse(
                    ast.parse(call).body[0].value  # type: ignore[attr-defined]
                )
                source = entrypoint.replace(normalized_call, "pass", 1)
                self.assertNotEqual(source, entrypoint)
                errors: list[str] = []
                validate_release._validate_runtime_entrypoint(
                    ast.parse(source), errors)
                self.assertTrue(
                    any(
                        f"must assemble {normalized_call}" in error
                        for error in errors
                    ),
                    errors,
                )

    def test_each_exception_registration_must_keep_its_handler(self) -> None:
        """
            入口调用统一注册函数后，每种异常仍要绑定到对应的已有处理函数。

        :return: 无返回值；断言缺少限流处理或错误转发数据库异常均会失败。
        """
        for original, replacement in (
            (
                "app.exception_handler(RateLimitExceeded)(handle_rate_limit_exceeded)",
                "pass",
            ),
            (
                "app.exception_handler(DatabaseUnavailableError)(handle_database_unavailable)",
                "app.exception_handler(DatabaseUnavailableError)(handle_unexpected_error)",
            ),
        ):
            with self.subTest(registration=original):
                source = self.exception_handlers.replace(
                    original, replacement, 1)
                self.assertNotEqual(source, self.exception_handlers)
                errors: list[str] = []
                validate_release._validate_exception_handler_registration(
                    ast.parse(source), errors)
                self.assertTrue(
                    any("exception registration must bind" in error for error in errors), errors)

    def test_route_validation_must_precede_resource_work(self) -> None:
        """把路由检查挪到资源建立之后必须被发布校验发现。"""
        source = self.entrypoint.replace(
            "    validate_v1_api_routes(app)",
            "    create_redis_client(get_settings())\n    validate_v1_api_routes(app)", 1,
        )
        self.assertNotEqual(source, self.entrypoint)
        errors: list[str] = []
        validate_release._validate_runtime_entrypoint(
            ast.parse(source), errors)
        self.assertTrue(
            any("before creating any resources" in item for item in errors), errors)

    def test_runtime_cannot_automatically_create_tables(self) -> None:
        """应用启动出现自动建表调用时必须拒绝；这里只解析，绝不执行。"""
        source = self.entrypoint.replace(
            "    validate_v1_api_routes(app)", "    validate_v1_api_routes(app)\n    Base.metadata.create_all()", 1
        )
        errors: list[str] = []
        validate_release._validate_runtime_entrypoint(
            ast.parse(source), errors)
        self.assertTrue(
            any("must not create tables" in item for item in errors), errors)


if __name__ == "__main__":
    unittest.main()
