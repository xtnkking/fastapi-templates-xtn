#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    用户名相关配置和检查规则：统一维护长度、允许字符、保留名称和首尾空白处理。
#    修改用户名规则先看这里；请求参数、数据库模型和错误提示都引用这里的配置。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        说明保留用户名与大小写匹配边界，避免误当成系统角色
# 2026/10/13    XTN       V1.002        补充用户名输入契约和逐阶段校验说明
# 2026/10/20    XTN       V1.003        删除重复的字段名参数，直接校验用户名
# 2026/11/26    XTN       V1.004        集中用户名配置，供请求、查询、模型和提示共用
# 2026/11/26    XTN       V1.005        按用途扩充系统、官方、测试和常见开发技术保留名
# 2026/11/26    XTN       V1.006        拒绝保留名两侧附加数字或下划线的变体
# 2026/11/26    XTN       V1.007        用户名校验入口改为直观的 validate_user_name
# --------------------------------------------------------------------------------------------------


import re

# 用户名去掉首尾空白后，最少和最多允许多少个字符；不从 .env 读取。
MIN_USER_NAME_LENGTH = 3
MAX_USER_NAME_LENGTH = 32

# 方括号内允许的字符：A-Z 和 a-z 是英文字母，0-9 是数字，_ 是下划线。
# 调整允许字符时，同时修改下面两行说明，接口文档和中英文提示会直接引用。
USER_NAME_CHARACTERS = r"A-Za-z0-9_"
USER_NAME_CHARACTERS_ZH = "英文字母、数字或下划线"
USER_NAME_CHARACTERS_EN = "ASCII letters, digits or underscores"

# 根据上面的字符和长度自动拼出完整规则；请求校验和数据库约束不再各写一份。
USER_NAME_PATTERN = rf"^[{USER_NAME_CHARACTERS}]{{{MIN_USER_NAME_LENGTH},{MAX_USER_NAME_LENGTH}}}$"

# 项目保留的系统、官方、测试和技术名称，禁止用作用户名，包括真正的管理员。
# 增减名称只改这里，统一用小写填写；下面按用途分组，便于查找和维护。
# 忽略大小写检查原名，再去掉两侧数字和下划线检查一次；admin01、_admin_ 都不能使用。
# 中间的字母不移除，my_admin、admin_bob 等名称仍按完整名称检查。
# 这是用户名规则，不是角色名单；要管理权限应绑定角色，不能靠改用户名获取权限。
RESERVED_USER_NAMES = frozenset(
    {
        # 系统管理、基础用户和匿名身份名称。
        "admin",
        "admins",
        "administrator",
        "administrators",
        "root",
        "superadmin",
        "super_admin",
        "superuser",
        "sysadmin",
        "sys_admin",
        "system_admin",
        "system",
        "user",
        "guest",
        "anonymous",
        "nobody",
        # 官方、客服与安全支持名称。
        "support",
        "kefu",
        "service",
        "services",
        "official",
        "webmaster",
        "security",
        "help",
        "helpdesk",
        "customer_service",
        "customer_support",
        "contact",
        # 常见编程语言、运行平台和页面技术。
        "python",
        "python3",
        "java",
        "javascript",
        "typescript",
        "php",
        "golang",
        "ruby",
        "rust",
        "swift",
        "kotlin",
        "scala",
        "perl",
        "lua",
        "dart",
        "csharp",
        "cpp",
        "dotnet",
        "nodejs",
        "html",
        "css",
        "sql",
        # 常见后端、前端开发框架。
        "fastapi",
        "django",
        "flask",
        "tornado",
        "spring",
        "springboot",
        "laravel",
        "express",
        "nestjs",
        "react",
        "vue",
        "angular",
        # 数据、数据库、缓存和搜索服务。
        "data",
        "database",
        "dba",
        "mysql",
        "mariadb",
        "postgresql",
        "postgres",
        "redis",
        "mongodb",
        "sqlite",
        "mssql",
        "sqlserver",
        "oracle",
        "elasticsearch",
        "opensearch",
        "clickhouse",
        "memcached",
        "cassandra",
        # 服务入口、系统、部署和监控名称。
        "api",
        "backend",
        "frontend",
        "server",
        "nginx",
        "apache",
        "tomcat",
        "linux",
        "windows",
        "docker",
        "kubernetes",
        "k8s",
        "devops",
        "ops",
        "prometheus",
        "grafana",
        # 代码托管、自动构建和包管理工具。
        "git",
        "github",
        "gitlab",
        "gitea",
        "jenkins",
        "npm",
        "pip",
        "maven",
        "gradle",
        "composer",
        # 开发、测试、示例及默认占位名称。
        "test",
        "testing",
        "tester",
        "ceshi",
        "demo",
        "debug",
        "dev",
        "developer",
        "developers",
        "staging",
        "production",
        "prod",
        "sandbox",
        "example",
        "default",
        "null",
    }
)


def validate_user_name(value: str | None) -> str:
    """
        去掉用户名首尾空白并检查是否符合规则，保留实际大小写供项目策略处理。

    :param value: 待校验的用户名；None 表示缺失，长度、允许字符和保留名称按本文件配置检查。
    :return: 去掉首尾空白并通过全部检查的用户名。
    :raises ValueError: 用户名缺失、格式非法或属于保留名。
    """
    # 步骤 1：先拒绝缺失输入，避免把空值继续作为用户名使用。
    if value is None:
        raise ValueError("user_name is required")
    # 步骤 2：统一去掉首尾空白并检查字符和长度；中间空格、中文仍不合法。
    normalized = value.strip()
    if re.fullmatch(USER_NAME_PATTERN, normalized) is None:
        raise ValueError(
            f"user_name must be {MIN_USER_NAME_LENGTH}-{MAX_USER_NAME_LENGTH} {USER_NAME_CHARACTERS_EN}"
        )
    # 步骤 3：先忽略大小写检查原名，再去掉两侧数字和下划线检查一次，例如 admin01 变为 admin。
    # 这里只查内存中的集合，不遍历名单；check_name 仅用于检查，不修改实际保存的用户名。
    check_name = normalized.casefold()
    if check_name in RESERVED_USER_NAMES or check_name.strip("0123456789_") in RESERVED_USER_NAMES:
        raise ValueError("reserved_user_name")
    return normalized
