#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    为操作员提供终端交互入口，给已有的唯一超级管理员重置密码。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/26    XTN       V1.001        文件名明确表示只重置超级管理员密码
# 2026/09/30    XTN       V1.002        线下恢复直接设置可登录密码
# 2026/10/02    XTN       V1.003        改用维护命令专属服务，不向新项目导出恢复流程
# 2026/10/10    XTN       V1.004        用户主键说明统一为 users.user_id
# 2026/10/13    XTN       V1.005        通俗说明维护命令的参数、隐藏输入与资源释放步骤
# 2026/10/16    XTN       V1.006        操作入口绑定一次关联 ID 并在连接池清理失败时仍恢复上下文
# --------------------------------------------------------------------------------------------------

"""为操作员提供终端交互入口，给已有的唯一超级管理员重置密码。"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys
import uuid

from app.commands.operator_password_service import OperatorPasswordService
from app.core.exceptions import AppError
from app.core.ids import require_entity_id
from app.core.logging.context import (
    bind_request_context,
    deactivate_request_context,
    reset_request_context,
)
from app.core.security.passwords import password_manager
from app.db.postgres_db import SessionFactory, engine


def _user_id(value: str) -> str:
    """
        校验命令行传入的 U 开头用户业务 ID。

    :param value: --user-id 参数传入的原始用户 ID 文本。
    :return: 可传给密码重置服务的用户 ID。
    :raises argparse.ArgumentTypeError: 格式无效。
    """
    # 用统一用户 ID 规则检查命令参数；错误转成命令行参数提示，还没开始数据库操作。
    try:
        return require_entity_id(value, "U")
    except ValueError as exc:
        raise argparse.ArgumentTypeError("user ID must be U plus 14 uppercase letters or digits") from exc


def _parser() -> argparse.ArgumentParser:
    """
        构造仅接受用户 ID 的命令行解析器，密码通过终端隐藏输入而非命令参数传入。

    :return: 已定义必填 --user-id 参数及其校验器的解析器。
    """
    # 只接受目标用户 ID，密码通过后面的隐藏输入读取，避免出现在命令历史和进程参数中。
    parser = argparse.ArgumentParser(
        description=(
            "Reset the password for the existing sole super administrator."
        )
    )
    parser.add_argument(
        "--user-id",
        required=True,
        type=_user_id,
        help="immutable users.user_id of the sole super administrator",
    )
    return parser


async def _run(user_id: str, new_password: str) -> None:
    """
        调用受约束的操作员恢复服务，并在成功或失败后释放数据库引擎连接池。

        此入口只处理已有的唯一超级管理员，不负责创建账号或绑定超级管理员角色。
        为本次操作生成并绑定一次关联 ID；资源释放即使失败，也清理和恢复原上下文。

    :param user_id: 需要恢复密码的现有超级管理员用户 ID。
    :param new_password: 操作员在本地终端输入并确认的新密码。
    :return: 无返回值，服务完成重置及资源清理后正常结束。
    :raises AppError: 目标账号状态、超级管理员身份或密码规则不符合要求。
    """
    # 1. 非 HTTP 入口在操作开始时绑定一次安全关联 ID，后续审计和日志复用它。
    context_token = bind_request_context(f"operator:{uuid.uuid4()}")
    try:
        # 2. 交给维护专用服务确认唯一超级管理员并重置密码，不绕过它的身份和密码规则。
        service = OperatorPasswordService(SessionFactory, password_manager)
        await service.reset_super_admin_password(
            user_id=user_id,
            new_password=new_password,
        )
    finally:
        try:
            # 3. 成功或失败都关闭该命令使用的数据库连接池，不留下后台连接。
            await engine.dispose()
        finally:
            # 4. 连接池关闭异常也必须使复制的上下文失效，再恢复本入口绑定前的上下文。
            deactivate_request_context()
            reset_request_context(context_token)


def main() -> int:
    """
        隐藏读取并二次确认新密码，执行超级管理员恢复并显示不含敏感数据的结果。

        此入口不创建账号或分配角色；成功后使用新密码直接登录。

    :return: 成功返回 0，业务重置失败返回 1，两次密码输入不一致返回 2。
    """
    # 1. 先检查目标用户 ID，再隐藏读取两遍密码；两次不同就结束，不访问数据库。
    args = _parser().parse_args()
    new_password = getpass.getpass("New password: ")
    confirmation = getpass.getpass("Repeat password: ")
    if new_password != confirmation:
        print("The two password entries do not match.", file=sys.stderr)
        return 2

    # 2. 执行异步重置；失败只给安全提示，不显示密码、连接地址或内部错误正文。
    try:
        asyncio.run(_run(args.user_id, new_password))
    except AppError:
        print(
            "Password reset failed. Check the user ID, account state, "
            "and password policy.",
            file=sys.stderr,
        )
        return 1
    # 3. 重置完成才显示成功；返回值供终端或脚本判断结果，0 表示成功。
    print(
        "Password reset. The account may now log in with the new password."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
