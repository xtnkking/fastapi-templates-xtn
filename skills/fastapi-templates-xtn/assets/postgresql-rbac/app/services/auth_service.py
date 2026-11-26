#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    本人用户名密码认证业务；处理注册、登录和本人改密。
# History:
# Date          Author    Version       Modification
# 2026/10/19    XTN       V1.031        直接导入共享业务服务，删除仅返回实例的依赖入口
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        管理员用户操作归用户业务，共用账号审计，数据库查询归仓储
# 2026/09/23    XTN       V1.002        补充面向初学者的业务权限、执行顺序和事务结果说明
# 2026/09/23    XTN       V1.003        类方法参数逐行对齐，整理业务调用排版
# 2026/09/23    XTN       V1.004        解释注册回调执行时机及前置校验责任
# 2026/09/26    XTN       V1.005        账号审计依赖统一为简洁明确的 AccountAuditService
# 2026/09/26    XTN       V1.006        用户创建和密码规则统一使用具体用户名语义
# 2026/09/29    XTN       V1.007        密码规则响应统一从错误模块导入
# 2026/09/30    XTN       V1.008        移除公开注册开关读写和注册时的开关复查
# 2026/09/30    XTN       V1.009        移除临时密码流程并让线下恢复直接设置密码
# 2026/10/02    XTN       V1.010        修正登录结果说明中的过时改密字段
# 2026/10/02    XTN       V1.011        线下超级管理员恢复移至不导出的维护命令模块
# 2026/10/02    XTN       V1.012        登录凭据异常改由统一业务异常模块提供
# 2026/10/02    XTN       V1.013        注册预检查直接沿用共享创建服务的用户名冲突提示
# 2026/10/02    XTN       V1.014        简化本人改密验证入口并展开身份快照字段
# 2026/10/09    XTN       V1.015        注册和本人改密引用集中定义的账号安全审计动作
# 2026/10/10    XTN       V1.016        统一用户身份命名，区分用户 ID、当前用户及目标用户
# 2026/10/13    XTN       V1.017        补齐密码认证全流程步骤、快照比较及提交与失败边界说明
# 2026/10/15    XTN       V1.018        注册直接复用 UserService 的用户创建及冲突判断
# 2026/10/15    XTN       V1.019        注册直接创建带密码的账号，合并会话与事务入口
# 2026/10/16    XTN       V1.020        账号审计自动获取请求 ID，清理注册与改密的重复传参
# 2026/10/16    XTN       V1.021        登录认证合并单次查询和转发函数，直接展开校验与并发复查
# 2026/10/16    XTN       V1.022        解释注册、登录和改密的关键变量、拒绝条件与异常转换原因；异常构造器标明 HTTP 状态
# 2026/10/16    XTN       V1.023        注册直接沿用共享创建的用户名冲突提示，删除外层重复捕获
# 2026/10/16    XTN       V1.024        注册与改密统一操作审计，保存脱敏请求及业务响应快照
# 2026/10/16    XTN       V1.025        审计调用收为成功与拒绝两个入口，分类和身份自动获取
# 2026/10/16    XTN       V1.026        合并登录重复复查流程，收拢账号状态判断并简化本人改密调用
# 2026/10/16    XTN       V1.027        登录业务入口统一命名为 login
# 2026/10/16    XTN       V1.028        登录只验证一次，锁内状态或哈希变化时直接拒绝
# 2026/10/16    XTN       V1.029        登录统一完成密码验证、Token 签发与 Redis 登记，并按步骤说明
# 2026/10/16    XTN       V1.030        登录成功后自动记录请求日志用户，路由无需手动填写
# 2026/10/19    XTN       V1.032        精简认证业务注释，用短句说明步骤和失败原因
# 2026/10/19    XTN       V1.033        账号信息统一命名 user_info，说明字段复制和会话关闭的用途
# 2026/10/19    XTN       V1.034        本人改密不返回布尔标记，审计响应与接口空结果一致
# 2026/10/20    XTN       V1.035        登录身份统一使用 login_info，认证依赖改用直观入口
# 2026/10/22    XTN       V1.036        用户查询统一使用 get_user，登录及旧密码验证明确包含删除状态
# 2026/10/22    XTN       V1.037        密码保存方法统一命名为 update_password
# 2026/10/23    XTN       V1.038        签发流程归认证服务，Redis 登录记录通过仓储访问
# 2026/10/26    XTN       V1.039        本人旧密码验证直接判断结果，收窄异常捕获并统一拒绝分支
# --------------------------------------------------------------------------------------------------

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.access.authorization import AuthorizationContext
from app.core.audit import AccountAuditAction
from app.core.codes import BusinessCode
from app.core.config import Settings
from app.core.exceptions import (
    InvalidLoginCredentialsError,
    forbidden_403,
    invalid_request_400,
    password_policy_response_400,
    unavailable_503,
)
from app.core.i18n.messages import MessageKey
from app.core.ids import require_entity_id
from app.core.logging.context import set_log_user_id
from app.core.logging.events import safe_exception_metadata, safe_log
from app.core.security.jwt_tokens import encode_access_token
from app.core.security.passwords import (
    PasswordHashError,
    PasswordManager,
    PasswordPolicyError,
    PasswordVerification,
    password_manager,
)
from app.db.postgres_db import SessionFactory
from app.db.redis_db import RedisClient
from app.models.postgres.user import User
from app.repositories.postgres.rbac_state_repository import rbac_state_repository
from app.repositories.postgres.user_repository import user_repository
from app.repositories.redis.login_session_repository import login_session_repository
from app.services.audit_service import AuditService
from app.services.user_service import user_service

logger = logging.getLogger(__name__)

# 登录编号重复才换一个重试，含首次共两次；Redis 故障不重复登记。
JTI_ISSUANCE_ATTEMPTS = 2


@dataclass(frozen=True, slots=True)
class LoginResult:
    """
        登录成功的结果：用户 ID、Token 和有效期。
    """

    # 本次登录的用户 ID。
    user_id: str
    # 已登记到 Redis 的登录凭证。
    access_token: str
    # Token 有效期，单位：秒。
    expires_in: int


@dataclass(frozen=True, slots=True)
class _UserInfo:
    """
        保存验密码前的账号信息，后面与加锁重查的结果比较。
        只保存字段值，不关联数据库会话，也不能重新给字段赋值。
        包含密码哈希，不能返回给客户端或写入日志。
    """

    # 用户 ID，用于重新查询同一账号。
    user_id: str
    # 用户名；None 表示未设置。
    user_name: str | None
    # 是否启用；停用后不能登录。
    is_active: bool
    # 是否已删除；删除后不能登录。
    is_deleted: bool
    # 登录撤销版本；改密、强制退出等操作会改变它。
    token_version: int
    # 保存的密码哈希；None 表示没有本地密码。
    password_hash: str | None
    # 上次改密时间，用于检查验密码期间是否改过密码。
    password_changed_at: datetime | None


class AuthService:
    """
        处理注册、完整登录和本人改密；耗时的密码计算不占用数据库行锁。
    """

    def __init__(self, session_factory: async_sessionmaker[AsyncSession],
                 manager: PasswordManager
                 ) -> None:
        """
            保存创建会话、验证密码和记录审计所需的工具。

        :param session_factory: 创建 PostgreSQL 异步会话的工厂。
        :param manager: 负责密码策略、Argon2 哈希和凭据验证的处理器。
        :return: 无返回值。
        """
        # 需要查库时才创建会话，不长期占用连接。
        self._session_factory = session_factory
        # 密码处理器负责规则检查和哈希计算。
        self._password_manager = manager
        # 审计服务负责记录账号操作。
        self._audit = AuditService(session_factory)

    async def register(self, *, user_name: str,
                       password: str
                       ) -> str:
        """
            先检查并计算密码哈希，再创建账号、绑定默认角色和记录审计，一起提交。
            路由先完成注册限流和一次性验证码校验；这里不重复执行。

        :param user_name: 已按项目用户名规则校验的注册用户名。
        :param password: 待校验并哈希的新密码，不保存原文。
        :return: 注册事务提交后的新用户 ID。
        :raises AppError: 用户名占用、密码不合规，或默认角色等必要数据缺失。
        :raises IntegrityError: 不属于用户名占用的数据库约束冲突。
        :raises RuntimeError: 缺少记录审计所需的请求信息。
        """

        # 1. 先检查密码并计算哈希，避免耗时计算占用数据库锁。
        try:
            # 数据库只保存哈希，不保存密码原文。
            password_hash = await self._password_manager.hash_new_password(
                password,
                user_name=user_name,
            )
        except PasswordPolicyError as exc:
            # 只把密码规则错误转为输入提示，系统故障仍向上抛出。
            raise password_policy_response_400(exc) from exc

        # 正常结束时提交，出错时回滚，最后关闭会话。
        async with self._session_factory() as session, session.begin():
            # 2. 创建用户并绑定默认角色；用户名占用由 create_user 报错。
            user = await user_service.create_user(
                session,
                user_name=user_name,
                password_hash=password_hash,
            )
            # 3. 审计与用户一起提交；注册时还没登录，操作人为空，被操作人是新用户。
            self._audit.audit_success(
                session,
                action=AccountAuditAction.REGISTER_USER,
                reason_code="registration_completed",
                target_user_id=user.user_id,
                # 同一条审计记录账号创建和默认角色绑定。
                after_state={"user_id": user.user_id, "default_role_key": "user"},
                # 保存业务返回值；响应是否发送成功由文件日志记录。
                message_key=MessageKey.AUTH_REGISTER_SUCCEEDED,
                code=BusinessCode.CREATED,
                data={"user_id": user.user_id},
            )
        # 事务提交成功后才返回用户 ID。
        return user.user_id

    async def login(self, *, user_name: str,
                    password: str,
                    redis: RedisClient,
                    settings: Settings
                    ) -> LoginResult:
        """
            查账号、验密码、复查账号，再签发 Token 并登记到 Redis。
            路由的限流和一次性验证码必须先通过，这里不再重复执行。
            密码只验证一次；复查发现账号或密码已变化，就拒绝本次请求。

        :param user_name: 请求模型已经校验过的登录用户名。
        :param password: 用户本次输入的密码，只用于验证，不保存原文。
        :param redis: 应用已创建的 Redis 客户端，用于登记本次登录。
        :param settings: Token 的签名密钥、有效期和允许同时登录的数量等配置。
        :return: 登录用户 ID、已登记的 Token 和有效期秒数；路由负责包装 HTTP 响应。
        :raises InvalidLoginCredentialsError: 密码错误、账号不可用，或验证期间账号及密码状态已变化。
        :raises AppError: 密码哈希损坏、登录版本已失效或 Redis 无法完成登记。
        """

        # 1. 查账号，把验密码和后续比较需要的字段存入 user_info。
        # 退出 async with 才会归还连接，避免验密码时一直占用数据库连接。
        async with self._session_factory() as session:
            user = await user_repository.get_user(
                session, user_name=user_name, is_deleted=None,
            )
            # 用户名不存在时为 None；复制的信息保留查库时的值。
            user_info = self._build_user_info(user) if user is not None else None

        # 2. 验证密码。账号不存在也做一次无效计算，减少通过响应快慢猜用户名的机会。
        verification = await self._verify_password_details(
            password, user_info.password_hash if user_info is not None else None,
        )
        if user_info is None or not verification.verified or user_info.is_deleted or not user_info.is_active:
            raise InvalidLoginCredentialsError()

        # 3. 旧哈希需要升级时，在锁外计算新哈希；密码和登录撤销版本都不变。
        replacement_hash = None
        if verification.needs_rehash:
            replacement_hash = await self._password_manager.hash_verified_password(password)

        # 4. 锁住用户并重新查询，确认算密码期间账号没变；提交成功后才继续签发 Token。
        async with self._session_factory() as session, session.begin():
            users = await user_repository.lock_users(session, {user_info.user_id})
            user = users.get(user_info.user_id)
            # 账号或密码变了就拒绝；即使只是另一笔登录升级了哈希，也不重新验证。
            if (
                user is None
                or not self._same_account_state(user, user_info)
                or user.password_hash != user_info.password_hash
            ):
                raise InvalidLoginCredentialsError()
            if replacement_hash is not None:
                user.password_hash = replacement_hash
            # 记下用户 ID 和登录撤销版本，供 Redis 登记使用。
            user_id = user.user_id
            token_version = user.token_version

        # 5. 释放数据库锁后，按刚确认的版本签发并登记 Token；登记失败就不返回 Token。
        access_token = await self.issue_access_token(
            redis,
            user_id=user_id,
            user_token_version=token_version,
            settings=settings,
        )

        # 6. 为当前请求日志记下用户，再把登录结果交给路由。
        set_log_user_id(user_id)
        return LoginResult(
            user_id=user_id,
            access_token=access_token,
            expires_in=settings.jwt_access_token_ttl_seconds,
        )

    async def issue_access_token(self, redis: RedisClient, *,
                                 user_id: str,
                                 user_token_version: int,
                                 settings: Settings
                                 ) -> str:
        """
            生成 Token，再让仓储登记登录；登记成功后才返回。

        :param redis: 应用共用的 Redis 客户端。
        :param user_id: 已通过账号检查的用户 ID，不能使用请求方随意指定的身份。
        :param user_token_version: 数据库刚确认的登录撤销版本。
        :param settings: Token 签名、有效期及每用户同时登录数量的配置。
        :return: 已确认登记成功的 Token 字符串。
        :raises ValueError: 用户 ID 或登录版本不合规，或生成的 Token 超过长度上限。
        :raises AppError: 登录版本已变化、Redis 不可用，或两次登录编号都发生冲突。
        """
        # 1. 检查服务端传来的身份和版本，再开始生成 Token。
        require_entity_id(user_id, "U")
        if (
            isinstance(user_token_version, bool)
            or not isinstance(user_token_version, int)
            or user_token_version < 0
        ):
            raise ValueError("the issuer requires a valid token version")

        # 2. 每次使用新的 UUID 登录编号生成 Token，签名由现有 JWT 工具完成。
        for _attempt in range(JTI_ISSUANCE_ATTEMPTS):
            token, token_info = encode_access_token(
                user_id=user_id,
                token_id=uuid.uuid4(),
                settings=settings,
            )
            # 3. 仓储负责登记、清理和超限淘汰；这里不操作 Redis Key 或脚本。
            registered = await login_session_repository.register_login_session(
                redis,
                token_info=token_info,
                user_token_version=user_token_version,
                max_active_sessions=settings.max_active_sessions_per_user,
            )
            if registered:
                return token
            # False 只表示编号重复，可以换一个重试；其他错误会直接抛出，不重复写入。

        # 4. 两次都遇到编号冲突就报错，不能返回尚未登记的 Token。
        raise unavailable_503("access_token_issuance_conflict")

    async def change_password(self, *, context: AuthorizationContext,
                              current_password: str,
                              new_password: str
                              ) -> None:
        """
            本人登录并通过改密验证码后，验证旧密码，再设置新密码。
            密码在锁外计算，锁内复查账号；新密码、登录撤销版本和审计一起提交。

        :param context: 当前登录用户的身份、Token 版本及审计上下文。
        :param current_password: 用于本人二次验证的旧密码。
        :param new_password: 需要设置的新密码，不得与旧密码相同。
        :return: 无返回值；正常结束表示密码、登录撤销版本和审计已一起提交。
        :raises AppError: 旧密码错误、新密码不合规，或验证后凭据已发生变化。
        """
        # 1. 新旧密码不能相同，再验证旧密码并记下账号信息。
        if current_password == new_password:
            raise invalid_request_400("new_password_must_differ")
        user_info = await self._verify_current_password(
            context=context,
            current_password=current_password,
        )
        # 2. 在锁外计算新密码哈希，写入前还会复查账号有没有变化。
        try:
            # 用数据库里的用户名检查密码规则，不能由请求方另传。
            new_hash = await self._password_manager.hash_new_password(
                new_password, user_name=user_info.user_name,
            )
        except PasswordPolicyError as exc:
            # 密码规则不通过就返回输入提示，此时还没有修改账号。
            raise password_policy_response_400(exc) from exc

        # 3. 先锁授权状态，再锁用户，保持加锁顺序一致；拿到锁后重新核对账号。
        async with self._session_factory() as session, session.begin():
            await rbac_state_repository.lock_rbac_state(session)
            users = await user_repository.lock_users(session, {context.login_info.user_id})
            user = users.get(context.login_info.user_id)
            # 验密码期间账号或密码变了，就拒绝本次改密。
            if (
                user is None
                or not self._same_account_state(user, user_info)
                or user.password_hash != user_info.password_hash
            ):
                raise forbidden_403("current_credential_changed")

            # 4. 保存新密码并增加撤销版本，让旧登录下次鉴权时失效。
            await user_repository.update_password(session, user=user, password_hash=new_hash)
            user.token_version += 1
            # 5. 审计与密码一起提交；提交失败时一起回滚。
            self._audit.audit_success(
                session,
                action=AccountAuditAction.CHANGE_PASSWORD,
                context=context,
                reason_code="password_changed",
                target_user_id=user.user_id,
                message_key=MessageKey.AUTH_PASSWORD_CHANGED_RELOGIN,
                data=None,
            )

    async def _verify_current_password(self, *, context: AuthorizationContext,
                                       current_password: str
                                       ) -> _UserInfo:
        """
            为本人改密验证旧密码和登录撤销版本，验证时不占用数据库锁。
            验证失败会尝试记录拒绝审计，审计故障不改变原来的错误提示。

        :param context: 当前操作者身份和 Token 版本。
        :param current_password: 操作者提交的当前密码，仅用于验证。
        :return: 验证时的账号信息；调用方加锁后仍须复查。
        :raises AppError: 当前密码或账号状态无效，或密码存储、计算服务不可用。
        """
        # 1. 查账号并复制待比较的字段，关闭会话后再算密码。
        # 查库失败直接交给上层处理，不能把数据库故障说成旧密码错误。
        async with self._session_factory() as session:
            user = await user_repository.get_user(
                session, user_id=context.login_info.user_id, is_deleted=None,
            )
            user_info = self._build_user_info(user) if user is not None else None

        # 2. 验证旧密码，只取是否正确；账号缺失时仍走占位验证，保持失败路径一致。
        try:
            password_correct = (await self._verify_password_details(
                current_password,
                user_info.password_hash if user_info is not None else None,
            )).verified
        except InvalidLoginCredentialsError:
            # 输入不符合密码验证规则，也按旧密码错误处理；存储损坏或计算繁忙仍向上抛出。
            password_correct = False

        # 3. 密码正确、账号未删除且启用、登录版本一致，才能继续。
        if (
            user_info is None
            or not password_correct
            or user_info.is_deleted
            or not user_info.is_active
            or user_info.token_version != context.login_info.token_version
        ):
            # 所有验证失败都在这里记一次拒绝审计，再返回相同的 403 提示。
            error = forbidden_403("current_password_invalid")
            await self._audit.audit_denied(
                action=AccountAuditAction.CHANGE_PASSWORD,
                context=context,
                target_user_id=context.login_info.user_id,
                error=error,
            )
            raise error
        # 4. 返回验密码时的账号信息，保存新密码前还要加锁复查。
        return user_info

    async def _verify_password_details(self, password: str,
                                       password_hash: str | None
                                       ) -> PasswordVerification:
        """
            验证输入密码；输入不合规按密码错误处理，保存的哈希损坏则按服务故障处理。
            没有真实哈希时也做一次无效计算。

        :param password: 用户本次输入的密码，不会写入日志或数据库。
        :param password_hash: 数据库保存的密码哈希；None 表示没有可验证的密码。
        :return: 密码是否正确、哈希是否需要升级，以及是否使用了占位哈希。
        :raises InvalidLoginCredentialsError: 输入的密码不符合允许验证的规则。
        :raises AppError: 数据库里的密码哈希已损坏，不能正常验证。
        """
        # 1. 验证密码；没有真实哈希时也做一次计算。
        try:
            return await self._password_manager.verify_or_dummy(password, password_hash)
        except PasswordPolicyError as exc:
            # 2. 输入不合规时，统一按密码错误拒绝。
            raise InvalidLoginCredentialsError() from exc
        except PasswordHashError as exc:
            # 3. 保存的哈希坏了属于系统故障；日志不能带上密码或哈希。
            safe_log(
                logger,
                logging.ERROR,
                "authentication.password_store.invalid",
                extra=safe_exception_metadata(exc),
            )
            # 对外返回 503，保留原异常供排查。
            raise unavailable_503("password_credential_unavailable") from exc

    @staticmethod
    def _build_user_info(user: User) -> _UserInfo:
        """
            复制验密码和后续比较需要的账号字段，不保留数据库会话。

        :param user: 刚从数据库查到、包含密码哈希和账号状态的用户。
        :return: 验证前的账号信息，后续与加锁重查的结果比较；包含密码哈希，不能记录到日志。
        """
        # 复制已查到的字段；此处不查库，连接由调用处的 async with 归还。
        return _UserInfo(
            user_id=user.user_id,
            user_name=user.user_name,
            is_active=user.is_active,
            is_deleted=user.deleted_at is not None,
            token_version=user.token_version,
            password_hash=user.password_hash,
            password_changed_at=user.password_changed_at,
        )

    @staticmethod
    def _same_account_state(user: User,
                            user_info: _UserInfo
                            ) -> bool:
        """
            把现在的账号和验密码前的副本逐项比较，检查这段时间有没有被人修改。

        :param user: 当前事务中重新查到并锁住的用户。
        :param user_info: 验密码前保存的账号信息。
        :return: 账号未删除且下面各项都没变时返回 True；密码哈希在调用处单独比较。
        """
        # 下面各项必须都没变；密码哈希由调用方另行比较。
        return (
            user.user_id == user_info.user_id
            and user.user_name == user_info.user_name
            and user.deleted_at is None
            and user.is_active == user_info.is_active
            and user.token_version == user_info.token_version
            and user.password_changed_at == user_info.password_changed_at
        )


# 各请求共用服务对象，不在对象上保存当前用户或请求数据。
auth_service = AuthService(SessionFactory, password_manager)
