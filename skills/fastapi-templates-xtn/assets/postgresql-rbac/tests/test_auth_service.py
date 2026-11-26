#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    离线检查认证业务的密码规则、事务与安全拒绝行为
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/29    XTN       V1.000        补充文件记录并覆盖非 ASCII 与不可见新密码拒绝
# 2026/09/30    XTN       V1.001        移除临时密码状态并验证直接重置行为
# 2026/10/02    XTN       V1.002        线下恢复测试改用维护命令专属服务
# 2026/10/02    XTN       V1.003        维护命令测试改用专属持有人查询仓储
# 2026/10/02    XTN       V1.004        登录凭据异常从统一业务异常模块导入
# 2026/10/02    XTN       V1.005        验证本人改密拒绝审计与哈希计算边界
# 2026/10/10    XTN       V1.006        统一用户 ID 与当前用户命名
# 2026/10/10    XTN       V1.007        非法密码长度使用统一消息键
# 2026/10/15    XTN       V1.008        验证注册和管理员新增初始带密码创建，不再二次改密
# 2026/10/16    XTN       V1.009        账号审计统一读取操作入口绑定的请求上下文
# 2026/10/16    XTN       V1.010        登录测试直接替换仓储查询并检查锁外验证前关闭短会话
# 2026/10/16    XTN       V1.011        异常构造器名称统一标明固定 HTTP 状态
# 2026/10/16    XTN       V1.012        通过仓储验证精简后的登录与改密流程和并发状态复查
# 2026/10/16    XTN       V1.013        登录业务入口统一使用直观的 login 名称
# 2026/10/16    XTN       V1.014        登录只验证一轮，并发哈希变化直接拒绝且不覆盖已有结果
# 2026/10/16    XTN       V1.015        验证完整登录在数据库提交并关闭会话后才登记和返回令牌
# 2026/10/16    XTN       V1.016        验证登录成功才记录请求日志用户，拒绝和登记失败不冒用身份
# 2026/10/22    XTN       V1.017        密码保存方法统一命名为 update_password
# 2026/10/26    XTN       V1.018        权限结果字段明确区分有效用户信息与包含停用角色的信息
# 2026/10/26    XTN       V1.019        覆盖本人改密统一凭据拒绝与系统故障传播边界
# --------------------------------------------------------------------------------------------------

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import ANY, AsyncMock, Mock

import pytest
from fastapi import Request
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.commands.operator_password_repository import operator_password_repository
from app.commands.operator_password_service import OperatorPasswordService
from app.core.access.permissions import PermissionKey
from app.core.audit import AccountAuditAction, AuditSource
from app.core.config import get_settings
from app.core.exceptions import AppError, InvalidLoginCredentialsError, forbidden_403, unavailable_503
from app.core.i18n.messages import MessageKey
from app.core.ids import new_entity_id
from app.core.logging.context import bind_request_context, deactivate_request_context, reset_request_context
from app.core.logging.details import HttpLogDetails
from app.core.security.passwords import (
    PasswordBusyError,
    PasswordHashError,
    PasswordManager,
    PasswordPolicyError,
    PasswordVerification,
)
from app.models.postgres.user import User
from app.repositories.postgres.rbac_state_repository import rbac_state_repository
from app.repositories.postgres.user_repository import user_repository
from app.services.auth_service import (
    AuthService,
    _UserInfo,
)
from app.services.user_service import UserService, user_service

pytestmark = pytest.mark.usefixtures("audit_request_context")

LOGIN_REDIS = cast(Any, object())


@pytest.fixture
def login_log_request(audit_request_context: str) -> Iterator[Request]:
    request = Request({"type": "http", "method": "POST", "path": "/api/v1/auth/login", "headers": []})
    token = bind_request_context(audit_request_context, http_details=HttpLogDetails(request, None))
    try:
        yield request
    finally:
        deactivate_request_context()
        reset_request_context(token)


@pytest.fixture(autouse=True)
def issue_token(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    issuer = AsyncMock(return_value="signed-access-token")
    monkeypatch.setattr("app.services.auth_service.AuthService.issue_access_token", issuer)
    return issuer


class _AsyncContext:
    def __init__(self, value: object) -> None:
        self._value = value

    async def __aenter__(self) -> object:
        return self._value

    async def __aexit__(self, *_args: object) -> None:
        return None


def _service(manager: Any) -> AuthService:
    return AuthService(
        cast(async_sessionmaker[AsyncSession], Mock(return_value=_AsyncContext(Mock(spec=AsyncSession)))),
        manager,
    )


def _snapshot(*, password_hash: str) -> _UserInfo:
    return _UserInfo(
        user_id=new_entity_id("U"),
        user_name="alice",
        is_active=True,
        is_deleted=False,
        token_version=0,
        password_hash=password_hash,
        password_changed_at=datetime.now(UTC),
    )


def _snapshot_user(snapshot: _UserInfo | None) -> User | None:
    """
        为登录查询组装独立用户模型，让真实认证入口负责复制快照及关闭会话。

    :param snapshot: 首次查询应读出的密码状态；None 表示用户名不存在。
    :return: 独立于锁内用户变化的查询模型，或不存在时的 None。
    """
    # 不复用锁内用户对象，避免并发状态变化提前改写首次查询的测试输入。
    if snapshot is None:
        return None
    return User(
        user_id=snapshot.user_id,
        user_name=snapshot.user_name,
        is_active=snapshot.is_active,
        deleted_at=datetime.now(UTC) if snapshot.is_deleted else None,
        token_version=snapshot.token_version,
        password_hash=snapshot.password_hash,
        password_changed_at=snapshot.password_changed_at,
    )


@pytest.mark.parametrize(("password", "expected_key"), [
    ("short", MessageKey.ERROR_PASSWORD_LENGTH),
    ("long-password-" * 5, MessageKey.ERROR_PASSWORD_LENGTH),
    ("safe-password\n", MessageKey.ERROR_PASSWORD_CHARACTERS),
    ("safe-password 中文", MessageKey.ERROR_PASSWORD_CHARACTERS),
    ("safe-password-\u200b", MessageKey.ERROR_PASSWORD_CHARACTERS),
    ("safe-password-\ud800", MessageKey.ERROR_PASSWORD_CHARACTERS),
])
async def test_new_password_rejection_is_actionable_before_database_work(password: str,
                                                                         expected_key: MessageKey) -> None:
    """
        直接调用业务也必须拒绝非法新密码，并选取明确提示而不是含糊的请求失败。

    :param password: 长度或字符不合法的新密码。
    :param expected_key: 预期的安全本地化消息键。
    :return: 无返回值；密码校验失败发生在创建数据库会话之前。
    """
    session_factory = Mock()
    service = AuthService(cast(async_sessionmaker[AsyncSession], session_factory), PasswordManager())
    with pytest.raises(AppError) as caught:
        await service.register(user_name="Alice", password=password)
    assert caught.value.status_code == 400
    assert caught.value.message_key == expected_key
    session_factory.assert_not_called()


@pytest.mark.parametrize("admin_create", [False, True])
async def test_new_accounts_pass_initial_hash_before_transaction(monkeypatch: pytest.MonkeyPatch,
                                                                 admin_create: bool,
                                                                 audit_request_context: str,
                                                                 ) -> None:
    """
        注册和管理员新增在锁外计算密码，首次创建即带哈希，成功审计仍在同一事务。

    :param monkeypatch: 隔离数据库、密码哈希和共享创建方法，不访问外部服务。
    :param admin_create: True 验证管理员新增，False 验证公开注册。
    :param audit_request_context: 操作入口已绑定的请求 ID，两个账号创建入口均应使用它。
    :return: 无返回值；创建与审计的执行顺序正确，不调用仅用于真实改密的 update_password。
    """
    events: list[str] = []
    in_transaction = False

    class Transaction:
        async def __aenter__(self) -> None:
            nonlocal in_transaction
            in_transaction = True
            events.append("transaction.enter")

        async def __aexit__(self, *_args: object) -> None:
            nonlocal in_transaction
            in_transaction = False
            events.append("transaction.exit")

    session = Mock(spec=AsyncSession)
    session.begin.return_value = Transaction()
    session_factory = Mock(return_value=_AsyncContext(session))
    password_hash = "$argon2id$prepared-initial-hash"
    created_user = User(user_id=new_entity_id("U"), user_name="learner_42", password_hash=password_hash,
                        password_changed_at=datetime.now(UTC), token_version=0)

    async def hash_password(_password: str, *, user_name: str | None) -> str:
        assert not in_transaction
        session_factory.assert_not_called()
        assert user_name == created_user.user_name
        events.append("hash")
        return password_hash

    async def create_user(created_session: AsyncSession, **kwargs: object) -> User:
        assert created_session is session
        assert in_transaction
        assert kwargs["password_hash"] == password_hash
        assert kwargs["user_name"] == created_user.user_name
        events.append("create")
        return created_user

    def add_success_audit(_audit: object) -> None:
        assert in_transaction
        events.append("audit")

    manager = Mock(hash_new_password=AsyncMock(side_effect=hash_password))
    shared_create = AsyncMock(side_effect=create_user)
    update_password = AsyncMock()
    monkeypatch.setattr(user_repository, "update_password", update_password)
    session.add.side_effect = add_success_audit
    if admin_create:
        service = UserService(cast(async_sessionmaker[AsyncSession], session_factory), manager)
        current_user_id = new_entity_id("U")
        context = SimpleNamespace(login_info=SimpleNamespace(user_id=current_user_id, token_version=0),
                                  audit_source=AuditSource.HTTP)
        monkeypatch.setattr(service, "create_user", shared_create)
        monkeypatch.setattr(rbac_state_repository, "lock_rbac_state", AsyncMock())
        monkeypatch.setattr(user_repository, "lock_users", AsyncMock())
        monkeypatch.setattr(user_repository, "check_current_user",
                            AsyncMock(return_value=SimpleNamespace(permissions={PermissionKey.USERS_CREATE.value})))
        result = await service.admin_create_user(context=cast(Any, context),
                                                 user_name=created_user.user_name, password="initial-password-42")
        assert shared_create.await_args is not None
        assert shared_create.await_args.kwargs["bound_by_user_id"] == current_user_id
        expected_action = AccountAuditAction.ADMIN_CREATE_USER.value
    else:
        auth_service = AuthService(cast(async_sessionmaker[AsyncSession], session_factory), manager)
        monkeypatch.setattr(user_service, "create_user", shared_create)
        result = await auth_service.register(user_name=created_user.user_name,
                                             password="initial-password-42")
        expected_action = AccountAuditAction.REGISTER_USER.value

    assert result == created_user.user_id
    assert events == ["hash", "transaction.enter", "create", "audit", "transaction.exit"]
    shared_create.assert_awaited_once()
    manager.hash_new_password.assert_awaited_once()
    update_password.assert_not_awaited()
    session.add.assert_called_once()
    audit = session.add.call_args.args[0]
    assert audit.action == expected_action
    assert audit.category == "account"
    assert audit.outcome == "succeeded"
    assert audit.user_id == (current_user_id if admin_create else None)
    assert audit.target_user_id == created_user.user_id
    assert audit.after_state == {"user_id": created_user.user_id, "default_role_key": "user"}
    assert audit.response_data["data"]["user_id"] == created_user.user_id
    assert audit.request_id == audit_request_context


@pytest.mark.parametrize(
    ("snapshot", "used_dummy"),
    [
        (None, True),
        (_snapshot(password_hash="$argon2id$stored"), False),
    ],
)
async def test_unknown_and_wrong_passwords_use_one_public_failure(monkeypatch: pytest.MonkeyPatch,
                                                                  snapshot: _UserInfo | None,
                                                                  used_dummy: bool,
                                                                  issue_token: AsyncMock,
                                                                  login_log_request: Request) -> None:
    manager = Mock()
    manager.verify_or_dummy = AsyncMock(
        return_value=PasswordVerification(
            verified=False,
            needs_rehash=False,
            used_dummy=used_dummy,
        )
    )
    service = _service(manager)
    monkeypatch.setattr(
        user_repository,
        "get_user",
        AsyncMock(return_value=_snapshot_user(snapshot)),
    )

    with pytest.raises(InvalidLoginCredentialsError) as caught:
        await service.login(
            redis=LOGIN_REDIS,
            settings=get_settings(),
            user_name="alice",
            password="candidate password",
        )

    assert str(caught.value) == "invalid_login_credentials"
    expected_hash = snapshot.password_hash if snapshot is not None else None
    manager.verify_or_dummy.assert_awaited_once_with(
        "candidate password",
        expected_hash,
    )
    issue_token.assert_not_awaited()
    assert getattr(login_log_request.state, "user_id", None) is None


async def test_corrupt_stored_hash_fails_closed_as_dependency_error(monkeypatch: pytest.MonkeyPatch) -> None:
    snapshot = _snapshot(password_hash="corrupt")
    manager = Mock()
    manager.verify_or_dummy = AsyncMock(side_effect=PasswordHashError("invalid"))
    service = _service(manager)
    monkeypatch.setattr(
        user_repository,
        "get_user",
        AsyncMock(return_value=_snapshot_user(snapshot)),
    )

    with pytest.raises(AppError) as caught:
        await service.login(
            redis=LOGIN_REDIS,
            settings=get_settings(),
            user_name="alice",
            password="candidate password",
        )

    assert caught.value.status_code == 503
    assert caught.value.reason_code == "password_credential_unavailable"


async def test_current_hash_login_returns_token_without_rehash(monkeypatch: pytest.MonkeyPatch,
                                                               issue_token: AsyncMock,
                                                               login_log_request: Request) -> None:
    """
        正常登录只验证一次现有密码并加锁确认状态，不执行无关的哈希升级。

    :param monkeypatch: 用独立用户模型和短会话替代真实数据库。
    :param issue_token: 隔离真实 Redis，检查签发发生在数据库会话关闭之后。
    :return: 无返回值；数据库提交和会话关闭后签发令牌，密码哈希保持不变。
    """
    snapshot = _snapshot(password_hash="$argon2id$current")
    user = _snapshot_user(snapshot)
    assert user is not None
    query_session = AsyncMock(spec=AsyncSession)
    query_session.__aenter__.return_value = query_session
    transaction = AsyncMock()
    locked_session = AsyncMock(spec=AsyncSession)
    locked_session.__aenter__.return_value = locked_session
    locked_session.begin = Mock(return_value=transaction)
    session_factory = Mock(side_effect=[query_session, locked_session])

    async def verify_password(_password: str, password_hash: str | None) -> PasswordVerification:
        query_session.__aexit__.assert_awaited_once_with(None, None, None)
        assert password_hash == snapshot.password_hash
        return PasswordVerification(True, False, False)

    manager = Mock(verify_or_dummy=AsyncMock(side_effect=verify_password), hash_verified_password=AsyncMock())
    service = AuthService(cast(async_sessionmaker[AsyncSession], session_factory), manager)
    monkeypatch.setattr(user_repository, "get_user", AsyncMock(return_value=_snapshot_user(snapshot)))
    lock_users = AsyncMock(return_value={snapshot.user_id: user})
    monkeypatch.setattr(user_repository, "lock_users", lock_users)

    async def issue_after_database_release(*_args: object, **_kwargs: object) -> str:
        transaction.__aexit__.assert_awaited_once_with(None, None, None)
        locked_session.__aexit__.assert_awaited_once_with(None, None, None)
        assert getattr(login_log_request.state, "user_id", None) is None
        return "signed-access-token"

    issue_token.side_effect = issue_after_database_release
    result = await service.login(redis=LOGIN_REDIS, settings=get_settings(),
                                 user_name="alice", password="current-password")

    assert result.user_id == snapshot.user_id
    assert login_log_request.state.user_id == snapshot.user_id
    assert result.access_token == "signed-access-token"
    assert result.expires_in == get_settings().jwt_access_token_ttl_seconds
    issue_token.assert_awaited_once_with(LOGIN_REDIS, user_id=snapshot.user_id,
                                         user_token_version=snapshot.token_version, settings=get_settings())
    assert user.password_hash == snapshot.password_hash
    manager.verify_or_dummy.assert_awaited_once()
    manager.hash_verified_password.assert_not_awaited()
    lock_users.assert_awaited_once_with(locked_session, {snapshot.user_id})


@pytest.mark.parametrize("failure_stage", ["commit", "redis"])
async def test_login_does_not_return_token_when_commit_or_registration_fails(
    monkeypatch: pytest.MonkeyPatch,
    issue_token: AsyncMock,
    failure_stage: str,
    login_log_request: Request,
) -> None:
    snapshot = _snapshot(password_hash="$argon2id$current")
    user = _snapshot_user(snapshot)
    transaction = AsyncMock()
    locked_session = AsyncMock(spec=AsyncSession)
    locked_session.__aenter__.return_value = locked_session
    locked_session.begin = Mock(return_value=transaction)
    query_session = AsyncMock(spec=AsyncSession)
    query_session.__aenter__.return_value = query_session
    manager = Mock(verify_or_dummy=AsyncMock(return_value=PasswordVerification(True, False, False)))
    service = AuthService(
        cast(async_sessionmaker[AsyncSession], Mock(side_effect=[query_session, locked_session])),
        manager,
    )
    monkeypatch.setattr(user_repository, "get_user", AsyncMock(return_value=_snapshot_user(snapshot)))
    monkeypatch.setattr(user_repository, "lock_users", AsyncMock(return_value={snapshot.user_id: user}))
    if failure_stage == "commit":
        transaction.__aexit__.side_effect = RuntimeError("commit_failed")
        error_type: type[Exception] = RuntimeError
    else:
        issue_token.side_effect = unavailable_503("session_registry_unavailable")
        error_type = AppError

    with pytest.raises(error_type):
        await service.login(redis=LOGIN_REDIS, settings=get_settings(),
                            user_name="alice", password="verified-password")

    assert getattr(login_log_request.state, "user_id", None) is None
    if failure_stage == "commit":
        issue_token.assert_not_awaited()
    else:
        transaction.__aexit__.assert_awaited_once_with(None, None, None)
        locked_session.__aexit__.assert_awaited_once_with(None, None, None)
        issue_token.assert_awaited_once()


async def test_service_self_change_rejects_reusing_the_current_password(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = Mock()
    manager.hash_new_password = AsyncMock()
    service = _service(manager)
    load_current_user = AsyncMock()
    monkeypatch.setattr(user_repository, "get_user", load_current_user)

    with pytest.raises(AppError) as caught:
        await service.change_password(
            context=cast(Any, object()),
            current_password="same-password-value",
            new_password="same-password-value",
        )

    assert caught.value.status_code == 400
    assert caught.value.reason_code == "new_password_must_differ"
    load_current_user.assert_not_awaited()
    manager.hash_new_password.assert_not_awaited()


@pytest.mark.parametrize(
    "invalid_state",
    ["wrong_password", "password_input", "missing", "inactive", "deleted", "token_version"],
)
async def test_self_change_wrong_current_password_audits_before_new_hash(monkeypatch: pytest.MonkeyPatch,
                                                                         invalid_state: str) -> None:
    """
        本人旧密码或账号状态无效时统一写拒绝审计，不开始新密码哈希或写事务。

    :param monkeypatch: 替换密码快照读取，保持测试离线且不连接数据库。
    :param invalid_state: 模拟旧密码不匹配、输入不合规或本人账号已不可用。
    :return: 无返回值；错误码、审计动作及调用顺序由断言确认。
    """
    snapshot = _snapshot(password_hash="$argon2id$stored")
    user = _snapshot_user(snapshot) if invalid_state != "missing" else None
    if user is not None:
        user.is_active = invalid_state != "inactive"
        user.deleted_at = datetime.now(UTC) if invalid_state == "deleted" else None
        user.token_version += int(invalid_state == "token_version")
    current_password = "" if invalid_state == "password_input" else "wrong-password"
    manager = Mock()
    manager.verify_or_dummy = AsyncMock(
        return_value=PasswordVerification(
            verified=invalid_state not in {"wrong_password", "missing"},
            needs_rehash=False,
            used_dummy=invalid_state == "missing",
        ),
        side_effect=PasswordPolicyError("password_empty") if invalid_state == "password_input" else None,
    )
    manager.hash_new_password = AsyncMock()
    session = Mock(spec=AsyncSession)
    session_factory = Mock(return_value=_AsyncContext(session))
    service = AuthService(cast(async_sessionmaker[AsyncSession], session_factory), manager)
    load_current_user = AsyncMock(return_value=user)
    audit_denied = AsyncMock()
    monkeypatch.setattr(user_repository, "get_user", load_current_user)
    monkeypatch.setattr(service._audit, "audit_denied", audit_denied)
    context = SimpleNamespace(
        login_info=SimpleNamespace(user_id=snapshot.user_id, token_version=snapshot.token_version),
        audit_source=AuditSource.HTTP,
    )

    with pytest.raises(AppError) as caught:
        await service.change_password(
            context=cast(Any, context),
            current_password=current_password,
            new_password="a-better-password",
        )

    assert caught.value.status_code == 403
    assert caught.value.reason_code == "current_password_invalid"
    load_current_user.assert_awaited_once_with(ANY, user_id=snapshot.user_id, is_deleted=None)
    manager.verify_or_dummy.assert_awaited_once_with(
        current_password,
        snapshot.password_hash if user is not None else None,
    )
    audit_denied.assert_awaited_once_with(
        action=AccountAuditAction.CHANGE_PASSWORD,
        context=context,
        target_user_id=snapshot.user_id,
        error=ANY,
    )
    assert audit_denied.await_args is not None
    assert audit_denied.await_args.kwargs["error"] is caught.value
    manager.hash_new_password.assert_not_awaited()
    session_factory.assert_called_once_with()
    session.begin.assert_not_called()


@pytest.mark.parametrize("failure_case", ["database", "corrupt_hash", "password_busy"])
async def test_self_change_dependency_failure_does_not_become_password_denial(monkeypatch: pytest.MonkeyPatch,
                                                                              failure_case: str) -> None:
    """
        查库、存储哈希或计算繁忙故障不能变成旧密码错误，也不写凭据拒绝审计。

    :param monkeypatch: 隔离真实数据库、密码计算和拒绝审计。
    :param failure_case: 在查询或密码验证中模拟的系统故障。
    :return: 无返回值；故障原样传播或保持既有 503，不计算新哈希或开始写事务。
    """
    snapshot = _snapshot(password_hash="$argon2id$stored")
    failure = {
        "database": SQLAlchemyError("database unavailable"),
        "corrupt_hash": PasswordHashError("invalid"),
        "password_busy": PasswordBusyError("password_queue_full"),
    }[failure_case]
    load_current_user = AsyncMock(return_value=_snapshot_user(snapshot))
    manager = Mock(verify_or_dummy=AsyncMock(), hash_new_password=AsyncMock())
    if failure_case == "database":
        load_current_user.side_effect = failure
    else:
        manager.verify_or_dummy.side_effect = failure
    session = Mock(spec=AsyncSession)
    session_factory = Mock(return_value=_AsyncContext(session))
    service = AuthService(cast(async_sessionmaker[AsyncSession], session_factory), manager)
    audit_denied = AsyncMock()
    monkeypatch.setattr(user_repository, "get_user", load_current_user)
    monkeypatch.setattr(service._audit, "audit_denied", audit_denied)
    context = SimpleNamespace(
        login_info=SimpleNamespace(user_id=snapshot.user_id, token_version=snapshot.token_version),
        audit_source=AuditSource.HTTP,
    )

    with pytest.raises((SQLAlchemyError, AppError, PasswordBusyError)) as caught:
        await service.change_password(
            context=cast(Any, context),
            current_password="current-password",
            new_password="a-better-password",
        )

    if failure_case == "corrupt_hash":
        assert isinstance(caught.value, AppError)
        assert caught.value.status_code == 503
        assert caught.value.reason_code == "password_credential_unavailable"
        assert caught.value.__cause__ is failure
    else:
        assert caught.value is failure
    load_current_user.assert_awaited_once_with(session, user_id=snapshot.user_id, is_deleted=None)
    if failure_case == "database":
        manager.verify_or_dummy.assert_not_awaited()
    else:
        manager.verify_or_dummy.assert_awaited_once_with("current-password", snapshot.password_hash)
    audit_denied.assert_not_awaited()
    manager.hash_new_password.assert_not_awaited()
    session_factory.assert_called_once_with()
    session.begin.assert_not_called()


@pytest.mark.parametrize("changed_state", [None, "inactive", "token_version", "password_hash", "password_changed_at"])
async def test_self_change_rechecks_current_state_after_lock_free_password_work(
        monkeypatch: pytest.MonkeyPatch, changed_state: str | None) -> None:
    """
        本人改密在会话和锁外计算密码，写入前复查账号；中途停用、撤销或改密都不能覆盖新状态。

    :param monkeypatch: 隔离真实数据库和密码计算，保留真实认证业务流程。
    :param changed_state: None 验证成功，其余值模拟查询之后改变的账号字段。
    :return: 无返回值；成功时密码、版本和审计同事务，拒绝时不写入任何成功结果。
    """
    snapshot = _snapshot(password_hash="$argon2id$old")
    user = _snapshot_user(snapshot)
    assert user is not None and snapshot.password_changed_at is not None
    if changed_state == "inactive":
        user.is_active = False
    elif changed_state == "token_version":
        user.token_version += 1
    elif changed_state == "password_hash":
        user.password_hash = "$argon2id$concurrent-password"
    elif changed_state == "password_changed_at":
        password_changed_at = user.password_changed_at
        assert password_changed_at is not None
        user.password_changed_at = password_changed_at + timedelta(seconds=1)
    initial_version = user.token_version
    session_open = False
    transaction_open = False
    events: list[str] = []

    class SessionContext:
        async def __aenter__(self) -> object:
            nonlocal session_open
            session_open = True
            return session

        async def __aexit__(self, *_args: object) -> None:
            nonlocal session_open
            session_open = False

    class Transaction:
        async def __aenter__(self) -> None:
            nonlocal transaction_open
            transaction_open = True

        async def __aexit__(self, *_args: object) -> None:
            nonlocal transaction_open
            transaction_open = False

    session = SimpleNamespace(begin=Transaction, add=Mock())

    async def verify_password(_password: str, password_hash: str | None) -> PasswordVerification:
        assert not session_open and not transaction_open
        assert password_hash == snapshot.password_hash
        events.append("verify")
        return PasswordVerification(True, False, False)

    async def hash_password(_password: str, *, user_name: str | None) -> str:
        assert not session_open and not transaction_open
        assert user_name == snapshot.user_name
        events.append("hash")
        return "$argon2id$new"

    async def lock_users(_session: object, user_ids: set[str]) -> dict[str, User]:
        assert transaction_open and user_ids == {snapshot.user_id}
        events.append("lock")
        return {snapshot.user_id: user}

    async def update_password(_session: object, *, user: User, password_hash: str) -> None:
        assert transaction_open and password_hash == "$argon2id$new"
        events.append("rotate")
        user.password_hash = password_hash

    def add_audit(_event: object) -> None:
        assert transaction_open
        events.append("audit")

    session.add.side_effect = add_audit
    manager = Mock(verify_or_dummy=AsyncMock(side_effect=verify_password),
                   hash_new_password=AsyncMock(side_effect=hash_password))
    service = AuthService(cast(async_sessionmaker[AsyncSession], Mock(side_effect=SessionContext)), manager)
    context = SimpleNamespace(login_info=SimpleNamespace(user_id=snapshot.user_id,
                                                         token_version=snapshot.token_version),
                              audit_source=AuditSource.HTTP)
    monkeypatch.setattr(user_repository, "get_user", AsyncMock(return_value=_snapshot_user(snapshot)))
    monkeypatch.setattr(rbac_state_repository, "lock_rbac_state", AsyncMock())
    monkeypatch.setattr(user_repository, "lock_users", lock_users)
    rotate = AsyncMock(side_effect=update_password)
    monkeypatch.setattr(user_repository, "update_password", rotate)

    if changed_state is None:
        await service.change_password(context=cast(Any, context), current_password="old-password",
                                      new_password="new-password")
        assert user.token_version == initial_version + 1
        assert events == ["verify", "hash", "lock", "rotate", "audit"]
        assert session.add.call_args.args[0].outcome == "succeeded"
    else:
        with pytest.raises(AppError) as caught:
            await service.change_password(context=cast(Any, context), current_password="old-password",
                                          new_password="new-password")
        assert caught.value.status_code == 403
        assert caught.value.reason_code == "current_credential_changed"
        assert user.token_version == initial_version
        assert events == ["verify", "hash", "lock"]
        rotate.assert_not_awaited()
        session.add.assert_not_called()


@pytest.mark.parametrize(
    ("error", "should_write"),
    [
        (forbidden_403("target_not_allowed"), True),
        (unavailable_503("authorization_authority_unavailable"), False),
    ],
)
async def test_account_security_denial_audit_excludes_infrastructure_failures(error: AppError,
                                                                              should_write: bool) -> None:
    session = Mock(spec=AsyncSession)
    session.begin.return_value = AsyncMock()
    service = AuthService(cast(async_sessionmaker[AsyncSession],
                               Mock(return_value=_AsyncContext(session))), Mock())
    user_id = new_entity_id("U")
    target_user_id = new_entity_id("U")

    context = SimpleNamespace(login_info=SimpleNamespace(user_id=user_id), audit_source=AuditSource.HTTP)
    await service._audit.audit_denied(
        error=error,
        action=AccountAuditAction.ADMIN_RESET_PASSWORD,
        context=cast(Any, context),
        target_user_id=target_user_id,
    )

    if should_write:
        session.add.assert_called_once()
        event = session.add.call_args.args[0]
        assert event.reason_code == error.reason_code
        assert event.action == AccountAuditAction.ADMIN_RESET_PASSWORD
        assert event.category == "account" and event.outcome == "denied"
        assert event.user_id == user_id and event.target_user_id == target_user_id
        assert event.source == AuditSource.HTTP
    else:
        session.add.assert_not_called()
        session.begin.assert_not_called()


async def test_denial_audit_failure_preserves_the_original_permission_error() -> None:
    class _FailingTransaction:
        async def __aenter__(self) -> None:
            raise OSError("account audit unavailable")

        async def __aexit__(self, *_args: object) -> None:
            return None

    session = SimpleNamespace(begin=Mock(return_value=_FailingTransaction()))
    service = AuthService(
        cast(
            async_sessionmaker[AsyncSession], Mock(return_value=_AsyncContext(session))
        ),
        Mock(),
    )
    error = forbidden_403("target_not_allowed")

    with pytest.raises(AppError) as caught:
        try:
            raise error
        except AppError as exc:
            await service._audit.audit_denied(
                error=exc,
                action=AccountAuditAction.ADMIN_RESET_PASSWORD,
                target_user_id=new_entity_id("U"),
                source=AuditSource.HTTP,
            )
            raise

    assert caught.value is error


async def test_password_rotation_updates_user_row_and_timestamp() -> None:
    user_id = new_entity_id("U")
    old_timestamp = datetime.now(UTC)
    user = User(
        user_id=user_id,
        user_name="target",
        token_version=3,
        password_hash="$argon2id$old",
        password_changed_at=old_timestamp,
    )
    changed_at = datetime.now(UTC)
    session = Mock(spec=AsyncSession)
    session.scalar = AsyncMock(return_value=changed_at)

    await user_repository.update_password(
        cast(AsyncSession, session),
        user=user,
        password_hash="$argon2id$new",
    )

    assert user.user_id == user_id
    assert user.password_hash == "$argon2id$new"
    assert user.password_changed_at == changed_at
    assert user.token_version == 3
    session.scalar.assert_awaited_once()


async def test_successful_login_upgrades_a_stale_hash_after_rechecking_locks(monkeypatch: pytest.MonkeyPatch) -> None:
    old_hash = "$argon2id$v=19$m=32768,t=2,p=2$old-salt-value-123$old-hash-value-123"
    new_hash = "$argon2id$v=19$m=65536,t=3,p=4$new-salt-value-123$new-hash-value-123"
    snapshot = _snapshot(password_hash=old_hash)
    user = User(
        user_id=snapshot.user_id,
        user_name=snapshot.user_name,
        is_active=True,
        token_version=snapshot.token_version,
        password_hash=old_hash,
        password_changed_at=snapshot.password_changed_at,
    )
    session = SimpleNamespace(begin=Mock(return_value=_AsyncContext(None)))
    session_factory = Mock(return_value=_AsyncContext(session))
    manager = Mock()
    manager.verify_or_dummy = AsyncMock(
        return_value=PasswordVerification(
            verified=True,
            needs_rehash=True,
            used_dummy=False,
        )
    )
    manager.hash_verified_password = AsyncMock(return_value=new_hash)
    service = AuthService(
        cast(async_sessionmaker[AsyncSession], session_factory),
        manager,
    )
    monkeypatch.setattr(
        user_repository,
        "get_user",
        AsyncMock(return_value=_snapshot_user(snapshot)),
    )
    monkeypatch.setattr(
        user_repository,
        "lock_users",
        AsyncMock(return_value={snapshot.user_id: user}),
    )

    identity = await service.login(
        redis=LOGIN_REDIS,
        settings=get_settings(),
        user_name="alice",
        password="verified legacy password",
    )

    assert identity.user_id == snapshot.user_id
    assert user.password_hash == new_hash
    assert user.password_changed_at == snapshot.password_changed_at
    assert user.token_version == snapshot.token_version
    manager.verify_or_dummy.assert_awaited_once_with("verified legacy password", old_hash)
    manager.hash_verified_password.assert_awaited_once_with("verified legacy password")


async def test_concurrent_stale_hash_upgrade_rejects_without_retry_or_overwrite(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
        别的登录已升级哈希时直接拒绝本次登录，不再验证第二轮，也不覆盖新哈希。

    :param monkeypatch: 隔离查询和行锁，模拟密码计算期间完成的并发哈希升级。
    :return: 无返回值；断言仅验证一次，且第一次加锁发现变化就结束。
    """
    old_hash = "$argon2id$v=19$m=32768,t=2,p=2$old-salt-value-123$old-hash-value-123"
    current_hash = (
        "$argon2id$v=19$m=65536,t=3,p=4$current-salt-value$current-hash-value"
    )
    snapshot = _snapshot(password_hash=old_hash)
    user = User(
        user_id=snapshot.user_id,
        user_name=snapshot.user_name,
        is_active=True,
        token_version=snapshot.token_version,
        password_hash=current_hash,
        password_changed_at=snapshot.password_changed_at,
    )
    transaction_open = False
    events: list[str] = []

    class _Transaction:
        async def __aenter__(self) -> None:
            nonlocal transaction_open
            assert not transaction_open
            transaction_open = True
            events.append("transaction.enter")

        async def __aexit__(self, *_args: object) -> None:
            nonlocal transaction_open
            transaction_open = False
            events.append("transaction.exit")

    session = SimpleNamespace(begin=Mock(side_effect=_Transaction))
    query_session = AsyncMock(spec=AsyncSession)
    query_session.__aenter__.return_value = query_session
    session_factory = Mock(side_effect=[query_session, _AsyncContext(session)])
    manager = Mock()

    async def verify_or_dummy(_password: str, password_hash: str | None) -> PasswordVerification:
        query_session.__aexit__.assert_awaited_once_with(None, None, None)
        assert not transaction_open
        assert password_hash == old_hash
        events.append("argon2.verify.old")
        return PasswordVerification(True, True, False)

    async def hash_verified_password(_password: str) -> str:
        assert not transaction_open
        events.append("argon2.hash.replacement")
        return "$argon2id$unused"

    async def lock_current_users(_session: object, _user_ids: set[str]) -> dict[str, User]:
        assert transaction_open
        events.append("database.lock.user")
        return {snapshot.user_id: user}

    manager.verify_or_dummy = AsyncMock(side_effect=verify_or_dummy)
    manager.hash_verified_password = AsyncMock(side_effect=hash_verified_password)
    service = AuthService(
        cast(async_sessionmaker[AsyncSession], session_factory),
        manager,
    )
    load_login_user = AsyncMock(return_value=_snapshot_user(snapshot))
    monkeypatch.setattr(
        user_repository,
        "get_user",
        load_login_user,
    )
    monkeypatch.setattr(user_repository, "lock_users", lock_current_users)

    with pytest.raises(InvalidLoginCredentialsError):
        await service.login(redis=LOGIN_REDIS, settings=get_settings(),
                            user_name="alice", password="verified legacy password")

    assert user.password_hash == current_hash
    assert user.password_changed_at == snapshot.password_changed_at
    assert user.token_version == snapshot.token_version
    load_login_user.assert_awaited_once_with(query_session, user_name="alice", is_deleted=None)
    manager.verify_or_dummy.assert_awaited_once_with("verified legacy password", old_hash)
    manager.hash_verified_password.assert_awaited_once_with("verified legacy password")
    assert session_factory.call_count == 2
    assert events == [
        "argon2.verify.old",
        "argon2.hash.replacement",
        "transaction.enter",
        "database.lock.user",
        "transaction.exit",
    ]


@pytest.mark.parametrize(
    "changed_state",
    ["missing", "deleted", "token_version", "inactive", "password_changed_at", "password_hash"],
)
async def test_login_first_lock_rejects_changed_authoritative_state(monkeypatch: pytest.MonkeyPatch,
                                                                    changed_state: str,
                                                                    issue_token: AsyncMock) -> None:
    """
        锁外验证后账号被删除、停用、撤销或改密时，在第一次加锁时直接拒绝。

    :param monkeypatch: 隔离数据库，在首次查询和加锁查询之间放入并发变化。
    :param changed_state: 需要模拟的账号变化，每个变化单独验证拒绝边界。
    :param issue_token: 隔离真实 Redis，确认账号变化后不签发令牌。
    :return: 无返回值；密码仅验证一遍，并发状态与已有哈希均保持不变。
    """
    old_hash = "$argon2id$v=19$m=32768,t=2,p=2$old-salt-value-123$old-hash-value-123"
    snapshot = _snapshot(password_hash=old_hash)
    assert snapshot.password_changed_at is not None
    user = User(
        user_id=snapshot.user_id,
        user_name=snapshot.user_name,
        is_active=changed_state != "inactive",
        deleted_at=datetime.now(UTC) if changed_state == "deleted" else None,
        token_version=(
            snapshot.token_version + 1
            if changed_state == "token_version"
            else snapshot.token_version
        ),
        password_hash=(
            "$argon2id$changed" if changed_state == "password_hash" else old_hash
        ),
        password_changed_at=(
            snapshot.password_changed_at + timedelta(seconds=1)
            if changed_state == "password_changed_at"
            else snapshot.password_changed_at
        ),
    )
    session = SimpleNamespace(begin=Mock(return_value=_AsyncContext(None)))
    manager = Mock()
    manager.verify_or_dummy = AsyncMock(
        return_value=PasswordVerification(True, True, False)
    )
    manager.hash_verified_password = AsyncMock(return_value="$argon2id$replacement")
    service = AuthService(
        cast(
            async_sessionmaker[AsyncSession],
            Mock(return_value=_AsyncContext(session)),
        ),
        manager,
    )
    monkeypatch.setattr(
        user_repository,
        "get_user",
        AsyncMock(return_value=_snapshot_user(snapshot)),
    )
    lock_users = AsyncMock(return_value={} if changed_state == "missing" else {snapshot.user_id: user})
    monkeypatch.setattr(user_repository, "lock_users", lock_users)
    concurrent_state = (user.password_hash, user.password_changed_at, user.token_version,
                        user.is_active, user.deleted_at)

    with pytest.raises(InvalidLoginCredentialsError):
        await service.login(
            redis=LOGIN_REDIS,
            settings=get_settings(),
            user_name="alice",
            password="verified legacy password",
        )

    manager.verify_or_dummy.assert_awaited_once_with("verified legacy password", old_hash)
    manager.hash_verified_password.assert_awaited_once_with("verified legacy password")
    lock_users.assert_awaited_once()
    assert session.begin.call_count == 1
    assert (user.password_hash, user.password_changed_at, user.token_version,
            user.is_active, user.deleted_at) == concurrent_state
    issue_token.assert_not_awaited()


async def test_login_rejects_token_version_change_before_hash_upgrade_lock(monkeypatch: pytest.MonkeyPatch) -> None:
    old_hash = "$argon2id$v=19$m=32768,t=2,p=2$old-salt-value-123$old-hash-value-123"
    snapshot = _snapshot(password_hash=old_hash)
    user = User(
        user_id=snapshot.user_id,
        user_name=snapshot.user_name,
        is_active=True,
        token_version=snapshot.token_version + 1,
        password_hash=old_hash,
        password_changed_at=snapshot.password_changed_at,
    )
    session = SimpleNamespace(begin=Mock(return_value=_AsyncContext(None)))
    manager = Mock()
    manager.verify_or_dummy = AsyncMock(
        return_value=PasswordVerification(True, False, False)
    )
    manager.hash_verified_password = AsyncMock()
    service = AuthService(
        cast(
            async_sessionmaker[AsyncSession],
            Mock(return_value=_AsyncContext(session)),
        ),
        manager,
    )
    monkeypatch.setattr(
        user_repository,
        "get_user",
        AsyncMock(return_value=_snapshot_user(snapshot)),
    )
    monkeypatch.setattr(
        user_repository,
        "lock_users",
        AsyncMock(return_value={snapshot.user_id: user}),
    )

    with pytest.raises(InvalidLoginCredentialsError):
        await service.login(
            redis=LOGIN_REDIS,
            settings=get_settings(),
            user_name="alice",
            password="verified password",
        )

    manager.hash_verified_password.assert_not_awaited()


async def test_concurrent_password_change_cancels_stale_hash_upgrade(monkeypatch: pytest.MonkeyPatch) -> None:
    old_hash = "$argon2id$v=19$m=32768,t=2,p=2$old-salt-value-123$old-hash-value-123"
    concurrent_hash = (
        "$argon2id$v=19$m=65536,t=3,p=4$concurrent-salt-12$concurrent-hash-12"
    )
    snapshot = _snapshot(password_hash=old_hash)
    assert snapshot.password_changed_at is not None
    user = User(
        user_id=snapshot.user_id,
        user_name=snapshot.user_name,
        is_active=True,
        token_version=snapshot.token_version,
        password_hash=concurrent_hash,
        password_changed_at=snapshot.password_changed_at + timedelta(seconds=1),
    )
    session = SimpleNamespace(begin=Mock(return_value=_AsyncContext(None)))
    manager = Mock()
    manager.verify_or_dummy = AsyncMock(
        return_value=PasswordVerification(
            verified=True,
            needs_rehash=True,
            used_dummy=False,
        )
    )
    manager.hash_verified_password = AsyncMock(return_value="$argon2id$replacement")
    service = AuthService(
        cast(
            async_sessionmaker[AsyncSession],
            Mock(return_value=_AsyncContext(session)),
        ),
        manager,
    )
    monkeypatch.setattr(
        user_repository,
        "get_user",
        AsyncMock(return_value=_snapshot_user(snapshot)),
    )
    monkeypatch.setattr(
        user_repository,
        "lock_users",
        AsyncMock(return_value={snapshot.user_id: user}),
    )

    with pytest.raises(InvalidLoginCredentialsError):
        await service.login(
            redis=LOGIN_REDIS,
            settings=get_settings(),
            user_name="alice",
            password="verified legacy password",
        )

    assert user.password_hash == concurrent_hash


@pytest.mark.parametrize("holder_case", ["none", "different", "multiple"])
async def test_operator_reset_requires_the_exact_super_admin_holder_set(monkeypatch: pytest.MonkeyPatch,
                                                                        holder_case: str) -> None:
    user_id = new_entity_id("U")
    user = User(user_id=user_id, user_name="recovery-target", is_active=True)
    session = SimpleNamespace(
        add=Mock(),
        begin=Mock(return_value=_AsyncContext(None)),
    )
    session_factory = Mock(return_value=_AsyncContext(session))
    manager = Mock()
    manager.hash_new_password = AsyncMock(return_value="$argon2id$new")
    service = OperatorPasswordService(
        cast(async_sessionmaker[AsyncSession], session_factory),
        manager,
    )

    calls: list[str] = []

    async def lock_state(locked_session: object) -> None:
        assert locked_session is session
        calls.append("rbac_state")

    async def lock_target(locked_session: object, user_ids: set[str]) -> dict[str, User]:
        assert locked_session is session
        assert user_ids == {user_id}
        calls.append("users")
        return {user_id: user}

    other_id = new_entity_id("U")
    holder_ids = {
        "none": frozenset(),
        "different": frozenset({other_id}),
        "multiple": frozenset({user_id, other_id}),
    }[holder_case]

    async def load_holders(locked_session: object) -> frozenset[str]:
        assert locked_session is session
        calls.append("holders")
        return holder_ids

    monkeypatch.setattr(rbac_state_repository, "lock_rbac_state", lock_state)
    monkeypatch.setattr(
        user_repository,
        "lock_users",
        lock_target,
    )
    monkeypatch.setattr(
        operator_password_repository,
        "load_live_super_admin_holder_ids",
        load_holders,
    )
    load_authority = AsyncMock()
    monkeypatch.setattr(
        user_repository,
        "get_user_permissions",
        load_authority,
    )

    with pytest.raises(AppError) as caught:
        await service.reset_super_admin_password(
            user_id=user_id,
            new_password="recovery-password-42",
        )

    assert caught.value.status_code == 409
    assert caught.value.reason_code == "operator_reset_requires_sole_super_admin"
    assert calls == ["rbac_state", "users", "holders"]
    load_authority.assert_not_awaited()
    session.add.assert_not_called()


async def test_operator_reset_accepts_only_the_target_as_sole_super_admin(monkeypatch: pytest.MonkeyPatch,
                                                                          audit_request_context: str) -> None:
    user_id = new_entity_id("U")
    new_password = "recovery-password-42"
    user = User(
        user_id=user_id,
        user_name="recovery-target",
        is_active=True,
        token_version=7,
    )
    session = SimpleNamespace(
        add=Mock(),
        begin=Mock(return_value=_AsyncContext(None)),
    )
    session_factory = Mock(return_value=_AsyncContext(session))
    manager = Mock()
    manager.hash_new_password = AsyncMock(return_value="$argon2id$new")
    service = OperatorPasswordService(
        cast(async_sessionmaker[AsyncSession], session_factory),
        manager,
    )
    calls: list[str] = []

    async def lock_state(locked_session: object) -> None:
        assert locked_session is session
        calls.append("rbac_state")

    async def lock_target(locked_session: object, user_ids: set[str]) -> dict[str, User]:
        assert locked_session is session
        assert user_ids == {user_id}
        calls.append("users")
        return {user_id: user}

    async def load_holders(locked_session: object) -> frozenset[str]:
        assert locked_session is session
        calls.append("holders")
        return frozenset({user_id})

    async def load_authority(locked_session: object, *, users: tuple[User, ...]) -> dict[str, SimpleNamespace]:
        assert locked_session is session
        assert users == (user,)
        calls.append("authority")
        return {user_id: SimpleNamespace(user_info_with_disabled_roles=SimpleNamespace(is_super_admin=True))}

    update_password = AsyncMock()
    monkeypatch.setattr(rbac_state_repository, "lock_rbac_state", lock_state)
    monkeypatch.setattr(user_repository, "lock_users", lock_target)
    monkeypatch.setattr(
        operator_password_repository,
        "load_live_super_admin_holder_ids",
        load_holders,
    )
    monkeypatch.setattr(
        user_repository,
        "get_user_permissions",
        load_authority,
    )
    monkeypatch.setattr(user_repository, "update_password", update_password)

    changed = await service.reset_super_admin_password(
        user_id=user_id,
        new_password=new_password,
    )

    assert changed is True
    assert calls == ["rbac_state", "users", "holders", "authority"]
    assert user.token_version == 8
    update_password.assert_awaited_once_with(
        session,
        user=user,
        password_hash="$argon2id$new",
    )
    event = session.add.call_args.args[0]
    assert event.action == "account_security.password.operator_reset"
    assert event.reason_code == "permanent_password_set"
    assert event.target_user_id == user_id
    assert event.request_id == audit_request_context


@pytest.mark.parametrize("revoked_after_hash", [False, True])
async def test_admin_reset_rechecks_authority_after_lock_free_hash(
        monkeypatch: pytest.MonkeyPatch, revoked_after_hash: bool) -> None:
    """
        管理员改密先确认目标，锁外计算后再次授权；并发撤权不能写密码或成功审计。

    :param monkeypatch: 隔离真实数据库和耗时密码运算的测试补丁。
    :param revoked_after_hash: 模拟密码计算期间被撤销管理员权限。
    :return: 无返回值，验证顺序、失败边界、Token 版本和成功审计。
    """
    in_transaction = False
    calls: list[str] = []

    class Transaction:
        async def __aenter__(self) -> None:
            """
                标记业务事务开始，供哈希回调检查没有持锁运算。

            :return: 无返回值。
            """
            nonlocal in_transaction
            in_transaction = True

        async def __aexit__(self, *_args: object) -> None:
            """
                记录事务退出，模拟提交或回滚后的无锁状态。

            :param _args: 上下文退出时的异常信息。
            :return: 无返回值。
            """
            nonlocal in_transaction
            in_transaction = False

    target = User(user_id=new_entity_id("U"), user_name="target_account", is_active=True, token_version=3)
    context = SimpleNamespace(login_info=SimpleNamespace(user_id=new_entity_id("U")), audit_source=AuditSource.HTTP)
    session = SimpleNamespace(begin=Transaction, add=Mock())
    session_factory = Mock(return_value=_AsyncContext(session))

    async def hash_password(_password: str, *, user_name: str | None) -> str:
        """
            确认哈希计算发生在两个授权事务之间，并使用初查的身份值。

        :param _password: 管理员提交的新密码。
        :param user_name: 密码策略比较的目标用户名。
        :return: 不依赖真实密码计算的测试哈希。
        """
        assert not in_transaction
        assert user_name == target.user_name
        calls.append("hash")
        return "$argon2id$new"

    manager = Mock(hash_new_password=AsyncMock(side_effect=hash_password))
    service = UserService(cast(async_sessionmaker[AsyncSession], session_factory), manager)

    async def authorize(_session: object, **_kwargs: object) -> User:
        """
            模拟加锁授权，必要时在第二次检查中拒绝已经撤权的操作者。

        :param _session: 当前业务事务会话。
        :param _kwargs: 操作者与目标用户参数。
        :return: 可管理的目标用户；并发撤权场景抛出权限错误。
        """
        assert in_transaction
        calls.append("authorize")
        if revoked_after_hash and calls.count("authorize") == 2:
            raise forbidden_403("missing_operation_permission")
        return target

    update_password = AsyncMock()
    denial = AsyncMock()
    monkeypatch.setattr(service, "_lock_authorized_reset_target", authorize)
    monkeypatch.setattr(user_repository, "update_password", update_password)
    monkeypatch.setattr(service._audit, "audit_denied", denial)
    if revoked_after_hash:
        with pytest.raises(AppError) as caught:
            await service.reset_user_password(context=cast(Any, context), target_user_id=target.user_id,
                                              new_password="new-safe-password-value")
        assert caught.value.reason_code == "missing_operation_permission"
        update_password.assert_not_awaited()
        session.add.assert_not_called()
        assert target.token_version == 3
        denial.assert_awaited_once()
    else:
        await service.reset_user_password(
            context=cast(Any, context), target_user_id=target.user_id,
            new_password="new-safe-password-value")
        assert target.token_version == 4
        assert update_password.await_args is not None
        assert update_password.await_args.kwargs["password_hash"] == "$argon2id$new"
        assert session.add.call_args.args[0].action == "account_security.password.admin_reset"
        denial.assert_not_awaited()
    assert calls == ["authorize", "hash", "authorize"]
