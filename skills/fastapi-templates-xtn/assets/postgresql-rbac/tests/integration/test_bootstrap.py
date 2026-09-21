import uuid
from datetime import UTC, datetime
from pathlib import Path

import asyncpg  # type: ignore[import-untyped]
import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.engine import make_url

from app.core.config import get_settings
from app.core.errors import RbacError
from app.core.security.domain import (
    MAX_ROLES_PER_USER,
    PERMISSION_CATALOG,
    SUPER_ADMIN_PERMISSION_KEYS,
    SYSTEM_ROLE_KEYS,
    SYSTEM_ROLE_SPECS,
    SystemRoleKey,
)
from app.db.postgres import SessionFactory
from app.models.access import (
    Permission,
    RbacAuditEvent,
    RbacState,
    Role,
    RolePermission,
    User,
    UserRole,
)
from app.services.provisioning import create_user_with_default_role

pytestmark = pytest.mark.postgresql

ASSET_ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP_SQL = ASSET_ROOT / "sql" / "bootstrap_super_admin.sql"
HANDOVER_SQL = ASSET_ROOT / "sql" / "handover_super_admin.sql"
PSQL_PREAMBLE = "\\set ON_ERROR_STOP on\n"
USER_ID_MARKER = ":'super_admin_user_id'"


def _render_bootstrap_sql(user_id: uuid.UUID | str) -> str:
    script = BOOTSTRAP_SQL.read_text(encoding="utf-8")
    assert script.startswith(PSQL_PREAMBLE)
    assert script.count(USER_ID_MARKER) == 1
    escaped_user_id = str(user_id).replace("'", "''")
    return script.removeprefix(PSQL_PREAMBLE).replace(
        USER_ID_MARKER,
        f"'{escaped_user_id}'",
    )


async def _run_bootstrap(user_id: uuid.UUID | str) -> None:
    url = make_url(get_settings().database_url)
    connection = await asyncpg.connect(
        host=url.host,
        port=url.port or 5432,
        user=url.username,
        password=url.password,
        database=url.database,
    )
    try:
        await connection.execute(_render_bootstrap_sql(user_id))
    finally:
        await connection.close()


async def _run_handover(old_id: uuid.UUID | str, new_id: uuid.UUID | str) -> None:
    script = HANDOVER_SQL.read_text(encoding="utf-8")
    assert script.startswith(PSQL_PREAMBLE)
    markers = {
        ":'old_super_admin_user_id'": old_id,
        ":'new_super_admin_user_id'": new_id,
    }
    for marker, value in markers.items():
        assert script.count(marker) == 1
        script = script.replace(marker, "'" + str(value).replace("'", "''") + "'")
    url = make_url(get_settings().database_url)
    connection = await asyncpg.connect(
        host=url.host,
        port=url.port or 5432,
        user=url.username,
        password=url.password,
        database=url.database,
    )
    try:
        await connection.execute(script.removeprefix(PSQL_PREAMBLE))
    finally:
        await connection.close()


async def _provision_user(
    user_name: str,
) -> User:
    async with SessionFactory() as session:
        async with session.begin():
            return await create_user_with_default_role(
                session,
                user_name=user_name,
                request_id=f"provision:{uuid.uuid4()}",
            )


async def _add_live_custom_roles(*, user_id: uuid.UUID, count: int) -> None:
    async with SessionFactory() as session:
        async with session.begin():
            roles = [
                Role(
                    key=f"bootstrap-limit-{index}-{uuid.uuid4().hex[:8]}",
                    name=f"Bootstrap limit {index}",
                    management_tier=10,
                )
                for index in range(count)
            ]
            session.add_all(roles)
            await session.flush()
            session.add_all(
                UserRole(user_id=user_id, role_id=role.id, assigned_by_user_id=None)
                for role in roles
            )


async def test_operator_sql_assigns_existing_super_admin_atomically() -> None:
    candidate = await _provision_user(user_name="bootstrap_super_admin")
    async with SessionFactory() as session:
        state_before = await session.get(RbacState, "global")
        user_before = await session.get(User, candidate.id)
        assert state_before is not None and user_before is not None
        epoch_before = state_before.epoch
        authz_version_before = user_before.authz_version
        token_version_before = user_before.token_version

    await _run_bootstrap(candidate.id)

    async with SessionFactory() as session:
        roles = {
            role.key: role
            for role in (
                await session.scalars(
                    select(Role).where(Role.key.in_(SYSTEM_ROLE_KEYS))
                )
            ).all()
        }
        assignments = (
            await session.execute(
                select(UserRole, Role.key)
                .join(Role, Role.id == UserRole.role_id)
                .where(
                    UserRole.user_id == candidate.id,
                    UserRole.deleted_at.is_(None),
                )
            )
        ).all()
        grants = (
            await session.execute(
                select(Permission.key)
                .select_from(RolePermission)
                .join(Permission, Permission.id == RolePermission.permission_id)
                .where(
                    RolePermission.role_id == roles[SystemRoleKey.SUPER_ADMIN.value].id
                )
            )
        ).all()
        audit = await session.scalar(
            select(RbacAuditEvent).where(
                RbacAuditEvent.action == "super_admin.bootstrap"
            )
        )
        state_after = await session.get(RbacState, "global")
        user_after = await session.get(User, candidate.id)

    assert set(roles) == SYSTEM_ROLE_KEYS
    for key, spec in SYSTEM_ROLE_SPECS.items():
        role = roles[key.value]
        assert role.management_tier == spec.management_tier
        assert role.is_system
        assert role.is_protected == spec.is_protected
        assert role.is_super_admin == spec.is_super_admin
        assert role.is_active
        assert role.deleted_at is None
    assert {row.key for row in assignments} == {
        SystemRoleKey.SUPER_ADMIN.value,
        SystemRoleKey.USER.value,
    }
    assert {row.key for row in grants} == SUPER_ADMIN_PERMISSION_KEYS
    assert state_after is not None and state_after.epoch == epoch_before + 1
    assert user_after is not None
    assert user_after.authz_version == authz_version_before + 1
    assert user_after.token_version == token_version_before
    assert not user_after.is_protected
    assert audit is not None
    assert audit.decision == "allowed"
    assert audit.source == "operator"
    assert audit.schema_version == 1
    assert audit.reason_code == "explicit_super_admin_bootstrap"
    assert audit.after_state is not None and audit.after_state["changed"] is True


async def test_operator_sql_uses_the_tenth_role_slot_and_replays_idempotently() -> None:
    candidate = await _provision_user(user_name="bootstrap_limit_nine")
    await _add_live_custom_roles(
        user_id=candidate.id,
        count=MAX_ROLES_PER_USER - 2,
    )

    await _run_bootstrap(candidate.id)
    await _run_bootstrap(candidate.id)

    async with SessionFactory() as session:
        live_count = await session.scalar(
            select(func.count(UserRole.id)).where(
                UserRole.user_id == candidate.id,
                UserRole.deleted_at.is_(None),
            )
        )
    assert live_count == MAX_ROLES_PER_USER


async def test_operator_sql_rejects_a_full_target_without_partial_changes() -> None:
    candidate = await _provision_user(user_name="bootstrap_limit_full")
    await _add_live_custom_roles(
        user_id=candidate.id,
        count=MAX_ROLES_PER_USER - 1,
    )
    async with SessionFactory() as session:
        state_before = await session.get(RbacState, "global")
        user_before = await session.get(User, candidate.id)
        audit_count_before = await session.scalar(
            select(func.count())
            .select_from(RbacAuditEvent)
            .where(RbacAuditEvent.action == "super_admin.bootstrap")
        )
        assert state_before is not None and user_before is not None
        epoch_before = state_before.epoch
        authz_version_before = user_before.authz_version

    with pytest.raises(
        asyncpg.PostgresError,
        match="already has 10 live role assignments",
    ):
        await _run_bootstrap(candidate.id)

    async with SessionFactory() as session:
        super_admin_role = await session.scalar(
            select(Role).where(Role.key == SystemRoleKey.SUPER_ADMIN.value)
        )
        assert super_admin_role is not None
        assignment = await session.scalar(
            select(UserRole).where(
                UserRole.user_id == candidate.id,
                UserRole.role_id == super_admin_role.id,
                UserRole.deleted_at.is_(None),
            )
        )
        state_after = await session.get(RbacState, "global")
        user_after = await session.get(User, candidate.id)
        audit_count_after = await session.scalar(
            select(func.count())
            .select_from(RbacAuditEvent)
            .where(RbacAuditEvent.action == "super_admin.bootstrap")
        )
    assert assignment is None
    assert state_after is not None and state_after.epoch == epoch_before
    assert user_after is not None
    assert user_after.authz_version == authz_version_before
    assert audit_count_after == audit_count_before


async def test_permission_catalog_matches_runtime_contract() -> None:
    async with SessionFactory() as session:
        rows = (
            await session.execute(
                select(Permission.key, Permission.description).where(
                    Permission.key.in_([item.value for item in PERMISSION_CATALOG])
                )
            )
        ).all()

    assert {row.key: row.description for row in rows} == {
        key.value: description for key, description in PERMISSION_CATALOG.items()
    }


async def test_operator_sql_does_not_grant_unknown_global_permission() -> None:
    extra_permission = Permission(
        id=uuid.uuid4(),
        key="platform:break_glass",
        description="Emergency-only permission",
    )
    async with SessionFactory() as session:
        session.add(extra_permission)
        await session.commit()

    try:
        candidate = await _provision_user("isolated_super_admin")
        await _run_bootstrap(candidate.id)
        async with SessionFactory() as session:
            role = await session.scalar(
                select(Role).where(Role.key == SystemRoleKey.SUPER_ADMIN.value)
            )
            assert role is not None
            unexpected_grant = await session.scalar(
                select(RolePermission).where(
                    RolePermission.role_id == role.id,
                    RolePermission.permission_id == extra_permission.id,
                )
            )
        assert unexpected_grant is None
    finally:
        async with SessionFactory() as session:
            await session.execute(
                delete(Permission).where(Permission.id == extra_permission.id)
            )
            await session.commit()


async def test_operator_sql_requires_an_existing_identity_and_rolls_back() -> None:
    missing_user_id = uuid.uuid4()
    with pytest.raises(
        asyncpg.PostgresError,
        match="target user account does not exist",
    ):
        await _run_bootstrap(missing_user_id)

    async with SessionFactory() as session:
        missing = await session.get(User, missing_user_id)
        audit_count = await session.scalar(
            select(func.count()).select_from(RbacAuditEvent)
        )
    assert missing is None
    assert audit_count == 0


async def test_operator_sql_rejects_disabled_identity_and_rolls_back() -> None:
    candidate = await _provision_user("disabled_super_admin")
    async with SessionFactory() as session:
        async with session.begin():
            stored = await session.get(User, candidate.id)
            state = await session.get(RbacState, "global")
            assert stored is not None and state is not None
            stored.is_active = False
            epoch_before = state.epoch
            version_before = stored.authz_version

    with pytest.raises(
        asyncpg.PostgresError,
        match="target user must be active, not system-protected, and not deleted",
    ):
        await _run_bootstrap(candidate.id)

    async with SessionFactory() as session:
        super_admin_role = await session.scalar(
            select(Role).where(Role.key == SystemRoleKey.SUPER_ADMIN.value)
        )
        state_after = await session.get(RbacState, "global")
        user_after = await session.get(User, candidate.id)
        assert super_admin_role is not None
        assignment = await session.scalar(
            select(UserRole).where(
                UserRole.user_id == candidate.id,
                UserRole.role_id == super_admin_role.id,
                UserRole.deleted_at.is_(None),
            )
        )
    assert assignment is None
    assert state_after is not None and state_after.epoch == epoch_before
    assert user_after is not None and user_after.authz_version == version_before


async def test_operator_sql_rejects_deleted_identity_and_rolls_back() -> None:
    candidate = await _provision_user("deleted_super_admin")
    async with SessionFactory() as session:
        async with session.begin():
            stored = await session.get(User, candidate.id)
            state = await session.get(RbacState, "global")
            assert stored is not None and state is not None
            stored.is_active = False
            stored.deleted_at = datetime.now(UTC)
            epoch_before = state.epoch
            version_before = stored.authz_version

    with pytest.raises(
        asyncpg.PostgresError,
        match="target user must be active, not system-protected, and not deleted",
    ):
        await _run_bootstrap(candidate.id)

    async with SessionFactory() as session:
        super_admin_role = await session.scalar(
            select(Role).where(Role.key == SystemRoleKey.SUPER_ADMIN.value)
        )
        state_after = await session.get(RbacState, "global")
        user_after = await session.get(User, candidate.id)
        assert super_admin_role is not None
        assignment = await session.scalar(
            select(UserRole).where(
                UserRole.user_id == candidate.id,
                UserRole.role_id == super_admin_role.id,
                UserRole.deleted_at.is_(None),
            )
        )
    assert assignment is None
    assert state_after is not None and state_after.epoch == epoch_before
    assert user_after is not None and user_after.authz_version == version_before


async def test_operator_sql_refuses_a_second_super_admin() -> None:
    first = await _provision_user("first_super_admin")
    second = await _provision_user("second_super_admin")
    await _run_bootstrap(first.id)

    async with SessionFactory() as session:
        state_before = await session.get(RbacState, "global")
        second_before = await session.get(User, second.id)
        assert state_before is not None and second_before is not None
        epoch_before = state_before.epoch
        version_before = second_before.authz_version

    with pytest.raises(
        asyncpg.PostgresError,
        match="a different super_admin already exists",
    ):
        await _run_bootstrap(second.id)

    async with SessionFactory() as session:
        super_admin_role = await session.scalar(
            select(Role).where(Role.key == SystemRoleKey.SUPER_ADMIN.value)
        )
        assert super_admin_role is not None
        holders = (
            await session.scalars(
                select(UserRole).where(
                    UserRole.role_id == super_admin_role.id,
                    UserRole.deleted_at.is_(None),
                )
            )
        ).all()
        state_after = await session.get(RbacState, "global")
        second_after = await session.get(User, second.id)
    assert [assignment.user_id for assignment in holders] == [first.id]
    assert state_after is not None and state_after.epoch == epoch_before
    assert second_after is not None and second_after.authz_version == version_before


async def test_operator_sql_same_identity_is_idempotent() -> None:
    candidate = await _provision_user("idempotent_super_admin")
    await _run_bootstrap(candidate.id)
    async with SessionFactory() as session:
        state_before = await session.get(RbacState, "global")
        user_before = await session.get(User, candidate.id)
        audit_count_before = await session.scalar(
            select(func.count())
            .select_from(RbacAuditEvent)
            .where(RbacAuditEvent.action == "super_admin.bootstrap")
        )
        assert state_before is not None and user_before is not None
        assert audit_count_before is not None
        epoch_before = state_before.epoch
        version_before = user_before.authz_version

    await _run_bootstrap(candidate.id)

    async with SessionFactory() as session:
        state_after = await session.get(RbacState, "global")
        user_after = await session.get(User, candidate.id)
        audit_count_after = await session.scalar(
            select(func.count())
            .select_from(RbacAuditEvent)
            .where(RbacAuditEvent.action == "super_admin.bootstrap")
        )
        replay_audit = await session.scalar(
            select(RbacAuditEvent).where(
                RbacAuditEvent.reason_code == "super_admin_already_bootstrapped"
            )
        )
    assert state_after is not None and state_after.epoch == epoch_before
    assert user_after is not None and user_after.authz_version == version_before
    assert audit_count_after == audit_count_before + 1
    assert replay_audit is not None
    assert replay_audit.after_state is not None
    assert replay_audit.after_state["changed"] is False


async def test_operator_sql_rejects_empty_user_id() -> None:
    with pytest.raises(asyncpg.PostgresError, match="must not be empty"):
        await _run_bootstrap("  ")


async def test_operator_sql_rejects_non_v4_user_id() -> None:
    with pytest.raises(asyncpg.PostgresError, match="must be a UUIDv4 value"):
        await _run_bootstrap(uuid.uuid1())


async def test_operator_handover_replaces_holder_and_revokes_both_sessions() -> None:
    old = await _provision_user("outgoing_admin")
    new = await _provision_user("incoming_admin")
    await _run_bootstrap(old.id)
    async with SessionFactory() as session:
        state_before = await session.get(RbacState, "global")
        old_before = await session.get(User, old.id)
        new_before = await session.get(User, new.id)
        assert state_before is not None and old_before is not None
        assert new_before is not None
        epoch = state_before.epoch
        old_authz, old_token = old_before.authz_version, old_before.token_version
        new_authz, new_token = new_before.authz_version, new_before.token_version

    await _run_handover(old.id, new.id)

    async with SessionFactory() as session:
        super_role_id = await session.scalar(
            select(Role.id).where(Role.key == SystemRoleKey.SUPER_ADMIN.value)
        )
        assert super_role_id is not None
        assignments = (
            await session.scalars(
                select(UserRole).where(UserRole.role_id == super_role_id)
            )
        ).all()
        current_old = await session.get(User, old.id)
        current_new = await session.get(User, new.id)
        state = await session.get(RbacState, "global")
        audit = await session.scalar(
            select(RbacAuditEvent).where(
                RbacAuditEvent.action == "super_admin.transfer"
            )
        )
    assert {a.user_id for a in assignments if a.deleted_at is None} == {new.id}
    assert {a.user_id for a in assignments if a.deleted_at is not None} == {old.id}
    assert current_old is not None and current_new is not None and state is not None
    assert current_old.authz_version == old_authz + 1
    assert current_new.authz_version == new_authz + 1
    assert current_old.token_version == old_token + 1
    assert current_new.token_version == new_token + 1
    assert state.epoch == epoch + 1
    assert audit is not None and audit.decision == "allowed"
    assert audit.source == "operator"
    assert audit.actor_user_id == old.id and audit.target_user_id == new.id


async def test_operator_handover_rejects_wrong_old_holder_without_changes() -> None:
    holder = await _provision_user("actual_admin")
    impostor = await _provision_user("claimed_admin")
    target = await _provision_user("target_admin")
    await _run_bootstrap(holder.id)
    async with SessionFactory() as session:
        state = await session.get(RbacState, "global")
        assert state is not None
        epoch = state.epoch

    with pytest.raises(asyncpg.PostgresError, match="not the sole super_admin"):
        await _run_handover(impostor.id, target.id)

    async with SessionFactory() as session:
        current_state = await session.get(RbacState, "global")
        super_role_id = await session.scalar(
            select(Role.id).where(Role.key == SystemRoleKey.SUPER_ADMIN.value)
        )
        audit_count = await session.scalar(
            select(func.count())
            .select_from(RbacAuditEvent)
            .where(RbacAuditEvent.action == "super_admin.transfer")
        )
        assert current_state is not None and super_role_id is not None
        holders = (
            await session.scalars(
                select(UserRole.user_id).where(
                    UserRole.role_id == super_role_id,
                    UserRole.deleted_at.is_(None),
                )
            )
        ).all()
    assert holders == [holder.id]
    assert current_state.epoch == epoch
    assert audit_count == 0


async def test_provisioning_creates_user_and_default_role_atomically() -> None:
    user_id = uuid.uuid4()
    async with SessionFactory() as session:
        async with session.begin():
            state_before = await session.get(RbacState, "global")
            assert state_before is not None
            epoch_before = state_before.epoch
            created = await create_user_with_default_role(
                session,
                user_name="  Provisioned_User  ",
                user_id=user_id,
                request_id="provision-default-user",
            )
            assert created.authz_version == 1
            assert created.user_name == "Provisioned_User"

    async with SessionFactory() as session:
        user_role = await session.scalar(
            select(Role).where(Role.key == SystemRoleKey.USER.value)
        )
        assert user_role is not None
        assignment = await session.scalar(
            select(UserRole).where(
                UserRole.user_id == user_id,
                UserRole.role_id == user_role.id,
                UserRole.deleted_at.is_(None),
            )
        )
        state_after = await session.get(RbacState, "global")
        audit = await session.scalar(
            select(RbacAuditEvent).where(
                RbacAuditEvent.request_id == "provision-default-user"
            )
        )

    assert assignment is not None
    assert state_after is not None and state_after.epoch == epoch_before + 1
    assert audit is not None and audit.reason_code == "default_user_role_assigned"
    assert audit.source == "service"
    assert audit.schema_version == 1


async def test_provisioning_strips_user_name_whitespace() -> None:
    created = await _provision_user(user_name="  USER_NAme_ONLY  ")

    assert created.user_name == "USER_NAme_ONLY"


@pytest.mark.parametrize(
    ("user_name", "message"),
    [
        ("  ", "user_name must be 3-32 ASCII"),
        ("u!", "user_name must be 3-32 ASCII"),
        ("admin", "reserved_user_name"),
    ],
)
async def test_provisioning_rejects_invalid_user_names(
    user_name: str,
    message: str,
) -> None:
    async with SessionFactory() as session:
        async with session.begin():
            with pytest.raises(ValueError, match=message):
                await create_user_with_default_role(
                    session,
                    user_name=user_name,
                )


@pytest.mark.parametrize(
    "user_name",
    ["existing_name", "  existing_name  "],
)
async def test_provisioning_rejects_an_existing_user_name(
    user_name: str,
) -> None:
    await _provision_user(user_name="existing_name")

    async with SessionFactory() as session:
        async with session.begin():
            with pytest.raises(RbacError) as exc_info:
                await create_user_with_default_role(
                    session,
                    user_name=user_name,
                )

    assert exc_info.value.reason_code == "user_identity_exists"


async def test_provisioning_rejects_an_existing_user_id() -> None:
    existing = await _provision_user(user_name="existing_id")

    async with SessionFactory() as session:
        async with session.begin():
            with pytest.raises(RbacError) as exc_info:
                await create_user_with_default_role(
                    session,
                    user_name="new_identity",
                    user_id=existing.id,
                )

    assert exc_info.value.reason_code == "user_identity_exists"
