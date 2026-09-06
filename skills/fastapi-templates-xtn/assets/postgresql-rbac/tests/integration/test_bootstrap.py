import uuid

import pytest
from sqlalchemy import delete, select

from app.database import SessionFactory
from app.rbac.bootstrap import bootstrap_owner
from app.rbac.domain import (
    OWNER_DELEGABLE_PERMISSION_KEYS,
    OWNER_PERMISSION_KEYS,
    PERMISSION_CATALOG,
)
from app.rbac.models import Permission, Role, RolePermission, User, UserRole

pytestmark = pytest.mark.postgresql


async def test_explicit_bootstrap_creates_one_protected_owner() -> None:
    owner = await bootstrap_owner(owner_email="bootstrap-owner@example.test")

    async with SessionFactory() as session:
        owner_role = await session.scalar(select(Role).where(Role.is_owner.is_(True)))
        assert owner_role is not None
        assignment = await session.get(UserRole, (owner.id, owner_role.id))
        grants = (
            await session.execute(
                select(Permission.key, RolePermission.can_delegate)
                .select_from(RolePermission)
                .join(Permission, Permission.id == RolePermission.permission_id)
                .where(RolePermission.role_id == owner_role.id)
            )
        ).all()

    assert owner_role.is_system
    assert owner_role.is_protected
    assert owner_role.management_tier == 1000
    assert assignment is not None
    assert {row.key for row in grants} == OWNER_PERMISSION_KEYS
    assert {row.key for row in grants if row.can_delegate} == (
        OWNER_DELEGABLE_PERMISSION_KEYS
    )


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


async def test_bootstrap_does_not_grant_unknown_global_permission() -> None:
    extra_permission = Permission(
        id=uuid.uuid4(),
        key="platform:break_glass",
        description="Emergency-only permission",
    )
    async with SessionFactory() as session:
        session.add(extra_permission)
        await session.commit()

    try:
        owner = await bootstrap_owner(owner_email="isolated-owner@example.test")
        async with SessionFactory() as session:
            owner_role = await session.scalar(
                select(Role).where(Role.is_owner.is_(True))
            )
            assert owner_role is not None
            unexpected_grant = await session.scalar(
                select(RolePermission).where(
                    RolePermission.role_id == owner_role.id,
                    RolePermission.permission_id == extra_permission.id,
                )
            )
            assignment = await session.get(UserRole, (owner.id, owner_role.id))
        assert unexpected_grant is None
        assert assignment is not None
    finally:
        async with SessionFactory() as session:
            await session.execute(
                delete(Permission).where(Permission.id == extra_permission.id)
            )
            await session.commit()


async def test_bootstrap_rejects_disabled_existing_owner_and_rolls_back() -> None:
    async with SessionFactory() as session:
        session.add(User(email="disabled-owner@example.test", is_active=False))
        await session.commit()

    with pytest.raises(RuntimeError, match="inactive or system-protected"):
        await bootstrap_owner(owner_email="disabled-owner@example.test")

    async with SessionFactory() as session:
        owner_role = await session.scalar(select(Role).where(Role.is_owner.is_(True)))
    assert owner_role is None


async def test_bootstrap_refuses_a_second_owner() -> None:
    await bootstrap_owner(owner_email="first-owner@example.test")

    with pytest.raises(RuntimeError, match="already exists"):
        await bootstrap_owner(owner_email="second-owner@example.test")
