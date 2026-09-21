from collections.abc import Awaitable, Callable

import pytest
from httpx import AsyncClient

from app.core.security.domain import PermissionKey
from app.db.postgres import SessionFactory
from app.models.access import Role, RolePermission, User, UserRole
from tests.integration.conftest import World
from tests.integration.query_capture import capture_selects

pytestmark = pytest.mark.postgresql
type AccessToken = Callable[[User], Awaitable[str]]


async def _headers(
    access_token: AccessToken,
    user: User,
) -> dict[str, str]:
    return {"Authorization": f"Bearer {await access_token(user)}"}


async def _request_select_count(
    client: AsyncClient,
    *,
    path: str,
    headers: dict[str, str],
) -> int:
    with capture_selects() as statements:
        response = await client.get(path, headers=headers)
    assert response.status_code == 200, response.text
    return len(statements)


async def test_user_reads_apply_strict_visibility_and_filtered_pagination(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    async with SessionFactory() as session:
        async with session.begin():
            protected_user = await session.get(User, world.users["newcomer"].id)
            assert protected_user is not None
            protected_user.is_protected = True

    manager_headers = await _headers(access_token, world.users["manager"])
    visible_names = {"junior", "lower", "blank", "disabled"}
    expected_ids = {str(world.users[name].id) for name in visible_names}
    listed_ids: set[str] = set()

    for page in range(1, 4):
        response = await client.get(
            f"/api/v1/users?page={page}&page_size=2",
            headers=manager_headers,
        )
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["total"] == len(expected_ids)
        listed_ids.update(item["id"] for item in data["items"])

    assert listed_ids == expected_ids

    missing = await client.get(
        "/api/v1/users/00000000-0000-4000-8000-000000000000",
        headers=manager_headers,
    )
    assert missing.status_code == 404
    missing_body = missing.json()
    for name in (
        "super_admin",
        "manager",
        "peer",
        "higher",
        "hidden_higher",
        "newcomer",
    ):
        hidden = await client.get(
            f"/api/v1/users/{world.users[name].id}",
            headers=manager_headers,
        )
        assert hidden.status_code == 404
        hidden_body = hidden.json()
        assert (
            hidden_body["code"],
            hidden_body["message"],
            hidden_body["data"],
        ) == (
            missing_body["code"],
            missing_body["message"],
            missing_body["data"],
        )

    visible = await client.get(
        f"/api/v1/users/{world.users['lower'].id}",
        headers=manager_headers,
    )
    assert visible.status_code == 200
    assert visible.json()["data"]["user_name"] == world.users["lower"].user_name

    exact_match = await client.get(
        f"/api/v1/users?user_name={world.users['lower'].user_name}",
        headers=manager_headers,
    )
    assert exact_match.status_code == 200
    exact_page = exact_match.json()["data"]
    assert exact_page["total"] == 1
    assert [item["id"] for item in exact_page["items"]] == [
        str(world.users["lower"].id)
    ]
    assert exact_page["items"][0]["user_name"] == world.users["lower"].user_name

    hidden_exact_match = await client.get(
        f"/api/v1/users?user_name={world.users['peer'].user_name}",
        headers=manager_headers,
    )
    assert hidden_exact_match.status_code == 200
    assert hidden_exact_match.json()["data"] == {
        "items": [],
        "page": 1,
        "page_size": 20,
        "total": 0,
    }

    super_admin_headers = await _headers(access_token, world.users["super_admin"])
    super_admin_list = await client.get(
        "/api/v1/users?page_size=200",
        headers=super_admin_headers,
    )
    assert super_admin_list.status_code == 200
    super_admin_page = super_admin_list.json()["data"]
    assert super_admin_page["total"] == len(world.users)
    assert {item["id"] for item in super_admin_page["items"]} == {
        str(user.id) for user in world.users.values()
    }
    super_admin_self = await client.get(
        f"/api/v1/users/{world.users['super_admin'].id}",
        headers=super_admin_headers,
    )
    assert super_admin_self.status_code == 200


async def test_role_reads_hide_peer_and_higher_authority(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    manager_headers = await _headers(access_token, world.users["manager"])
    listed = await client.get(
        "/api/v1/roles?page_size=200",
        headers=manager_headers,
    )
    assert listed.status_code == 200
    page = listed.json()["data"]
    assert page["total"] == 4
    assert {item["key"] for item in page["items"]} == {
        "user",
        "junior-admin",
        "viewer",
        "auditor",
    }

    missing = await client.get(
        "/api/v1/roles/00000000-0000-4000-8000-000000000000",
        headers=manager_headers,
    )
    assert missing.status_code == 404
    missing_body = missing.json()
    assert missing.headers["X-Request-ID"] == missing_body["request_id"]
    for name in ("super_admin", "admin", "higher"):
        hidden = await client.get(
            f"/api/v1/roles/{world.roles[name].id}",
            headers=manager_headers,
        )
        assert hidden.status_code == 404
        hidden_body = hidden.json()
        assert hidden.headers["X-Request-ID"] == hidden_body["request_id"]
        assert hidden_body["request_id"] != missing_body["request_id"]
        for field in ("code", "message", "data"):
            assert hidden_body[field] == missing_body[field]

    visible = await client.get(
        f"/api/v1/roles/{world.roles['viewer'].id}",
        headers=manager_headers,
    )
    assert visible.status_code == 200

    super_admin_headers = await _headers(access_token, world.users["super_admin"])
    all_roles = await client.get(
        "/api/v1/roles?page_size=200",
        headers=super_admin_headers,
    )
    assert all_roles.status_code == 200
    expected_ids = {str(role.id) for role in world.roles.values()}
    assert all_roles.json()["data"]["total"] == len(expected_ids)
    assert {item["id"] for item in all_roles.json()["data"]["items"]} == expected_ids


async def test_disabled_roles_remain_assigned_but_do_not_contribute_authority(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
) -> None:
    disabled_role = Role(
        key="disabled-high",
        name="Disabled high role",
        management_tier=900,
        is_active=False,
    )
    async with SessionFactory() as session:
        async with session.begin():
            session.add(disabled_role)
            await session.flush()
            session.add_all(
                (
                    RolePermission(
                        role_id=disabled_role.id,
                        permission_id=world.permissions[
                            PermissionKey.PROJECTS_UPDATE.value
                        ].id,
                        assigned_by_user_id=world.users["super_admin"].id,
                    ),
                    UserRole(
                        user_id=world.users["lower"].id,
                        role_id=disabled_role.id,
                        assigned_by_user_id=world.users["super_admin"].id,
                    ),
                )
            )

    manager_headers = await _headers(access_token, world.users["manager"])
    response = await client.get(
        f"/api/v1/users/{world.users['lower'].id}",
        headers=manager_headers,
    )

    assert response.status_code == 200
    data = response.json()["data"]
    assert set(data) == {
        "id",
        "user_name",
        "is_active",
        "assigned_role_ids",
        "effective_role_ids",
        "effective_management_tier",
        "effective_permissions",
        "authz_version",
    }
    assert set(data["assigned_role_ids"]) == {
        str(world.roles["user"].id),
        str(world.roles["viewer"].id),
    }
    assert set(data["effective_role_ids"]) == {
        str(world.roles["user"].id),
        str(world.roles["viewer"].id),
    }
    assert data["effective_management_tier"] == 20
    assert data["effective_permissions"] == [PermissionKey.PROJECTS_READ.value]

    manager_list_response = await client.get(
        "/api/v1/users?page_size=200",
        headers=manager_headers,
    )
    assert manager_list_response.status_code == 200
    manager_list_item = next(
        item
        for item in manager_list_response.json()["data"]["items"]
        if item["id"] == str(world.users["lower"].id)
    )
    assert str(disabled_role.id) not in manager_list_item["assigned_role_ids"]

    super_admin_headers = await _headers(access_token, world.users["super_admin"])
    super_admin_response = await client.get(
        f"/api/v1/users/{world.users['lower'].id}",
        headers=super_admin_headers,
    )
    assert super_admin_response.status_code == 200
    super_admin_data = super_admin_response.json()["data"]
    assert str(disabled_role.id) in super_admin_data["assigned_role_ids"]
    assert str(disabled_role.id) not in super_admin_data["effective_role_ids"]

    super_admin_list_response = await client.get(
        "/api/v1/users?page_size=200",
        headers=super_admin_headers,
    )
    assert super_admin_list_response.status_code == 200
    super_admin_list_item = next(
        item
        for item in super_admin_list_response.json()["data"]["items"]
        if item["id"] == str(world.users["lower"].id)
    )
    assert str(disabled_role.id) in super_admin_list_item["assigned_role_ids"]


@pytest.mark.parametrize("resource", ["roles", "users"])
async def test_list_select_count_does_not_grow_with_page_size(
    client: AsyncClient,
    world: World,
    access_token: AccessToken,
    resource: str,
) -> None:
    super_admin_headers = await _headers(access_token, world.users["super_admin"])

    one_item = await _request_select_count(
        client,
        path=f"/api/v1/{resource}?page_size=1",
        headers=super_admin_headers,
    )
    full_page = await _request_select_count(
        client,
        path=f"/api/v1/{resource}?page_size=200",
        headers=super_admin_headers,
    )

    assert full_page == one_item
    assert full_page <= 8
