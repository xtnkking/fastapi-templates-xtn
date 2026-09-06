import uuid
from dataclasses import dataclass
from enum import StrEnum


class PermissionKey(StrEnum):
    ROLES_READ = "roles:read"
    ROLES_CREATE = "roles:create"
    ROLES_ASSIGN = "roles:assign"
    ROLES_REVOKE = "roles:revoke"
    ROLES_PERMISSIONS_UPDATE = "roles:permissions:update"
    ROLES_DELEGATION_UPDATE = "roles:delegation:update"
    USERS_READ = "users:read"
    USERS_STATUS_UPDATE = "users:status:update"
    SYSTEM_OWNER_TRANSFER = "system_owner:transfer"
    PROJECTS_READ = "projects:read"
    PROJECTS_UPDATE = "projects:update"


PERMISSION_CATALOG: dict[PermissionKey, str] = {
    PermissionKey.ROLES_READ: "Read roles and their permission grants",
    PermissionKey.ROLES_CREATE: "Create an unprotected role",
    PermissionKey.ROLES_ASSIGN: "Assign an existing manageable role",
    PermissionKey.ROLES_REVOKE: "Revoke an existing manageable role",
    PermissionKey.ROLES_PERMISSIONS_UPDATE: (
        "Replace permission grants on a manageable role"
    ),
    PermissionKey.ROLES_DELEGATION_UPDATE: (
        "Replace delegable grants on a manageable role"
    ),
    PermissionKey.USERS_READ: "Read users and their current authority",
    PermissionKey.USERS_STATUS_UPDATE: "Activate or suspend a manageable user",
    PermissionKey.SYSTEM_OWNER_TRANSFER: "Transfer the sole system Owner atomically",
    PermissionKey.PROJECTS_READ: "Read projects",
    PermissionKey.PROJECTS_UPDATE: "Update projects",
}

# This explicit allowlist prevents a newly seeded break-glass capability from
# silently becoming assignable through ordinary role administration.
OWNER_PERMISSION_KEYS = frozenset(
    {
        PermissionKey.ROLES_READ.value,
        PermissionKey.ROLES_CREATE.value,
        PermissionKey.ROLES_ASSIGN.value,
        PermissionKey.ROLES_REVOKE.value,
        PermissionKey.ROLES_PERMISSIONS_UPDATE.value,
        PermissionKey.ROLES_DELEGATION_UPDATE.value,
        PermissionKey.USERS_READ.value,
        PermissionKey.USERS_STATUS_UPDATE.value,
        PermissionKey.SYSTEM_OWNER_TRANSFER.value,
        PermissionKey.PROJECTS_READ.value,
        PermissionKey.PROJECTS_UPDATE.value,
    }
)
NON_DELEGABLE_CONTROL_PERMISSIONS = frozenset(
    {
        PermissionKey.ROLES_DELEGATION_UPDATE.value,
        PermissionKey.SYSTEM_OWNER_TRANSFER.value,
    }
)
OWNER_DELEGABLE_PERMISSION_KEYS = (
    OWNER_PERMISSION_KEYS - NON_DELEGABLE_CONTROL_PERMISSIONS
)


@dataclass(frozen=True, slots=True)
class Principal:
    user_id: uuid.UUID
    token_version: int
    token_id: uuid.UUID


@dataclass(frozen=True, slots=True)
class RoleGrant:
    role_id: uuid.UUID
    management_tier: int
    permissions: frozenset[str]
    delegable_permissions: frozenset[str]
    is_protected: bool
    is_owner: bool


@dataclass(frozen=True, slots=True)
class AuthoritySnapshot:
    user_id: uuid.UUID
    user_is_active: bool
    user_is_protected: bool
    roles: tuple[RoleGrant, ...]
    permissions: frozenset[str]
    delegable_permissions: frozenset[str]
    management_tier: int
    is_protected: bool
    is_owner: bool
    authz_version: int

    @classmethod
    def build(
        cls,
        *,
        user_id: uuid.UUID,
        user_is_active: bool,
        user_is_protected: bool,
        authz_version: int,
        roles: tuple[RoleGrant, ...],
    ) -> "AuthoritySnapshot":
        permissions = frozenset(
            permission for role in roles for permission in role.permissions
        )
        delegable = frozenset(
            permission for role in roles for permission in role.delegable_permissions
        )
        return cls(
            user_id=user_id,
            user_is_active=user_is_active,
            user_is_protected=user_is_protected,
            roles=tuple(sorted(roles, key=lambda role: str(role.role_id))),
            permissions=permissions,
            delegable_permissions=delegable,
            management_tier=max((role.management_tier for role in roles), default=0),
            is_protected=(
                user_is_protected or any(role.is_protected for role in roles)
            ),
            is_owner=any(role.is_owner for role in roles),
            authz_version=authz_version,
        )

    def with_role(self, role: RoleGrant) -> "AuthoritySnapshot":
        roles = {item.role_id: item for item in self.roles}
        roles[role.role_id] = role
        return self._replace_roles(tuple(roles.values()))

    def without_role(self, role_id: uuid.UUID) -> "AuthoritySnapshot":
        return self._replace_roles(
            tuple(role for role in self.roles if role.role_id != role_id)
        )

    def _replace_roles(self, roles: tuple[RoleGrant, ...]) -> "AuthoritySnapshot":
        return self.build(
            user_id=self.user_id,
            user_is_active=self.user_is_active,
            user_is_protected=self.user_is_protected,
            authz_version=self.authz_version,
            roles=roles,
        )


@dataclass(frozen=True, slots=True)
class AuthorizationContext:
    principal: Principal
    authorization_epoch: int
    authority: AuthoritySnapshot
    request_id: str

    @property
    def permissions(self) -> frozenset[str]:
        return self.authority.permissions
