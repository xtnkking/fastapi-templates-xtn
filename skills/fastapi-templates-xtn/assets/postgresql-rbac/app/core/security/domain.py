import uuid
from dataclasses import dataclass
from enum import StrEnum

from app.core.audit import AuditSource


class PermissionKey(StrEnum):
    PERMISSIONS_READ = "permissions:read"
    ROLES_READ = "roles:read"
    ROLES_CREATE = "roles:create"
    ROLES_UPDATE = "roles:update"
    ROLES_STATUS_UPDATE = "roles:status:update"
    ROLES_DELETE = "roles:delete"
    ROLES_ASSIGN = "roles:assign"
    ROLES_REVOKE = "roles:revoke"
    ROLES_PERMISSIONS_BIND = "roles:permissions:bind"
    ROLES_PERMISSIONS_UNBIND = "roles:permissions:unbind"
    USERS_READ = "users:read"
    USERS_CREATE = "users:create"
    USERS_STATUS_UPDATE = "users:status:update"
    USERS_PASSWORD_RESET = "users:password:reset"
    USERS_SESSIONS_REVOKE = "users:sessions:revoke"
    REGISTRATION_CONFIGURE = "registration:configure"
    PROJECTS_READ = "projects:read"
    PROJECTS_UPDATE = "projects:update"


PERMISSION_CATALOG: dict[PermissionKey, str] = {
    PermissionKey.PERMISSIONS_READ: "Read the permission catalog",
    PermissionKey.ROLES_READ: "Read roles and their permission grants",
    PermissionKey.ROLES_CREATE: "Create an unprotected role",
    PermissionKey.ROLES_UPDATE: "Update a manageable role's public information",
    PermissionKey.ROLES_STATUS_UPDATE: "Enable or disable a manageable role",
    PermissionKey.ROLES_DELETE: "Soft-delete a manageable role",
    PermissionKey.ROLES_ASSIGN: "Assign an existing manageable role",
    PermissionKey.ROLES_REVOKE: "Revoke an existing manageable role",
    PermissionKey.ROLES_PERMISSIONS_BIND: ("Bind one permission to a manageable role"),
    PermissionKey.ROLES_PERMISSIONS_UNBIND: (
        "Unbind one permission from a manageable role"
    ),
    PermissionKey.USERS_READ: "Read users and their current authority",
    PermissionKey.USERS_CREATE: "Create a user with the mandatory base role",
    PermissionKey.USERS_STATUS_UPDATE: "Activate or suspend a manageable user",
    PermissionKey.USERS_PASSWORD_RESET: (
        "Reset the local password of a strictly lower user"
    ),
    PermissionKey.USERS_SESSIONS_REVOKE: "End every login of a strictly lower user",
    PermissionKey.REGISTRATION_CONFIGURE: "Change the public registration switch",
    PermissionKey.PROJECTS_READ: "Read projects",
    PermissionKey.PROJECTS_UPDATE: "Update projects",
}


class SystemRoleKey(StrEnum):
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    USER = "user"


@dataclass(frozen=True, slots=True)
class SystemRoleSpec:
    key: SystemRoleKey
    name: str
    description: str
    management_tier: int
    is_protected: bool
    is_super_admin: bool
    permissions: frozenset[str]


# Explicit allowlists prevent newly seeded or break-glass capabilities from
# silently becoming available to a built-in role.
SUPER_ADMIN_PERMISSION_KEYS = frozenset(
    {
        PermissionKey.PERMISSIONS_READ.value,
        PermissionKey.ROLES_READ.value,
        PermissionKey.ROLES_CREATE.value,
        PermissionKey.ROLES_UPDATE.value,
        PermissionKey.ROLES_STATUS_UPDATE.value,
        PermissionKey.ROLES_DELETE.value,
        PermissionKey.ROLES_ASSIGN.value,
        PermissionKey.ROLES_REVOKE.value,
        PermissionKey.ROLES_PERMISSIONS_BIND.value,
        PermissionKey.ROLES_PERMISSIONS_UNBIND.value,
        PermissionKey.USERS_READ.value,
        PermissionKey.USERS_CREATE.value,
        PermissionKey.USERS_STATUS_UPDATE.value,
        PermissionKey.USERS_PASSWORD_RESET.value,
        PermissionKey.USERS_SESSIONS_REVOKE.value,
        PermissionKey.REGISTRATION_CONFIGURE.value,
        PermissionKey.PROJECTS_READ.value,
        PermissionKey.PROJECTS_UPDATE.value,
    }
)
ADMIN_PERMISSION_KEYS = frozenset(
    {
        PermissionKey.PERMISSIONS_READ.value,
        PermissionKey.ROLES_READ.value,
        PermissionKey.ROLES_CREATE.value,
        PermissionKey.ROLES_UPDATE.value,
        PermissionKey.ROLES_STATUS_UPDATE.value,
        PermissionKey.ROLES_ASSIGN.value,
        PermissionKey.ROLES_REVOKE.value,
        PermissionKey.ROLES_PERMISSIONS_BIND.value,
        PermissionKey.ROLES_PERMISSIONS_UNBIND.value,
        PermissionKey.USERS_READ.value,
        PermissionKey.USERS_CREATE.value,
        PermissionKey.USERS_STATUS_UPDATE.value,
        PermissionKey.USERS_PASSWORD_RESET.value,
        PermissionKey.USERS_SESSIONS_REVOKE.value,
        PermissionKey.PROJECTS_READ.value,
        PermissionKey.PROJECTS_UPDATE.value,
    }
)
USER_PERMISSION_KEYS: frozenset[str] = frozenset()

SYSTEM_ROLE_SPECS: dict[SystemRoleKey, SystemRoleSpec] = {
    SystemRoleKey.SUPER_ADMIN: SystemRoleSpec(
        key=SystemRoleKey.SUPER_ADMIN,
        name="Super administrator",
        description="Sole protected administrator for the application",
        management_tier=1000,
        is_protected=True,
        is_super_admin=True,
        permissions=SUPER_ADMIN_PERMISSION_KEYS,
    ),
    SystemRoleKey.ADMIN: SystemRoleSpec(
        key=SystemRoleKey.ADMIN,
        name="Administrator",
        description="Built-in administrator for strictly lower authority",
        management_tier=500,
        is_protected=False,
        is_super_admin=False,
        permissions=ADMIN_PERMISSION_KEYS,
    ),
    SystemRoleKey.USER: SystemRoleSpec(
        key=SystemRoleKey.USER,
        name="User",
        description="Mandatory lowest-authority role for every user",
        management_tier=0,
        is_protected=False,
        is_super_admin=False,
        permissions=USER_PERMISSION_KEYS,
    ),
}
SYSTEM_ROLE_KEYS = frozenset(item.value for item in SystemRoleKey)
RESERVED_ROLE_KEYS = SYSTEM_ROLE_KEYS
MAX_ROLES_PER_USER = 10


@dataclass(frozen=True, slots=True)
class Principal:
    user_id: uuid.UUID
    token_version: int
    token_id: uuid.UUID
    issued_at: int
    expires_at: int


@dataclass(frozen=True, slots=True)
class RoleGrant:
    role_id: uuid.UUID
    key: str
    management_tier: int
    permissions: frozenset[str]
    is_system: bool
    is_protected: bool
    is_super_admin: bool


@dataclass(frozen=True, slots=True)
class AuthoritySnapshot:
    user_id: uuid.UUID
    user_is_active: bool
    user_is_protected: bool
    token_version: int
    roles: tuple[RoleGrant, ...]
    permissions: frozenset[str]
    management_tier: int
    is_protected: bool
    is_super_admin: bool
    authz_version: int

    @classmethod
    def build(
        cls,
        *,
        user_id: uuid.UUID,
        user_is_active: bool,
        user_is_protected: bool,
        token_version: int = 0,
        authz_version: int,
        roles: tuple[RoleGrant, ...],
    ) -> "AuthoritySnapshot":
        permissions = frozenset(
            permission for role in roles for permission in role.permissions
        )
        return cls(
            user_id=user_id,
            user_is_active=user_is_active,
            user_is_protected=user_is_protected,
            token_version=token_version,
            roles=tuple(sorted(roles, key=lambda role: str(role.role_id))),
            permissions=permissions,
            management_tier=max((role.management_tier for role in roles), default=0),
            is_protected=(
                user_is_protected or any(role.is_protected for role in roles)
            ),
            is_super_admin=any(role.is_super_admin for role in roles),
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
            token_version=self.token_version,
            authz_version=self.authz_version,
            roles=roles,
        )


@dataclass(frozen=True, slots=True)
class AuthorizationContext:
    principal: Principal
    authorization_epoch: int
    authority: AuthoritySnapshot
    request_id: str
    audit_source: AuditSource = AuditSource.SERVICE

    @property
    def permissions(self) -> frozenset[str]:
        return self.authority.permissions
