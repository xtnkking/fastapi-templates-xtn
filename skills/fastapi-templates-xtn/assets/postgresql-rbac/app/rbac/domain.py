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
    MEMBERSHIPS_READ = "memberships:read"
    MEMBERSHIPS_CREATE = "memberships:create"
    MEMBERSHIPS_STATUS_UPDATE = "memberships:status:update"
    TENANT_OWNERSHIP_TRANSFER = "tenant_ownership:transfer"
    PROJECTS_READ = "projects:read"
    PROJECTS_UPDATE = "projects:update"


PERMISSION_CATALOG: dict[PermissionKey, str] = {
    PermissionKey.ROLES_READ: "Read tenant roles and their permission grants",
    PermissionKey.ROLES_CREATE: "Create an unprotected tenant role",
    PermissionKey.ROLES_ASSIGN: "Assign an existing manageable role",
    PermissionKey.ROLES_REVOKE: "Revoke an existing manageable role",
    PermissionKey.ROLES_PERMISSIONS_UPDATE: (
        "Replace permission grants on a manageable tenant role"
    ),
    PermissionKey.ROLES_DELEGATION_UPDATE: (
        "Replace delegable grants on a manageable tenant role"
    ),
    PermissionKey.MEMBERSHIPS_READ: "Read visible tenant memberships",
    PermissionKey.MEMBERSHIPS_CREATE: "Create a membership for a known identity",
    PermissionKey.MEMBERSHIPS_STATUS_UPDATE: (
        "Suspend or reactivate a manageable tenant membership"
    ),
    PermissionKey.TENANT_OWNERSHIP_TRANSFER: "Transfer tenant ownership atomically",
    PermissionKey.PROJECTS_READ: "Read tenant projects",
    PermissionKey.PROJECTS_UPDATE: "Update tenant projects",
}

# These allowlists are intentionally explicit. Adding a platform or break-glass
# permission to the global catalog must not silently grant it to tenant owners.
TENANT_OWNER_PERMISSION_KEYS = frozenset(
    {
        PermissionKey.ROLES_READ.value,
        PermissionKey.ROLES_CREATE.value,
        PermissionKey.ROLES_ASSIGN.value,
        PermissionKey.ROLES_REVOKE.value,
        PermissionKey.ROLES_PERMISSIONS_UPDATE.value,
        PermissionKey.ROLES_DELEGATION_UPDATE.value,
        PermissionKey.MEMBERSHIPS_READ.value,
        PermissionKey.MEMBERSHIPS_CREATE.value,
        PermissionKey.MEMBERSHIPS_STATUS_UPDATE.value,
        PermissionKey.TENANT_OWNERSHIP_TRANSFER.value,
        PermissionKey.PROJECTS_READ.value,
        PermissionKey.PROJECTS_UPDATE.value,
    }
)
NON_DELEGABLE_CONTROL_PERMISSIONS = frozenset(
    {
        PermissionKey.ROLES_DELEGATION_UPDATE.value,
        PermissionKey.TENANT_OWNERSHIP_TRANSFER.value,
    }
)
TENANT_OWNER_DELEGABLE_PERMISSION_KEYS = (
    TENANT_OWNER_PERMISSION_KEYS - NON_DELEGABLE_CONTROL_PERMISSIONS
)


@dataclass(frozen=True, slots=True)
class Principal:
    user_id: uuid.UUID
    token_tenant_id: uuid.UUID
    token_version: int
    token_id: str


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
    membership_id: uuid.UUID
    user_id: uuid.UUID
    membership_status: str
    user_is_active: bool
    roles: tuple[RoleGrant, ...]
    permissions: frozenset[str]
    delegable_permissions: frozenset[str]
    management_tier: int
    identity_is_protected: bool
    is_protected: bool
    is_owner: bool
    authz_version: int

    @classmethod
    def build(
        cls,
        *,
        membership_id: uuid.UUID,
        user_id: uuid.UUID,
        membership_status: str,
        membership_is_protected: bool,
        user_is_protected: bool,
        authz_version: int,
        roles: tuple[RoleGrant, ...],
        user_is_active: bool = True,
    ) -> "AuthoritySnapshot":
        permissions = frozenset(
            permission for role in roles for permission in role.permissions
        )
        delegable = frozenset(
            permission for role in roles for permission in role.delegable_permissions
        )
        return cls(
            membership_id=membership_id,
            user_id=user_id,
            membership_status=membership_status,
            user_is_active=user_is_active,
            roles=tuple(sorted(roles, key=lambda role: str(role.role_id))),
            permissions=permissions,
            delegable_permissions=delegable,
            management_tier=max((role.management_tier for role in roles), default=0),
            identity_is_protected=(membership_is_protected or user_is_protected),
            is_protected=(
                membership_is_protected
                or user_is_protected
                or any(role.is_protected for role in roles)
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
            membership_id=self.membership_id,
            user_id=self.user_id,
            membership_status=self.membership_status,
            membership_is_protected=self.identity_is_protected,
            user_is_protected=False,
            authz_version=self.authz_version,
            roles=roles,
            user_is_active=self.user_is_active,
        )


@dataclass(frozen=True, slots=True)
class AuthorizationContext:
    principal: Principal
    tenant_id: uuid.UUID
    tenant_authz_epoch: int
    authority: AuthoritySnapshot
    request_id: str

    @property
    def permissions(self) -> frozenset[str]:
        return self.authority.permissions
