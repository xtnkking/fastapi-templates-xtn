\set ON_ERROR_STOP on

BEGIN;

SELECT set_config(
    'fastapi_templates_xtn.bootstrap_super_admin_user_id',
    :'super_admin_user_id',
    true
);

DO $bootstrap$
DECLARE
    candidate_user_id uuid := nullif(
        btrim(
            current_setting(
                'fastapi_templates_xtn.bootstrap_super_admin_user_id',
                true
            )
        ),
        ''
    )::uuid;
    candidate users%ROWTYPE;
    super_admin_role roles%ROWTYPE;
    user_role roles%ROWTYPE;
    super_admin_role_id uuid;
    user_role_id uuid;
    holder_count integer;
    holder_user_id uuid;
    candidate_role_count integer;
    assigned_super_admin boolean;
    permission_keys text[];
    expected_permission_keys constant text[] := ARRAY[
        'permissions:read',
        'projects:read',
        'projects:update',
        'registration:configure',
        'roles:assign',
        'roles:create',
        'roles:delete',
        'roles:permissions:bind',
        'roles:permissions:unbind',
        'roles:read',
        'roles:revoke',
        'roles:status:update',
        'roles:update',
        'users:create',
        'users:password:reset',
        'users:read',
        'users:sessions:revoke',
        'users:status:update'
    ]::text[];
BEGIN
    IF candidate_user_id IS NULL THEN
        RAISE EXCEPTION 'super_admin_user_id must not be empty';
    END IF;
    IF substring(candidate_user_id::text FROM 15 FOR 1) <> '4'
       OR substring(candidate_user_id::text FROM 20 FOR 1) NOT IN ('8', '9', 'a', 'b') THEN
        RAISE EXCEPTION 'super_admin_user_id must be a UUIDv4 value';
    END IF;

    -- This is the first lock. It serializes every compliant authorization writer.
    PERFORM scope
    FROM rbac_state
    WHERE scope = 'global'
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'rbac_state global row is missing; run migrations';
    END IF;

    -- Discover IDs while the global guard freezes the authorization topology.
    SELECT id INTO super_admin_role_id
    FROM roles
    WHERE key = 'super_admin';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'super_admin system role is missing; run migrations';
    END IF;

    SELECT id INTO user_role_id
    FROM roles
    WHERE key = 'user';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'user system role is missing; run migrations';
    END IF;

    SELECT * INTO candidate
    FROM users
    WHERE id = candidate_user_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION
            'target user account does not exist; create it through the trusted registration or provisioning flow first';
    END IF;

    -- Follow the shared lock order: users, roles, then policy relationship rows.
    PERFORM u.id
    FROM users AS u
    WHERE u.id = candidate.id
       OR u.id IN (
           SELECT ur.user_id
           FROM user_roles AS ur
           WHERE ur.role_id = super_admin_role_id
             AND ur.deleted_at IS NULL
       )
    ORDER BY u.id
    FOR UPDATE;

    PERFORM r.id
    FROM roles AS r
    WHERE r.id IN (super_admin_role_id, user_role_id)
    ORDER BY r.id
    FOR UPDATE;

    PERFORM rp.role_id
    FROM role_permissions AS rp
    WHERE rp.role_id IN (super_admin_role_id, user_role_id)
      AND rp.deleted_at IS NULL
    ORDER BY rp.role_id, rp.permission_id
    FOR UPDATE OF rp;

    PERFORM ur.user_id
    FROM user_roles AS ur
    WHERE (ur.user_id = candidate.id OR ur.role_id = super_admin_role_id)
      AND ur.deleted_at IS NULL
    ORDER BY ur.user_id, ur.role_id
    FOR UPDATE OF ur;

    -- Reload every decision input after the canonical locks are held.
    SELECT * INTO STRICT candidate
    FROM users
    WHERE id = candidate.id;
    IF NOT candidate.is_active
       OR candidate.is_protected
       OR candidate.deleted_at IS NOT NULL THEN
        RAISE EXCEPTION 'target user must be active, not system-protected, and not deleted';
    END IF;

    SELECT * INTO STRICT super_admin_role
    FROM roles
    WHERE id = super_admin_role_id;
    IF super_admin_role.key <> 'super_admin'
       OR super_admin_role.name <> 'Super administrator'
       OR super_admin_role.description <> 'Sole protected administrator for the application'
       OR super_admin_role.management_tier <> 1000
       OR NOT super_admin_role.is_active
       OR NOT super_admin_role.is_protected
       OR NOT super_admin_role.is_system
       OR NOT super_admin_role.is_super_admin
       OR super_admin_role.deleted_at IS NOT NULL
       OR super_admin_role.deleted_by_user_id IS NOT NULL THEN
        RAISE EXCEPTION 'super_admin role does not match the migrated system-role contract';
    END IF;

    SELECT * INTO STRICT user_role
    FROM roles
    WHERE id = user_role_id;
    IF user_role.key <> 'user'
       OR user_role.name <> 'User'
       OR user_role.description <> 'Mandatory lowest-authority role for every user'
       OR user_role.management_tier <> 0
       OR NOT user_role.is_active
       OR user_role.is_protected
       OR NOT user_role.is_system
       OR user_role.is_super_admin
       OR user_role.deleted_at IS NOT NULL
       OR user_role.deleted_by_user_id IS NOT NULL THEN
        RAISE EXCEPTION 'user role does not match the migrated system-role contract';
    END IF;

    SELECT coalesce(array_agg(p.key ORDER BY p.key), ARRAY[]::text[])
    INTO permission_keys
    FROM role_permissions AS rp
    JOIN permissions AS p ON p.id = rp.permission_id
    WHERE rp.role_id = super_admin_role_id
      AND rp.deleted_at IS NULL
      AND p.deleted_at IS NULL;
    IF permission_keys <> expected_permission_keys THEN
        RAISE EXCEPTION 'super_admin permission grants do not match the versioned allowlist';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM role_permissions
        WHERE role_id = user_role_id
          AND deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION 'user role must not contain permission grants';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM user_roles
        WHERE user_id = candidate.id
          AND role_id = user_role_id
          AND deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION
            'target user lacks the mandatory user role; repair the trusted provisioning flow before bootstrap';
    END IF;

    SELECT count(*) INTO candidate_role_count
    FROM user_roles
    WHERE user_id = candidate.id
      AND deleted_at IS NULL;

    SELECT count(*) INTO holder_count
    FROM user_roles
    WHERE role_id = super_admin_role_id
      AND deleted_at IS NULL;

    SELECT user_id INTO holder_user_id
    FROM user_roles
    WHERE role_id = super_admin_role_id
      AND deleted_at IS NULL
    ORDER BY user_id
    LIMIT 1;

    IF holder_count > 1 THEN
        RAISE EXCEPTION 'multiple super_admin assignments exist; bootstrap refused';
    END IF;
    IF holder_count = 1 AND holder_user_id <> candidate.id THEN
        RAISE EXCEPTION 'a different super_admin already exists; bootstrap refused';
    END IF;

    assigned_super_admin := holder_count = 0;
    IF assigned_super_admin AND candidate_role_count >= 10 THEN
        RAISE EXCEPTION
            'target user already has 10 live role assignments; unbind a non-mandatory role before bootstrap';
    END IF;
    IF assigned_super_admin THEN
        INSERT INTO user_roles (user_id, role_id, assigned_by_user_id)
        VALUES (candidate.id, super_admin_role_id, NULL);

        UPDATE users
        SET authz_version = authz_version + 1
        WHERE id = candidate.id;

        UPDATE rbac_state
        SET epoch = epoch + 1
        WHERE scope = 'global';
    END IF;

    INSERT INTO rbac_audit_events (
        actor_user_id,
        target_user_id,
        target_role_id,
        action,
        decision,
        reason_code,
        source,
        schema_version,
        before_state,
        after_state,
        request_id
    ) VALUES (
        candidate.id,
        candidate.id,
        super_admin_role_id,
        'super_admin.bootstrap',
        'allowed',
        CASE
            WHEN assigned_super_admin THEN 'explicit_super_admin_bootstrap'
            ELSE 'super_admin_already_bootstrapped'
        END,
        'operator',
        1,
        NULL,
        jsonb_build_object(
            'super_admin_user_id', candidate.id::text,
            'super_admin_role_id', super_admin_role_id::text,
            'base_user_role_id', user_role_id::text,
            'changed', assigned_super_admin
        ),
        'bootstrap:super_admin:' || candidate.id::text
    );
END;
$bootstrap$;

COMMIT;
