\set ON_ERROR_STOP on

-- Operator-only action. Supply both immutable UUIDv4 user IDs from a trusted host.
-- psql --set=old_super_admin_user_id=... --set=new_super_admin_user_id=... \
--      --file sql/handover_super_admin.sql
BEGIN;

SELECT set_config(
    'fastapi_templates_xtn.transfer_old_user_id', :'old_super_admin_user_id', true
);
SELECT set_config(
    'fastapi_templates_xtn.transfer_new_user_id', :'new_super_admin_user_id', true
);

DO $transfer$
DECLARE
    old_user_id uuid := nullif(btrim(current_setting(
        'fastapi_templates_xtn.transfer_old_user_id', true)), '')::uuid;
    new_user_id uuid := nullif(btrim(current_setting(
        'fastapi_templates_xtn.transfer_new_user_id', true)), '')::uuid;
    super_role roles%ROWTYPE;
    old_holder users%ROWTYPE;
    new_holder users%ROWTYPE;
    live_holder_count integer;
    target_role_count integer;
BEGIN
    IF old_user_id IS NULL OR new_user_id IS NULL OR old_user_id = new_user_id THEN
        RAISE EXCEPTION 'two different, existing user IDs are required';
    END IF;
    IF substring(old_user_id::text FROM 15 FOR 1) <> '4'
       OR substring(new_user_id::text FROM 15 FOR 1) <> '4'
       OR substring(old_user_id::text FROM 20 FOR 1) NOT IN ('8', '9', 'a', 'b')
       OR substring(new_user_id::text FROM 20 FOR 1) NOT IN ('8', '9', 'a', 'b') THEN
        RAISE EXCEPTION 'both user IDs must be UUIDv4 values';
    END IF;

    -- The same first lock and lock order as application authorization writes.
    PERFORM scope FROM rbac_state WHERE scope = 'global' FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'rbac_state global row is missing; run migrations';
    END IF;
    PERFORM id FROM users
    WHERE id IN (old_user_id, new_user_id)
    ORDER BY id FOR UPDATE;
    SELECT * INTO old_holder FROM users WHERE id = old_user_id;
    SELECT * INTO new_holder FROM users WHERE id = new_user_id;
    IF old_holder.id IS NULL OR new_holder.id IS NULL THEN
        RAISE EXCEPTION 'both user accounts must already exist';
    END IF;
    IF NOT old_holder.is_active OR old_holder.deleted_at IS NOT NULL
       OR NOT new_holder.is_active OR new_holder.is_protected
       OR new_holder.deleted_at IS NOT NULL THEN
        RAISE EXCEPTION 'both accounts must be active and the target unprotected';
    END IF;

    SELECT * INTO super_role FROM roles WHERE key = 'super_admin' FOR UPDATE;
    IF super_role.id IS NULL OR NOT super_role.is_system
       OR NOT super_role.is_protected OR NOT super_role.is_super_admin
       OR NOT super_role.is_active OR super_role.deleted_at IS NOT NULL
       OR super_role.management_tier <> 1000 THEN
        RAISE EXCEPTION 'super_admin system role does not match the migrated contract';
    END IF;
    PERFORM id FROM roles WHERE key = 'user' FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'mandatory user system role is missing';
    END IF;

    PERFORM ur.id FROM user_roles AS ur
    WHERE ur.user_id IN (old_user_id, new_user_id)
       OR ur.role_id = super_role.id
    ORDER BY ur.user_id, ur.role_id FOR UPDATE OF ur;
    SELECT count(*) INTO live_holder_count FROM user_roles
    WHERE role_id = super_role.id AND deleted_at IS NULL;
    IF live_holder_count <> 1 OR NOT EXISTS (
        SELECT 1 FROM user_roles
        WHERE user_id = old_user_id AND role_id = super_role.id
          AND deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION 'the expected current user is not the sole super_admin';
    END IF;
    IF EXISTS (
        SELECT 1 FROM users AS u
        WHERE u.id IN (old_user_id, new_user_id)
          AND NOT EXISTS (
              SELECT 1 FROM user_roles AS ur
              JOIN roles AS r ON r.id = ur.role_id
              WHERE ur.user_id = u.id AND r.key = 'user'
                AND ur.deleted_at IS NULL AND r.deleted_at IS NULL AND r.is_active
          )
    ) THEN
        RAISE EXCEPTION 'both accounts must retain the mandatory user role';
    END IF;
    SELECT count(*) INTO target_role_count FROM user_roles
    WHERE user_id = new_user_id AND deleted_at IS NULL;
    IF target_role_count >= 10 THEN
        RAISE EXCEPTION 'target already has 10 live roles';
    END IF;

    UPDATE user_roles SET deleted_at = now(), deleted_by_user_id = old_user_id
    WHERE user_id = old_user_id AND role_id = super_role.id AND deleted_at IS NULL;
    INSERT INTO user_roles (user_id, role_id, assigned_by_user_id)
    VALUES (new_user_id, super_role.id, old_user_id);
    -- Reject pre-transfer bearer tokens for both accounts, including those
    -- already present in the Redis active-JTI registry.
    UPDATE users SET authz_version = authz_version + 1,
                     token_version = token_version + 1
    WHERE id IN (old_user_id, new_user_id);
    UPDATE rbac_state SET epoch = epoch + 1 WHERE scope = 'global';
    INSERT INTO rbac_audit_events (
        actor_user_id, target_user_id, target_role_id, action, decision,
        reason_code, source, schema_version, before_state, after_state, request_id
    ) VALUES (
        old_user_id, new_user_id, super_role.id, 'super_admin.transfer', 'allowed',
        'operator_transfer', 'operator', 1,
        jsonb_build_object('super_admin_user_id', old_user_id::text),
        jsonb_build_object('super_admin_user_id', new_user_id::text),
        'operator:super_admin_transfer:' || new_user_id::text
    );
END;
$transfer$;

COMMIT;
