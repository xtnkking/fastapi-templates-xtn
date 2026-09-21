import uuid

from redis.crc import key_slot

from app.core.config import get_settings
from app.core.security.tokens import _active_jti_field, _user_session_keys


def test_all_session_operations_can_use_one_cluster_slot_per_user() -> None:
    settings = get_settings()
    observed_slots = set()
    for number in range(32):
        user_id = uuid.UUID(int=number, version=4)
        keys = _user_session_keys(settings=settings, user_id=user_id)
        assert len(set(keys)) == 3
        slots = {key_slot(key.encode()) for key in keys}
        assert len(slots) == 1
        assert all(str(user_id) not in key for key in keys)
        observed_slots.update(slots)

    # Users are distributed; a constant hash tag would pin all sessions to one node.
    assert len(observed_slots) > 16


def test_session_namespace_isolates_service_environment_and_user() -> None:
    settings = get_settings()
    user_id = uuid.uuid4()
    keys = _user_session_keys(settings=settings, user_id=user_id)
    other_service = settings.model_copy(update={"service_name": "other-service"})
    other_environment = settings.model_copy(update={"app_environment": "other-env"})
    configured_scope = settings.model_copy(
        update={"jwt_issuer": "https://issuer.example", "jwt_audience": "example"}
    )

    assert not set(keys).intersection(
        _user_session_keys(settings=other_service, user_id=user_id)
    )
    assert not set(keys).intersection(
        _user_session_keys(settings=other_environment, user_id=user_id)
    )
    assert not set(keys).intersection(
        _user_session_keys(settings=settings, user_id=uuid.uuid4())
    )
    assert keys == _user_session_keys(settings=configured_scope, user_id=user_id)


def test_jti_fields_are_digests_not_bearer_or_raw_identifier_values() -> None:
    settings = get_settings()
    token_id = uuid.uuid4()
    field = _active_jti_field(settings=settings, token_id=token_id)

    assert len(field) == 64
    assert set(field) <= set("0123456789abcdef")
    assert field != _active_jti_field(settings=settings, token_id=uuid.uuid4())
    assert field != _active_jti_field(
        settings=settings.model_copy(update={"service_name": "another"}),
        token_id=token_id,
    )
