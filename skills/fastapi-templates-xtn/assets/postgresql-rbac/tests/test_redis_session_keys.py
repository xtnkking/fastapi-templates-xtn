#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    验证 Redis 会话键直接使用用户 ID，不同用户使用各自的记录和顺序键。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/30    XTN       V1.000        保留会话键隔离检查，移除集群槽位测试
# 2026/10/13    XTN       V1.001        会话键只取用户 ID，JTI 字段只取登录标识摘要
# 2026/10/13    XTN       V1.002        精确核对登录记录和顺序二键契约
# 2026/10/13    XTN       V1.003        检查直观用户键名和短 UUID 登录字段
# 2026/10/20    XTN       V1.004        移除单测 UUID 包装，字段格式由实际签发和 Lua 存储验证
# --------------------------------------------------------------------------------------------------

from app.core.ids import new_entity_id
from app.repositories.redis.login_session_repository import _user_session_keys


def test_session_keys_use_user_id_and_isolate_users() -> None:
    """
        确认两把会话键直接包含业务用户 ID，不同用户的登录互不覆盖。

    :return: 无返回值；键名符合用户 ID 契约且不同用户的键不相交时通过。
    """
    user_id = new_entity_id("U")
    keys = _user_session_keys(user_id=user_id)
    assert keys == (f"login:sessions:{user_id}", f"login:sequence:{user_id}")
    assert len(set(keys)) == 2
    assert len(user_id) == 15
    assert all(key.endswith(user_id) for key in keys)
    assert not set(keys).intersection(_user_session_keys(user_id=new_entity_id("U")))
    assert keys == _user_session_keys(user_id=user_id)
