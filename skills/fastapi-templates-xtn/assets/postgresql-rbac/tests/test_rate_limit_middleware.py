#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    检查限流只读取服务端确认的来源 IP，并拒绝缺失或错误地址。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/08    XTN       V1.000        对齐直接接收 Request 的限流 IP 入口
# --------------------------------------------------------------------------------------------------

from starlette.requests import Request

from app.dependencies.rate_limit import get_limit_ip


def test_only_asgi_peer_is_used_for_anonymous_rate_limit() -> None:
    assert (
        get_limit_ip(
            Request({
                "type": "http",
                "client": ("2001:0db8::1", 5000),
                "headers": [(b"x-forwarded-for", b"198.51.100.7")],
            })
        )
        == "2001:db8::1"
    )
    assert get_limit_ip(Request({"type": "http", "headers": []})) == ""
    assert get_limit_ip(Request({"type": "http", "client": ("unknown", 5000)})) == ""
