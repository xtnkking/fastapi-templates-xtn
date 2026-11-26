#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    统一定义验证码用途及登录要求，供请求模型、限流、接口和验证码服务共同引用。
#    用途名单自动从枚举生成；新增用途只维护本文件的定义和对应业务接口。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/10/09    XTN       V1.000        新建
# 2026/10/13    XTN       V1.001        说明验证码用途登录要求的属性计算步骤
# 2026/10/14    XTN       V1.002        Service 直接使用用途枚举，删除不再使用的完整用途名单
# 2026/10/24    XTN       V1.003        私有验证码场景补全操作对象，明确新增用户和两种改密业务
# --------------------------------------------------------------------------------------------------

from enum import Enum
from typing import Final


# 使用与参考项目一致的 str + Enum 写法；对外的字符串值显式取 .value。
class CaptchaScene(str, Enum):  # noqa: UP042
    """
        验证码使用用途；前端提交枚举值，业务代码通过成员名称引用。
        每张验证码固定绑定一个用途，登录验证码不能用于重置密码等其他操作。
    """

    LOGIN = "login"                                          # 登录前获取验证码。
    REGISTER = "register"                                    # 注册前获取验证码。
    ADMIN_CREATE_USER = "admin_create_user"                    # 管理员新增用户，验证码绑定当前登录用户。
    ADMIN_RESET_USER_PASSWORD = "admin_reset_user_password"    # 管理员重置他人密码，验证码绑定当前登录用户。
    USER_CHANGE_PASSWORD = "user_change_password"              # 当前用户修改本人密码，包含管理员本人改密。

    @property
    def requires_login(self) -> bool:
        """
            判断获取本用途验证码是否必须先登录，并在验证码中绑定当前用户。
            新增用途默认要求登录；确需未登录使用时，在下面明确列出该枚举成员。
            此属性只规定登录要求，操作权限仍由对应业务接口检查。

        :return: True 表示已登录用途；False 表示允许未登录获取。
        """
        # 只有登录和注册允许未登录领取；其余用途都要求绑定已认证的当前用户。
        return self not in (CaptchaScene.LOGIN, CaptchaScene.REGISTER)


# 以下名单自动生成，不要手工增删成员；统一修改上方枚举及 requires_login 属性。
# 未登录入口按“用途 + IP”限流，只接受允许未登录获取的用途。
PUBLIC_CAPTCHA_SCENES: Final = frozenset(scene.value for scene in CaptchaScene if not scene.requires_login)
# 已登录入口按“用途 + 操作者 ID”限流；普通用户本人改密也属于这组。
PRIVATE_CAPTCHA_SCENES: Final = frozenset(scene.value for scene in CaptchaScene if scene.requires_login)
