#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    实现密码边界校验及有并发上限的 Argon2id 哈希和验证。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/23    XTN       V1.000        补充文件职责、版本记录与清晰注释
# 2026/09/23    XTN       V1.001        统一注册、本人改密与管理员密码操作的策略错误提示
# 2026/09/23    XTN       V1.002        解释密码验证结果与耗时运算的并发保护
# 2026/09/23    XTN       V1.003        类方法参数逐行对齐，整理业务调用排版
# 2026/09/26    XTN       V1.004        密码与用户名比较改用单一可选参数
# 2026/09/29    XTN       V1.005        密码规则错误的响应转换移至统一错误模块
# 2026/09/29    XTN       V1.006        准确说明连续弱密码及用户名比较范围
# 2026/09/29    XTN       V1.007        新密码仅允许可见 ASCII 字符，拒绝空白和非 ASCII 输入
# 2026/10/02    XTN       V1.008        删除不会触发的字节上限和多余的 Unicode 比较归一化
# 2026/10/13    XTN       V1.009        补全密码函数异常契约及验证并发取消的业务阶段
# 2026/10/14    XTN       V1.010        密码最大长度统一为 32 字符，删除重复的登录长度上限
# 2026/10/16    XTN       V1.011        新密码沿用输入边界的最大长度检查，删除重复判断
# 2026/10/20    XTN       V1.012        登录输入上限独立于新密码策略，收紧策略不影响旧密码验证
# 2026/10/20    XTN       V1.013        限制本进程密码任务的排队人数和等待时间，繁忙时及时拒绝
# --------------------------------------------------------------------------------------------------


import asyncio
import math
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, TypeVar

from argon2 import PasswordHasher, extract_parameters
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import Type

# 单次 Argon2id 运算的内存预算，单位 KiB；65,536 KiB 约为 64 MiB，提高会增加每次登录的内存压力。
ARGON2_MEMORY_COST_KIB: Final = 65_536
ARGON2_TIME_COST: Final = 3  # 内存处理轮数；提高会增加破解成本，也会增加登录耗时。
ARGON2_PARALLELISM: Final = 4  # 单次计算的并行度，不是允许同时登录的用户数。
ARGON2_HASH_LENGTH: Final = 32  # 哈希输出长度，单位字节；编码到数据库后字符串会更长。
ARGON2_SALT_LENGTH: Final = 16  # 每次随机盐的长度，单位字节；盐由哈希器生成，不使用固定盐。
# 新密码长度按字符计；注册、创建用户、改密和重置的请求约束及提示自动引用。
# 修改这两个值不改变登录和旧密码验证；修改源码后重启服务，前端设置密码的限制也要同步。
MIN_PASSWORD_CHARACTERS: Final = 8
MAX_PASSWORD_CHARACTERS: Final = 32
# 所有密码输入的传输上限，单位字符，用于拦截异常大输入；不是新密码允许的长度。
# 不随新密码策略收紧而改变，避免已有用户的原密码被拒绝；放宽新密码长度时不能超过此值。
MAX_PASSWORD_INPUT_CHARACTERS: Final = 1_024
# 每个应用进程最多同时运行两个密码哈希/验证任务；多进程部署的总内存消耗需乘以进程数。
DEFAULT_MAX_CONCURRENT_OPERATIONS: Final = 2
DEFAULT_MAX_WAITING_OPERATIONS: Final = 4  # 每进程另外最多等候四项；0 表示没有空位就立即拒绝。
DEFAULT_WAIT_TIMEOUT_SECONDS: Final = 0.5  # 只限制等候名额的秒数，不中断已经开始的密码计算。

# 不存在的账号也执行一次相同参数的 Argon2id 验证，减少通过登录耗时猜测账号是否存在的差异。
# 这里只保留占位哈希，不保留原密码；即使比对偶然通过，used_dummy 也保证不能登录成功。
# 调整上面的哈希参数时同步检查占位哈希，避免新旧计算成本差异过大或被参数上限拒绝。
DUMMY_PASSWORD_HASH: Final = (
    "$argon2id$v=19$m=65536,t=3,p=4$LXt4vIgFZ6WkGw0A38ssxg$"
    "FHhivkBqhiWg1sDCem36CG0Ob137XKSwAlPuAVbeAp8"
)

_T = TypeVar("_T")


class PasswordPolicyError(ValueError):
    """
        携带固定密码规则原因码，由上层翻译为用户可理解的提示，禁止附带密码原文。
    """

    def __init__(self, reason_code: str) -> None:
        """
            保存密码规则失败原因，供上层映射为统一业务消息。

        :param reason_code: 不包含密码原文的固定失败原因代码。
        :return: 无返回值，初始化密码校验异常。
        """
        # 步骤：同时保存原因码和标准异常消息，让上层用固定原因选择文案而不接触密码原文。
        self.reason_code = reason_code
        super().__init__(reason_code)


class PasswordHashError(RuntimeError):
    """
        表示数据库中的密码哈希损坏、参数不安全或无法被验证器使用。
    """


class PasswordBusyError(RuntimeError):
    """
        密码计算的等候位置已满或等待超时，由统一异常处理器返回服务繁忙。
    """

    def __init__(self, reason_code: str) -> None:
        """
            记下拒绝原因，供日志区分排队已满和等待超时，不携带密码。

        :param reason_code: password_queue_full 表示队列已满；password_queue_timeout 表示等待超时。
        :return: 无返回值，初始化密码计算繁忙异常。
        """
        # 只保存固定原因码，客户端提示由统一异常处理器按语言选择。
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class PasswordVerification:
    """
        返回密码匹配结果、是否需要升级哈希参数，以及是否使用了不可登录的占位哈希。
    """

    verified: bool  # 输入密码是否匹配；账号状态和登录权限仍由业务层继续检查。
    needs_rehash: bool  # 旧哈希参数需要升级；不是要求用户更换密码，而是重新计算存储值。
    used_dummy: bool  # 是否用占位哈希模拟运算；账号不存在也耗时验证，减少通过耗时猜用户名。


def validate_login_password_input(password: str) -> str:
    """
        仅校验登录密码的传输边界，不用新密码强度规则拒绝既有合法密码。

    :param password: 用户提交的原始密码，不去除空格或改写字符。
    :return: 通过非空、字符数及 UTF-8 编码检查的原密码。
    :raises PasswordPolicyError: 类型、编码或长度不符合登录输入边界。
    """

    # 步骤 1：先检查字符串、非空和字符数，不按新密码规则拒绝已存在的登录密码。
    if not isinstance(password, str):
        raise PasswordPolicyError("password_invalid_type")
    if not password:
        raise PasswordPolicyError("password_empty")
    if len(password) > MAX_PASSWORD_INPUT_CHARACTERS:
        raise PasswordPolicyError("password_too_long")
    # 步骤 2：确认原文可以编码为 UTF-8，成功后原样交给哈希器，不去除空白或改写字符。
    # 传输字符数已有独立上限，无须再增加一个远大于可能输入的字节限制。
    # 仍显式拒绝无法编码的代理字符，避免把底层 UnicodeEncodeError 交给接口。
    try:
        password.encode("utf-8")
    except UnicodeEncodeError:
        raise PasswordPolicyError("password_invalid_unicode") from None
    return password


def validate_new_password(password: str, *, user_name: str | None = None) -> str:
    """
        校验新密码长度、可见 ASCII 字符范围及简单弱密码模式。

        连续序列只针对整段为纯 ASCII 字母或纯数字的升降序；
        大小写比较不会改写实际密码，也不默认要求大小写、数字或特殊符号组合。
        ASCII 33～126 包含英文、数字和常见英文标点，不包含空格及任何非 ASCII 字符。

    :param password: 将用于哈希的原始新密码。
    :param user_name: 当前账号用户名；默认 None 跳过用户名比较，提供时拒绝忽略大小写后完全相同的密码。
    :return: 通过新密码规则的原字符串，不裁剪或归一化。
    :raises PasswordPolicyError: 密码越界、含不允许的字符、过于简单或与用户名完全相同。
    :raises TypeError: 提供的 user_name 既不是字符串，也不是 None。
    """

    # 步骤 1：先检查输入边界，再按当前新密码策略检查长度和字符范围。
    # 登录和旧密码验证不走下面的策略，避免提高要求后把已有用户挡在外面。
    validate_login_password_input(password)
    if len(password) < MIN_PASSWORD_CHARACTERS:
        raise PasswordPolicyError("password_too_short")
    if len(password) > MAX_PASSWORD_CHARACTERS:
        raise PasswordPolicyError("password_too_long")
    if any(not 33 <= ord(character) <= 126 for character in password):
        raise PasswordPolicyError("password_invalid_character")

    # 步骤 2：检查整段重复字符及纯字母、纯数字的连续升降序，避免容易猜出的简单密码。
    # 新密码已经限定为 ASCII；只转小写比较弱模式，实际哈希仍使用用户输入的原文。
    lowercase_password = password.lower()
    if len(set(lowercase_password)) == 1:
        raise PasswordPolicyError("password_common_or_weak")
    # 只拦截整段纯字母或纯数字的相邻升降序；混合或局部序列不在这条规则内。
    if lowercase_password.isdigit() or lowercase_password.isalpha():
        # 与去掉首字符的序列逐位比较；两边长度相差一位，因此允许 zip 提前结束。
        steps = [
            ord(right) - ord(left)
            for left, right in zip(lowercase_password, lowercase_password[1:], strict=False)
        ]
        if len(set(steps)) == 1 and steps[0] in (-1, 1):
            raise PasswordPolicyError("password_common_or_weak")
    # 步骤 3：有用户名时检查其类型并作完整比较；不因密码包含用户名的一部分就拦截。
    # 比较忽略大小写，但通过检查的密码仍保留用户输入的原文。
    if user_name is not None and not isinstance(user_name, str):
        raise TypeError("user_name must be a string or None")
    if user_name is not None and lowercase_password == user_name.lower():
        raise PasswordPolicyError("password_same_as_user_name")
    return password


class PasswordManager:
    """
        统一执行密码规则、Argon2id 哈希与验证，并限制本进程的计算人数和等候人数。
    """

    def __init__(self, *, max_concurrent_operations: int = DEFAULT_MAX_CONCURRENT_OPERATIONS,
                 max_waiting_operations: int = DEFAULT_MAX_WAITING_OPERATIONS,
                 wait_timeout_seconds: float = DEFAULT_WAIT_TIMEOUT_SECONDS
                 ) -> None:
        """
            创建哈希器和本进程的计算名额，默认两项计算、四项等候，最多等待半秒。

        :param max_concurrent_operations: 本实例同时运行的哈希或验证任务上限，范围 1～32，默认 2。
        :param max_waiting_operations: 另外允许等候的任务数，默认 4；0 表示不排队。
        :param wait_timeout_seconds: 等待计算名额的最长秒数，默认 0.5；空闲时直接计算。
        :return: 无返回值，创建哈希器及保护 CPU、内存的异步信号量。
        :raises ValueError: 人数或等待秒数不合法。
        """
        # 1. 这些人数只在本实例、当前进程内统计，不使用 Redis，也不与其他 worker 共用。
        self._running_operations = 0  # 已取得计算名额，原生运算结束后才减回去。
        self._waiting_operations = 0  # 正在等候名额，开始计算、超时或取消时减回去。
        self.configure_limits(
            max_concurrent_operations=max_concurrent_operations,
            max_waiting_operations=max_waiting_operations,
            wait_timeout_seconds=wait_timeout_seconds,
        )
        # 步骤 2：用统一成本参数创建 Argon2id 哈希器，哈希器自行生成每次运算的随机盐。
        # Argon2id 是刻意耗时的密码哈希算法，泄露数据库后也不能直接读出原密码。
        self._hasher = PasswordHasher(
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST_KIB,
            parallelism=ARGON2_PARALLELISM,
            hash_len=ARGON2_HASH_LENGTH,
            salt_len=ARGON2_SALT_LENGTH,
            type=Type.ID,
        )

    def configure_limits(self, *, max_concurrent_operations: int,
                         max_waiting_operations: int,
                         wait_timeout_seconds: float
                         ) -> None:
        """
            在应用启动时设置计算和排队限制；有任务时禁止更换名额，避免旧任务突破新上限。

        :param max_concurrent_operations: 同时计算的任务数，必须是 1～32 的整数。
        :param max_waiting_operations: 另外允许等候的任务数，必须是非负整数，0 表示不排队。
        :param wait_timeout_seconds: 只等待空闲名额的最长秒数，必须是有限正数。
        :return: 无返回值，后续密码任务使用本次设置的限制。
        :raises ValueError: 人数或等待秒数不合法。
        :raises RuntimeError: 已有任务正在计算或排队，不能中途更换限制。
        """
        # 1. 先检查配置，避免把 True 当成一个名额，或把无限等待写成超时时间。
        if type(max_concurrent_operations) is not int or not 1 <= max_concurrent_operations <= 32:
            raise ValueError("max_concurrent_operations must be between 1 and 32")
        if type(max_waiting_operations) is not int or max_waiting_operations < 0:
            raise ValueError("max_waiting_operations must be a nonnegative integer")
        if (
            isinstance(wait_timeout_seconds, bool)
            or not isinstance(wait_timeout_seconds, (int, float))
            or not math.isfinite(wait_timeout_seconds)
            or wait_timeout_seconds <= 0
        ):
            raise ValueError("wait_timeout_seconds must be a finite positive number")
        # 2. 只在没有任务时重新建立名额；应用启动调用一次，修改 .env 后重启生效。
        if self._running_operations or self._waiting_operations:
            raise RuntimeError("cannot change password limits while operations are active")
        self._semaphore = asyncio.Semaphore(max_concurrent_operations)
        self._max_waiting_operations = max_waiting_operations
        self._wait_timeout_seconds = float(wait_timeout_seconds)

    async def _run_bounded(self, operation: Callable[[], _T]) -> _T:
        """
            有名额就计算，否则只让有限任务短暂等候；排队已满或等待超时就拒绝。
            已开始的原生运算不能直接终止，请求取消后仍等它结束再归还名额。
            同步运算自身抛出的异常原样交给调用方，不转换为密码不匹配。

        :param operation: 无参数的同步密码运算函数，取得并发名额后才在线程中调用一次。
        :return: 同步运算函数的执行结果。
        :raises PasswordBusyError: 等候位置已满或等待计算名额超时，没有启动本次密码运算。
        :raises asyncio.CancelledError: 等待名额时直接传播取消；运算开始后等其结束并回收任务异常再传播。
        """
        # 1. 没有计算名额时先检查等候人数，满了立即拒绝，不继续积压请求。
        # 本段检查和人数增加之间没有 await，同一事件循环中的其他请求不能插进来抢同一个位置。
        if self._semaphore.locked():
            if self._waiting_operations >= self._max_waiting_operations:
                raise PasswordBusyError("password_queue_full")
            self._waiting_operations += 1
            try:
                # 2. 只给等待名额设置超时；超时和取消都不会启动线程，信号量会清理这次等候。
                async with asyncio.timeout(self._wait_timeout_seconds):
                    await self._semaphore.acquire()
            except TimeoutError as exc:
                raise PasswordBusyError("password_queue_timeout") from exc
            finally:
                self._waiting_operations -= 1
        else:
            # 有空位就立即拿取，正常请求不需要固定等半秒。
            await self._semaphore.acquire()

        # 3. 已取得名额才在线程中计算，调用方此时不应持有数据库连接或行锁。
        self._running_operations += 1
        try:
            worker = asyncio.create_task(asyncio.to_thread(operation))
            try:
                return await asyncio.shield(worker)
            except asyncio.CancelledError:
                # 4. 请求取消时先等真实线程结束；不能因为请求断开就提前给下一项计算让位。
                # 请求取消不会停止底层线程，必须等实际运算结束再释放名额，否则会突破 CPU/内存上限。
                # 截止时间和进程关闭可能连续触发取消，等待期间仍需保护尚未退出的线程任务。
                while not worker.done():
                    try:
                        await asyncio.shield(worker)
                    except asyncio.CancelledError:
                        continue
                    except Exception:
                        break
                if not worker.cancelled():
                    worker.exception()
                raise
        finally:
            # 5. 正常结束或异常退出都归还名额，让下一项等候任务继续；异常不自动重试。
            self._running_operations -= 1
            self._semaphore.release()

    async def hash_new_password(self, password: str, *,
                                user_name: str | None = None
                                ) -> str:
        """
            校验新密码规则后，在受限线程任务中生成含随机盐的 Argon2id 哈希。

        :param password: 用户输入的原始新密码。
        :param user_name: 当前账号用户名；默认 None 跳过比较，提供时拒绝忽略大小写后完全相同的新密码。
        :return: 可保存到用户密码字段的 Argon2id 编码哈希。
        :raises PasswordPolicyError: 新密码未通过密码规则检查。
        :raises TypeError: 提供的 user_name 既不是字符串，也不是 None。
        :raises PasswordBusyError: 等候已满或等待超时，没有生成密码哈希。
        :raises asyncio.CancelledError: 请求被取消；已开始的哈希运算结束后才释放计算名额。
        """
        # 步骤 1：先完成新密码规则检查，非法输入不会占用昂贵的 Argon2id 计算名额。
        validated = validate_new_password(password, user_name=user_name)
        # 步骤 2：等待名额并在线程中哈希，随机盐由哈希器生成；此处不写入数据库。
        return await self._run_bounded(lambda: self._hasher.hash(validated))

    async def hash_verified_password(self, password: str) -> str:
        """
            为已经验证成功的既有密码升级哈希参数，不追加当前的新密码强度规则。

        :param password: 调用方已经验证正确的原始密码。
        :return: 使用当前 Argon2id 参数生成的编码哈希。
        :raises PasswordPolicyError: 密码不符合基本传输边界。
        :raises PasswordBusyError: 等候已满或等待超时，没有生成升级哈希。
        :raises asyncio.CancelledError: 请求被取消；已开始的哈希运算结束后才释放计算名额。
        """

        # 步骤 1：仅检查传输边界；密码确实正确必须由调用方事先验证，不追加当前新密码规则。
        validated = validate_login_password_input(password)
        # 步骤 2：受限线程重新计算当前成本的哈希；调用方负责将新哈希保存到数据库。
        return await self._run_bounded(lambda: self._hasher.hash(validated))

    async def verify_or_dummy(self, password: str,
                              password_hash: str | None
                              ) -> PasswordVerification:
        """
            验证密码并检查哈希是否需升级；不存在的账号也执行占位哈希验证。

            存储哈希的计算参数不得超过资源上限，占位验证始终不能认证成功。

        :param password: 用户提交的原始登录密码。
        :param password_hash: 数据库存储的编码哈希，账号不存在时传 None。
        :return: 不可变的验证结果快照；占位哈希始终返回未通过且不需升级，尚未检查账号状态。
        :raises PasswordPolicyError: 密码输入违反传输边界。
        :raises PasswordHashError: 存储哈希损坏或其参数不安全。
        :raises PasswordBusyError: 等候已满或等待超时，没有开始密码验证。
        :raises asyncio.CancelledError: 请求被取消；已开始的验证运算结束后才释放计算名额。
        """
        # 步骤 1：检查原密码输入并选定实际或占位哈希，账号缺失仍会进入同一种验证运算。
        validated = validate_login_password_input(password)
        used_dummy = password_hash is None
        encoded_hash = DUMMY_PASSWORD_HASH if password_hash is None else password_hash

        # 步骤 2：解析哈希编码并检查其计算成本，防止损坏的存储内容触发过度资源消耗。
        try:
            parameters = extract_parameters(encoded_hash)
        except InvalidHashError as exc:
            raise PasswordHashError("stored password hash is invalid") from exc
        # 验证前检查存储哈希自身携带的成本，避免异常数据库内容触发超大内存或超长计算。
        # 盐和输出摘要都额外限制为最多 64 字节；这是读取防护上限，不是新哈希的生成长度。
        if (
            parameters.type is not Type.ID
            or parameters.version != 19
            or parameters.memory_cost > ARGON2_MEMORY_COST_KIB
            or parameters.time_cost > ARGON2_TIME_COST
            or parameters.parallelism > ARGON2_PARALLELISM
            or parameters.salt_len > 64
            or parameters.hash_len > 64
        ):
            raise PasswordHashError("stored password hash parameters are unsafe")

        def verify() -> tuple[bool, bool]:
            """
                由下方受限线程任务调用，对闭包中已选定的哈希验证密码并检查是否需要升级。
                定义此回调时尚未执行验证；密码不匹配作为正常失败结果返回。

            :return: 密码是否匹配及当前哈希是否需要升级的二元组。
            :raises PasswordHashError: 哈希编码无效或验证器无法使用该哈希。
            """
            # 步骤：真正调用哈希器验证；不匹配返回两个 False，损坏哈希抛错，匹配后才检查成本升级。
            try:
                verified = self._hasher.verify(encoded_hash, validated)
            except VerifyMismatchError:
                return False, False
            except (InvalidHashError, VerificationError) as exc:
                raise PasswordHashError("stored password hash is invalid") from exc
            return bool(verified), self._hasher.check_needs_rehash(encoded_hash)

        # 步骤 3：取得计算名额后在线程中调用上面的回调，实际密码验证在这里开始。
        verified, needs_rehash = await self._run_bounded(verify)
        # 步骤 4：将结果封装为快照；即使占位密码碰巧匹配，也不能认证成功或触发真实账号哈希升级。
        return PasswordVerification(
            verified=verified and not used_dummy,
            needs_rehash=needs_rehash and not used_dummy,
            used_dummy=used_dummy,
        )


# 进程内复用哈希器和并发信号量，不能每次请求新建，否则并发限制会失去共享约束。
password_manager = PasswordManager()
