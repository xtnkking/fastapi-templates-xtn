#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 说明:
#    配置应用自己的安全 JSON 日志，同时写入控制台和 logs/日期/app.log。
#    不接管根日志器或第三方错误日志；写日志失败不影响业务调用。
# History:
# Date          Author    Version       Modification
# --------------------------------------------------------------------------------------------------
# 2026/09/29    XTN       V1.000        从日志模块拆出后台输出和处理器配置
# 2026/09/30    XTN       V1.001        使用标准输出处理器替代默认后台队列
# 2026/10/13    XTN       V1.002        补充安全日志输出和处理器替换的通俗步骤
# 2026/10/14    XTN       V1.003        补齐按北京时间日期分目录的文件日志和退出清理
# 2026/10/14    XTN       V1.004        文件达到配置大小前切分，按日期与序号追加保存
# 2026/10/14    XTN       V1.005        日志配置不再接收服务名称、版本和环境
# 2026/10/14    XTN       V1.006        文件目录与日志时间共用北京时间常量
# --------------------------------------------------------------------------------------------------

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import TextIO

from app.core.logging.events import LOG_TIMEZONE, SafeJsonFormatter

# 从当前源码位置找到项目根目录，不受启动命令所在目录影响；需要换位置时修改这里。
LOG_ROOT_DIR = Path(__file__).resolve().parents[3] / "logs"


class SafeStreamHandler(logging.StreamHandler[TextIO]):
    """
        只输出安全格式化后的单行 JSON；输出失败时不改变接口结果。
    """

    MAX_LINE_BYTES = 16_384  # 单条日志最多 16 KiB，避免意外的大日志占用输出通道。

    def __init__(self, stream: TextIO) -> None:
        """
            使用调用方提供的输出流，不负责关闭该流。

        :param stream: 通常是服务进程的标准输出。
        :return: 无返回值，完成日志处理器初始化。
        """
        # 复用调用方的输出流，通常就是进程标准输出，不在这里额外打开文件。
        super().__init__(stream)

    def emit(self, record: logging.LogRecord) -> None:
        """
            格式化并写出一条日志；超长或写入失败时直接忽略。

        :param record: 当前应用产生的日志记录。
        :return: 无返回值；日志故障不会向业务代码传播。
        """
        # 先安全格式化并限制实际 UTF-8 字节数，再写出并刷新；任一步失败都只忽略日志。
        try:
            line = self.format(record)
            if len(line.encode("utf-8")) > self.MAX_LINE_BYTES:
                return
            self.stream.write(line + self.terminator)
            self.flush()
        except Exception:
            return


class DailyFileHandler(logging.FileHandler):
    """
        把安全 JSON 日志按日期保存，文件放不下下一条时切换到下一个序号。
    """

    def __init__(self, log_root_dir: Path, max_file_bytes: int) -> None:
        """
            记住日志保存位置，第一次有日志时才创建日期目录和文件。

        :param log_root_dir: 日志根目录，默认是项目根目录下的 logs。
        :param max_file_bytes: 单个文件允许的最大字节数，由配置中的 MB 换算而来。
        :return: 无返回值；此时尚未打开日志文件。
        """
        # delay=True 表示现在只配置处理器，文件在 emit 中按日期打开。
        self.log_root_dir = log_root_dir.resolve()
        self.max_file_bytes = max_file_bytes  # 检查文件实际字节数，中文按 UTF-8 编码后计算。
        self.current_date = ""  # 已打开文件的日期；初始为空，第一次写入时确定。
        super().__init__(self.log_root_dir / "app.log", mode="a", encoding="utf-8", delay=True)

    def emit(self, record: logging.LogRecord) -> None:
        """
            检查日志和文件大小，选择当天能放下本条日志的文件，再追加并刷新。

        :param record: 应用产生的日志，创建时间决定它所属的北京时间日期。
        :return: 无返回值；目录、文件或格式化失败只影响日志，不改变接口结果。
        """
        try:
            # 1. 文件和控制台使用相同的安全格式与大小上限，不保存原始请求或密码。
            line = self.format(record)
            if len(line.encode("utf-8")) > SafeStreamHandler.MAX_LINE_BYTES:
                return
            line += self.terminator
            line_bytes = len(line.encode("utf-8"))  # 换行也占用空间，不能只数可见字符。
            if line_bytes > self.max_file_bytes:
                return

            # 2. 第一次写入或日期变化时选文件；当天继续写时先确认本条是否会超过上限。
            today = datetime.fromtimestamp(record.created, LOG_TIMEZONE).strftime("%Y-%m-%d")
            stream: TextIO | None = self.stream
            if today != self.current_date or stream is None:
                stream = self._open_file(today, line_bytes)
            else:
                stream.seek(0, 2)  # 移到文件末尾，读取磁盘上现有文件的字节位置。
                if stream.tell() + line_bytes > self.max_file_bytes:
                    stream = self._open_file(today, line_bytes)

            # 3. 每条日志占一行，并立即刷新；正常退出前不需要等待后台队列。
            stream.write(line)
            self.flush()
        except Exception:
            # 日志盘满或目录无权限时放弃本条文件输出，控制台仍由另一个处理器负责。
            return

    def _open_file(self, today: str, line_bytes: int) -> TextIO:
        """
            找到当天最新序号的文件；放不下本条时继续选下一个，不覆盖或删除旧日志。

        :param today: 本条日志所属的北京时间日期，例如 2026-10-14。
        :param line_bytes: 本条日志连同换行占用的 UTF-8 字节数。
        :return: 已按追加模式打开的文件，可继续写入本条日志。
        """
        # 1. 创建当天目录，并找出已有的最大文件序号，重启后仍从最新文件继续。
        log_directory = self.log_root_dir / today
        log_directory.mkdir(parents=True, exist_ok=True)
        file_index = 0  # 0 对应 app.log；1、2 等依次对应 app.1.log、app.2.log。
        for path in log_directory.glob("app.*.log"):
            number = path.stem.removeprefix("app.")
            if number.isascii() and number.isdecimal():
                file_index = max(file_index, int(number))

        # 2. 检查已有文件是否放得下本条；满了就增加序号，旧文件保留原样。
        log_file = log_directory / ("app.log" if file_index == 0 else f"app.{file_index}.log")
        while log_file.exists() and log_file.stat().st_size + line_bytes > self.max_file_bytes:
            file_index += 1
            log_file = log_directory / f"app.{file_index}.log"

        # 3. 关闭原文件，再追加打开选中的文件；固定 LF 换行，让 Windows 下的字节计算也准确。
        if self.stream is not None:
            previous_stream = self.stream
            self.stream = None
            previous_stream.close()
        self.baseFilename = str(log_file)
        self.stream = log_file.open("a", encoding="utf-8", newline="\n")
        self.current_date = today
        return self.stream

    def close(self) -> None:
        """
            退出或重新配置时关闭文件，关闭故障不阻止其他资源清理。

        :return: 无返回值；只关闭本处理器自己的文件，不关闭控制台。
        """
        # 标准 FileHandler 负责刷新和关闭；文件故障不能取代原来的启动或业务错误。
        try:
            super().close()
        except Exception:
            return


def configure_logging(*, log_level: str, include_exception_details: bool,
                      log_file_max_mb: int,
                      log_root_dir: Path = LOG_ROOT_DIR) -> tuple[SafeStreamHandler, DailyFileHandler]:
    """
        只配置 app 命名空间的安全 JSON 日志，不重置其他库的错误日志。
        关闭 Uvicorn 原始访问日志，避免记录含查询参数的 URL 或重复请求记录。

    :param log_level: 应用日志的最低输出级别。
    :param include_exception_details: True 时从日志原异常提取类型与代码位置；False 时不额外提取，两者都不输出异常原文。
    :param log_file_max_mb: 单个日志文件的大小上限，1 MB 按 1024 × 1024 字节计算。
    :param log_root_dir: 文件日志保存目录，默认是项目根目录下的 logs。
    :return: 控制台和文件处理器，供应用退出时逐个移除和关闭。
    """
    # 1. 控制台和文件共用安全 JSON 格式器，同一条日志的字段和脱敏结果一致。
    handlers = (SafeStreamHandler(sys.stdout), DailyFileHandler(log_root_dir, log_file_max_mb * 1024 * 1024))
    formatter = SafeJsonFormatter(
        include_exception_details=include_exception_details,
    )
    for handler in handlers:
        handler.setFormatter(formatter)

    # 2. 替换 app 自己的旧处理器并设置级别，关闭向上转发，避免同一条日志重复输出。
    application_logger = logging.getLogger("app")
    for previous in list(application_logger.handlers):
        application_logger.removeHandler(previous)
        if isinstance(previous, SafeStreamHandler | DailyFileHandler):
            previous.close()
    for handler in handlers:
        application_logger.addHandler(handler)
    application_logger.setLevel(log_level)
    application_logger.propagate = False
    application_logger.disabled = False

    # 3. 关闭可能携带原始 URL 的 Uvicorn 访问日志，请求记录由安全中间件负责。
    logging.getLogger("uvicorn.access").disabled = True
    return handlers
