#!/usr/bin/env python3
"""Keep this Mac's split proxy up: campus DIRECT if it works, else VPS.

Does not touch Fisher 8080. Reconnects the SSH hop if it drops.
"""

from __future__ import annotations

import os
import signal
import time
from pathlib import Path

import start as loom

HERE = Path(__file__).resolve().parent
LOOP_PID = HERE / ".loop.pid"


def _write_pid() -> None:
    LOOP_PID.write_text(str(os.getpid()), encoding="utf-8")


def _on_stop(_signum, _frame) -> None:
    loom.log("loop 收到停止信号")
    raise SystemExit(0)


def main() -> None:
    _write_pid()
    signal.signal(signal.SIGTERM, _on_stop)
    signal.signal(signal.SIGINT, _on_stop)
    cfg = loom.load_config()
    loom.log("loop 已开：每条连接先试校园网，不通再走服务器（失败黏住，防抖）")
    while True:
        try:
            loom.ensure(cfg)
        except Exception as exc:
            loom.log(f"loop 重试: {type(exc).__name__}: {exc}")
        time.sleep(5)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        loom.log(f"loop 退出: {type(exc).__name__}: {exc}")
        raise
