#!/usr/bin/env python3
"""Keep this Mac's split proxy up: campus DIRECT if it works, else VPS.

Does not touch Fisher 8080. Reconnects the SSH hop if it drops.
Polls every 2s so a dead hop clears system proxy before Chrome sits on ERR_TUNNEL.
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
    loom.log("loop 已开：每 2s 检查隧道；断线先关系统代理再重连")
    fails = 0
    while True:
        try:
            inner = int(cfg.get("inner_port") or cfg["remote_port"])
            if not loom.tunnel_ok(inner):
                # Don't wait for full ensure path — drop proxy immediately.
                loom.clear_split_system_proxy(cfg["network_service"])
            loom.ensure(cfg)
            fails = 0
            time.sleep(2)
        except Exception as exc:
            fails += 1
            loom.log(f"loop 重试 ({fails}): {type(exc).__name__}: {exc}")
            time.sleep(min(1.0 + fails * 0.5, 5.0))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        loom.log(f"loop 退出: {type(exc).__name__}: {exc}")
        raise
