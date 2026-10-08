#!/usr/bin/env python3
"""Turn off this Mac's personal loom_local proxy. Does not stop Fisher 8080."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIG_PATH = HERE / "config.yaml"
PID_PATH = HERE / ".mihomo.pid"
SSH_PID_PATH = HERE / ".ssh.pid"
LOOP_PID_PATH = HERE / ".loop.pid"
FRONT_PID_PATH = HERE / ".front.pid"
SHUTTLE_PID_PATH = HERE / ".sshuttle.pid"


def cfg_service() -> str:
    service = "Wi-Fi"
    if CONFIG_PATH.exists():
        for raw in CONFIG_PATH.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line.startswith("network_service:"):
                service = line.split(":", 1)[1].strip().strip('"').strip("'") or service
    return service


def kill_pidfile(path: Path) -> None:
    if not path.exists():
        return
    try:
        os.kill(int(path.read_text().strip()), signal.SIGTERM)
    except (OSError, ValueError):
        pass
    path.unlink(missing_ok=True)


def main() -> None:
    service = cfg_service()
    for args in (
        ["-setwebproxystate", service, "off"],
        ["-setsecurewebproxystate", service, "off"],
        ["-setsocksfirewallproxystate", service, "off"],
        ["-setautoproxystate", service, "off"],
    ):
        subprocess.check_call(["networksetup", *args], stdout=subprocess.DEVNULL)
    kill_pidfile(LOOP_PID_PATH)
    kill_pidfile(FRONT_PID_PATH)
    kill_pidfile(PID_PATH)
    kill_pidfile(SSH_PID_PATH)
    if SHUTTLE_PID_PATH.exists():
        try:
            subprocess.call(["sudo", "-n", "kill", SHUTTLE_PID_PATH.read_text().strip()], stdout=subprocess.DEVNULL)
        except Exception:
            pass
        SHUTTLE_PID_PATH.unlink(missing_ok=True)
    print(f"已关掉本机分流 loop 和系统代理（{service}）。Fisher 8080 未动。", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"失败: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
