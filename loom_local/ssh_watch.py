#!/usr/bin/env python3
"""Keep the personal SSH -L hop alive. Restarts immediately when ssh exits.

Owned by start.start_local_ssh_forward; stop.py SIGTERM ends this process.
Does not touch Fisher 8080.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import start as loom

HERE = Path(__file__).resolve().parent
STOP = False


def _on_stop(_signum, _frame) -> None:
    global STOP
    STOP = True
    loom.log("ssh_watch 收到停止信号")


def _ssh_cmd(cfg: dict[str, str]) -> list[str]:
    inner = int(cfg.get("inner_port") or cfg["remote_port"])
    remote_port = int(cfg["remote_port"])
    return [
        "ssh",
        "-N",
        *loom.ssh_opts(cfg),
        "-o",
        "ExitOnForwardFailure=yes",
        "-L",
        f"127.0.0.1:{inner}:127.0.0.1:{remote_port}",
        cfg["ssh_host"],
    ]


def main() -> None:
    signal.signal(signal.SIGTERM, _on_stop)
    signal.signal(signal.SIGINT, _on_stop)
    cfg = loom.load_config()
    inner = int(cfg.get("inner_port") or cfg["remote_port"])
    backoff = 0.5
    loom.log(f"ssh_watch 已开：守护 127.0.0.1:{inner}")
    while not STOP:
        if loom.tunnel_ok(inner):
            # Another forward already holds the port (rare). Wait and recheck.
            time.sleep(2)
            continue
        cmd = _ssh_cmd(cfg)
        log_path = HERE / "ssh_watch.log"
        with log_path.open("a", encoding="utf-8") as err:
            err.write(f"\n--- start {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
            err.flush()
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=err,
                start_new_session=True,
            )
        deadline = time.time() + 12
        up = False
        while time.time() < deadline and not STOP:
            if proc.poll() is not None:
                break
            if loom.tunnel_ok(inner):
                up = True
                backoff = 0.5
                break
            time.sleep(0.2)
        if STOP:
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except OSError:
                    proc.terminate()
            break
        if up:
            loom.log(f"ssh_watch 隧道就绪 pid={proc.pid}")
            while not STOP and proc.poll() is None:
                time.sleep(1)
            if STOP:
                if proc.poll() is None:
                    try:
                        os.killpg(proc.pid, signal.SIGTERM)
                    except OSError:
                        proc.terminate()
                break
            code = proc.poll()
            loom.log(f"ssh_watch 隧道退出 code={code}，{backoff:.1f}s 后重连")
        else:
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    proc.kill()
            loom.log(f"ssh_watch 本次没起来，{backoff:.1f}s 后重试")
        time.sleep(backoff)
        backoff = min(backoff * 1.7, 8.0)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        loom.log(f"ssh_watch 退出: {type(exc).__name__}: {exc}")
        sys.exit(1)
