#!/usr/bin/env python3
"""Personal proxy for this Mac only.

Default: SSH-tunnel to the Los Angeles VPS (117.55.227.80) and point this Mac's system
proxy at 127.0.0.1. Optional: pull a loom-share Clash subscription instead.

Leaves the G11/Fisher 8080 exit alone. Binds the local hop to 127.0.0.1.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from direct_or_hop import WechatHysteresis, build_local_judge_pac, campus_needs_wechat_hop

HERE = Path(__file__).resolve().parent
CONFIG_PATH = HERE / "config.yaml"
EXAMPLE_PATH = HERE / "config.example.yaml"
RUNTIME_PATH = HERE / ".runtime.yaml"
PID_PATH = HERE / ".mihomo.pid"
SSH_PID_PATH = HERE / ".ssh.pid"
LOOP_PID_PATH = HERE / ".loop.pid"
FRONT_PID_PATH = HERE / ".front.pid"
SHUTTLE_PID_PATH = HERE / ".sshuttle.pid"
CIDR_PATH = HERE / "wechat_cidrs.txt"
PAC_PATH = HERE / "split.pac"
KEY_PATH = HERE / ".tunnel.key"
LOG_PATH = HERE / "loom_local.log"
ACCESS_LOG = HERE / "access.log"
REMOTE_FILES = ("remote_proxy.py", "crypto3.py", "tunnel_proto.py")

DEFAULTS = {
    "mode": "ssh",
    "ssh_host": "root@117.55.227.80",
    "identity_file": ".us_vps_ed25519",
    "remote_port": "17900",
    "inner_port": "17900",
    "subscribe_url": "",
    "mixed_port": "17890",
    "pac_port": "17891",
    "api_port": "19090",
    "network_service": "Wi-Fi",
    "tunnel_secret": "",
}


def identity_path(cfg: dict[str, str]) -> Path:
    raw = cfg.get("identity_file") or ".us_vps_ed25519"
    path = Path(raw)
    if not path.is_absolute():
        path = HERE / path
    return path


def ssh_opts(cfg: dict[str, str]) -> list[str]:
    # ConnectTimeout only covers the handshake. A stalled session otherwise
    # sits forever and wedges the reconnect loop.
    return [
        "-i",
        str(identity_path(cfg)),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=12",
        "-o",
        # Detect dead peers in ~12s so ssh_watch can re-open the hop quickly.
        "ServerAliveInterval=3",
        "-o",
        "ServerAliveCountMax=4",
        "-o",
        "TCPKeepAlive=yes",
    ]


def _kill_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except OSError:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def run_bounded(cmd: list[str], timeout: float) -> None:
    """Run a command; kill the whole process group if it exceeds timeout."""
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        _, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_group(proc.pid)
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
        raise
    if proc.returncode != 0:
        tail = (err or b"").decode("utf-8", "replace").strip()
        raise subprocess.CalledProcessError(proc.returncode, cmd, stderr=tail)


def log(msg: str) -> None:
    print(msg, flush=True)
    with LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(msg + "\n")


def load_config() -> dict[str, str]:
    if not CONFIG_PATH.exists():
        if EXAMPLE_PATH.exists():
            CONFIG_PATH.write_text(EXAMPLE_PATH.read_text(encoding="utf-8"), encoding="utf-8")
        else:
            CONFIG_PATH.write_text("mode: ssh\nssh_host: root@117.55.227.80\nidentity_file: .us_vps_ed25519\n", encoding="utf-8")
    cfg = dict(DEFAULTS)
    for raw in CONFIG_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        cfg[key.strip()] = value.strip().strip('"').strip("'")
    ensure_secret(cfg)
    return cfg


def ensure_secret(cfg: dict[str, str]) -> str:
    secret = cfg.get("tunnel_secret") or ""
    if len(secret) < 32:
        secret = os.urandom(32).hex()
        cfg["tunnel_secret"] = secret
        with CONFIG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(f"\ntunnel_secret: {secret}\n")
    KEY_PATH.write_text(secret + "\n", encoding="utf-8")
    os.chmod(KEY_PATH, 0o600)
    return secret


def kill_pidfile(path: Path) -> None:
    if not path.exists():
        return
    try:
        pid = int(path.read_text().strip())
        os.kill(pid, signal.SIGTERM)
    except (OSError, ValueError):
        pass
    path.unlink(missing_ok=True)


def run_networksetup(*args: str) -> None:
    subprocess.check_call(["networksetup", *args], stdout=subprocess.DEVNULL)


def write_split_pac(mixed_port: int) -> str:
    PAC_PATH.write_text(build_local_judge_pac("127.0.0.1", mixed_port), encoding="utf-8")
    return PAC_PATH.resolve().as_uri()


def split_proxy_already_on(pac_url: str, mixed_port: int) -> bool:
    """True when system HTTP/HTTPS already point at the local judge."""
    try:
        raw = subprocess.check_output(["scutil", "--proxy"], text=True)
    except subprocess.CalledProcessError:
        return False
    flags = {}
    for line in raw.splitlines():
        if " : " not in line:
            continue
        key, value = line.split(" : ", 1)
        flags[key.strip()] = value.strip()
    # Manual proxy: Chrome cannot skip it the way it sometimes skips PAC.
    return (
        flags.get("HTTPEnable") == "1"
        and flags.get("HTTPSEnable") == "1"
        and flags.get("HTTPProxy") == "127.0.0.1"
        and flags.get("HTTPSProxy") == "127.0.0.1"
        and flags.get("HTTPPort") == str(mixed_port)
        and flags.get("HTTPSPort") == str(mixed_port)
        and flags.get("ProxyAutoConfigEnable", "0") != "1"
        and flags.get("SOCKSEnable", "0") != "1"
    )


def pac_http_url(cfg: dict[str, str] | None = None) -> str:
    port = int((cfg or {}).get("pac_port") or DEFAULTS["pac_port"])
    return f"http://127.0.0.1:{port}/split.pac"


def clear_split_system_proxy(service: str) -> None:
    """Drop the system proxy while the local port is down, so the browser is not black-holed."""
    for args in (
        ["-setwebproxystate", service, "off"],
        ["-setsecurewebproxystate", service, "off"],
        ["-setsocksfirewallproxystate", service, "off"],
        ["-setautoproxystate", service, "off"],
    ):
        try:
            run_networksetup(*args)
        except subprocess.CalledProcessError:
            pass


# Desktop NetEase / school sites: go DIRECT on campus. Routing them through the
# local judge previously sent 易盾 (ac.dun.163.com) to LA and tripped risk control.
PROXY_BYPASS_DOMAINS = (
    "127.0.0.1",
    "localhost",
    "*.local",
    "163.com",
    "*.163.com",
    "126.net",
    "*.126.net",
    "126.com",
    "*.126.com",
    "127.net",
    "*.127.net",
    "netease.com",
    "*.netease.com",
    "yungu.org",
    "*.yungu.org",
    "yungu-inc.org",
    "*.yungu-inc.org",
)


def set_split_system_proxy(service: str, mixed_port: int, cfg: dict[str, str] | None = None) -> None:
    write_split_pac(mixed_port)
    pac_url = pac_http_url(cfg)
    try:
        run_networksetup("-setproxybypassdomains", service, *PROXY_BYPASS_DOMAINS)
    except subprocess.CalledProcessError as exc:
        log(f"设置代理绕过域名失败: {exc}")
    if split_proxy_already_on(pac_url, mixed_port):
        return
    # Force HTTP/HTTPS through the local judge. PAC alone lets some browser
    # paths skip the hop; campus then times out TLS to bilibili.
    run_networksetup("-setautoproxystate", service, "off")
    run_networksetup("-setsocksfirewallproxystate", service, "off")
    run_networksetup("-setwebproxy", service, "127.0.0.1", str(mixed_port))
    run_networksetup("-setsecurewebproxy", service, "127.0.0.1", str(mixed_port))
    run_networksetup("-setwebproxystate", service, "on")
    run_networksetup("-setsecurewebproxystate", service, "on")


def tunnel_ok(port: int) -> bool:
    try:
        with socket_connect("127.0.0.1", port, 0.4):
            return True
    except OSError:
        return False


def pidfile_alive(path: Path) -> bool:
    if not path.exists():
        return False
    try:
        pid = int(path.read_text().strip())
        os.kill(pid, 0)
        return True
    except (OSError, ValueError):
        path.unlink(missing_ok=True)
        return False


def remote_port_up(cfg: dict[str, str]) -> bool:
    remote_port = int(cfg["remote_port"])
    try:
        run_bounded(
            [
                "ssh",
                *ssh_opts(cfg),
                cfg["ssh_host"],
                f"ss -lnt | grep -E -q '[:.]{remote_port}\\b'",
            ],
            15,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return False


def start_remote_only(cfg: dict[str, str]) -> None:
    """Bring up remote_proxy without re-uploading every file."""
    remote_port = int(cfg["remote_port"])
    remote_cmd = (
        "cd ~/loom_personal && "
        "mkdir -p ~/loom_personal && "
        "if [ -f remote.pid ]; then kill \"$(cat remote.pid)\" 2>/dev/null || true; sleep 0.2; fi; "
        "fuser -k %s/tcp >/dev/null 2>&1 || true; sleep 0.2; "
        "PY=$(command -v python3.9 || command -v python3.8 || command -v python3) && "
        "nohup \"$PY\" remote_proxy.py --host 127.0.0.1 --port %s "
        "--key-file tunnel.key </dev/null >remote.log 2>&1 & echo $! > remote.pid; sleep 0.6; "
        "if ! ss -lnt | grep -E -q '[:.]%s\\b'; then "
        "echo REMOTE_START_FAILED; cat remote.log; exit 1; fi"
    ) % (remote_port, remote_port, remote_port)
    run_bounded(["ssh", *ssh_opts(cfg), cfg["ssh_host"], remote_cmd], 25)


def _kill_orphan_ssh_forward(inner: int) -> None:
    """Drop leftover ssh -L on our local hop port (not Fisher 8080)."""
    try:
        out = subprocess.check_output(["lsof", "-nP", f"-iTCP:{inner}", "-sTCP:LISTEN"], text=True)
    except subprocess.CalledProcessError:
        return
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 2 or parts[0].lower() != "ssh":
            continue
        try:
            os.kill(int(parts[1]), signal.SIGTERM)
        except (OSError, ValueError):
            pass


def start_local_ssh_forward(cfg: dict[str, str]) -> None:
    """Ensure ssh_watch is running and the local hop port is listening."""
    inner = int(cfg.get("inner_port") or cfg["remote_port"])
    if tunnel_ok(inner) and pidfile_alive(SSH_PID_PATH):
        return
    # If the watcher is already alive, let it re-open ssh instead of killing it.
    if pidfile_alive(SSH_PID_PATH):
        deadline = time.time() + 12
        while time.time() < deadline:
            if tunnel_ok(inner):
                return
            if not pidfile_alive(SSH_PID_PATH):
                break
            time.sleep(0.25)
    kill_pidfile(SSH_PID_PATH)
    _kill_orphan_ssh_forward(inner)
    time.sleep(0.15)
    err = (HERE / "ssh_watch.log").open("a", encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, "-u", str(HERE / "ssh_watch.py")],
        stdout=err,
        stderr=err,
        start_new_session=True,
        cwd=str(HERE),
    )
    SSH_PID_PATH.write_text(str(proc.pid), encoding="utf-8")
    deadline = time.time() + 18
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("ssh_watch 没起来，检查这台电脑能不能 ssh 到服务器")
        if tunnel_ok(inner):
            return
        time.sleep(0.25)
    raise RuntimeError("SSH 隧道守护已开，但本机端口还没就绪")


def reconnect_tunnel(cfg: dict[str, str]) -> None:
    """Fast path when the hop dropped overnight: no scp, just forward again."""
    log("隧道断了，正在重连（不重新上传脚本）…")
    # Prefer leaving a live remote alone. start_remote_only kills 17900 and
    # races with sshuttle / other SSH sessions on the same VPS.
    if not remote_port_up(cfg):
        try:
            start_remote_only(cfg)
        except Exception as exc:
            log(f"远端重启跳过/失败，先试本机转发: {type(exc).__name__}: {exc}")
    start_local_ssh_forward(cfg)
    mixed = int(cfg["mixed_port"])
    if not tunnel_ok(mixed) or not pidfile_alive(FRONT_PID_PATH):
        start_local_front(cfg)


_fast_fails = 0


def ensure(cfg: dict[str, str]) -> None:
    global _fast_fails
    mixed = int(cfg["mixed_port"])
    service = cfg["network_service"]
    mode = (cfg.get("mode") or "ssh").lower()
    if mode == "subscribe":
        if not pidfile_alive(PID_PATH):
            start_subscribe_mode(cfg)
    else:
        inner = int(cfg.get("inner_port") or cfg["remote_port"])
        if not tunnel_ok(inner):
            # Front may still be up — clear system proxy first or Chrome keeps
            # getting ERR_TUNNEL_CONNECTION_FAILED against a dead hop.
            clear_split_system_proxy(service)
            try:
                reconnect_tunnel(cfg)
                _fast_fails = 0
            except Exception as exc:
                _fast_fails += 1
                log(f"快速重连失败（{_fast_fails}/3）: {type(exc).__name__}: {exc}")
                if _fast_fails < 3:
                    clear_split_system_proxy(service)
                    raise
                log("连续三次快速重连失败，改走完整启动")
                _fast_fails = 0
                try:
                    start_ssh_mode(cfg)
                except Exception:
                    clear_split_system_proxy(service)
                    raise
        elif not tunnel_ok(mixed) or not pidfile_alive(FRONT_PID_PATH):
            start_local_front(cfg)
    if not tunnel_ok(mixed):
        clear_split_system_proxy(service)
        raise RuntimeError("本机端口没起来，已先关掉系统代理")
    set_split_system_proxy(service, mixed, cfg)
    # ensure() is also called from agents / one-shots — always keep the watchdog.
    spawn_loop()


def wechat_cidrs() -> list[str]:
    if not CIDR_PATH.exists():
        return []
    out: list[str] = []
    for raw in CIDR_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


_wechat_hop_tried = False
_wechat_gate = WechatHysteresis()


def shuttle_alive() -> bool:
    if pidfile_alive(SHUTTLE_PID_PATH):
        return True
    try:
        out = subprocess.check_output(
            ["pgrep", "-f", "/opt/homebrew/bin/sshuttle -r"],
            text=True,
        )
    except subprocess.CalledProcessError:
        return False
    pids = [p for p in out.split() if p.isdigit()]
    if not pids:
        return False
    SHUTTLE_PID_PATH.write_text(pids[0], encoding="utf-8")
    return True


def stop_wechat_hop() -> None:
    if not shuttle_alive():
        return
    pid = SHUTTLE_PID_PATH.read_text().strip() if SHUTTLE_PID_PATH.exists() else ""
    if pid:
        subprocess.call(["sudo", "-n", "kill", pid], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.call(
        ["sudo", "-n", "pkill", "-f", "/opt/homebrew/bin/sshuttle -r"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if not shuttle_alive():
        SHUTTLE_PID_PATH.unlink(missing_ok=True)
        log("微信校园网能直连，已停转发")


def start_wechat_hop(cfg: dict[str, str]) -> None:
    global _wechat_hop_tried
    if campus_needs_wechat_hop():
        _wechat_gate.on_fail()
    else:
        _wechat_gate.on_ok()
        if shuttle_alive() and not _wechat_gate.should_keep_hop():
            stop_wechat_hop()
        return
    if shuttle_alive():
        return
    if _wechat_hop_tried:
        return
    _wechat_hop_tried = True
    sshuttle = shutil.which("sshuttle") or "/opt/homebrew/bin/sshuttle"
    if not Path(sshuttle).exists():
        log("没有 sshuttle，微信长连接过不了校园网")
        return
    cidrs = wechat_cidrs()
    if not cidrs:
        return
    cmd = [
        "sudo",
        "-n",
        sshuttle,
        "-r",
        cfg["ssh_host"],
        "--pidfile",
        str(SHUTTLE_PID_PATH),
        "-D",
        "--exclude",
        "117.55.227.80",
        "--exclude",
        "10.0.0.0/8",
        "--exclude",
        "116.62.109.80/32",
        "--ssh-cmd",
        "ssh " + " ".join(ssh_opts(cfg)),
        *cidrs,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        script = HERE / "start_wechat_hop.sh"
        script.chmod(0o755)
        osa = (
            f'do shell script "{script} {cfg["ssh_host"]}" '
            "with administrator privileges"
        )
        proc = subprocess.run(["osascript", "-e", osa], capture_output=True, text=True)
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()
            log(f"微信 TCP hop 需要本机管理员密码: {err}")
            return
    time.sleep(0.4)
    if pidfile_alive(SHUTTLE_PID_PATH):
        log("微信 TCP 已走服务器（sshuttle）")


def spawn_loop() -> None:
    if pidfile_alive(LOOP_PID_PATH):
        return
    LOOP_PID_PATH.unlink(missing_ok=True)
    # Keep loop logs — silent DEVNULL hid overnight deaths.
    loop_log = (HERE / "loop.log").open("a", encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, "-u", str(HERE / "loop.py")],
        stdout=loop_log,
        stderr=loop_log,
        start_new_session=True,
        cwd=str(HERE),
    )
    LOOP_PID_PATH.write_text(str(proc.pid), encoding="utf-8")
    time.sleep(0.2)
    if proc.poll() is not None:
        raise RuntimeError("loop 没起来")
    log(f"loop 已开 pid={proc.pid}")


def start_local_front(cfg: dict[str, str]) -> None:
    mixed = int(cfg["mixed_port"])
    inner = int(cfg.get("inner_port") or cfg["remote_port"])
    kill_pidfile(FRONT_PID_PATH)
    access = ACCESS_LOG.open("a", encoding="utf-8")
    proc = subprocess.Popen(
        [
            sys.executable,
            "-u",
            str(HERE / "local_front.py"),
            "--listen",
            f"127.0.0.1:{mixed}",
            "--inner",
            f"127.0.0.1:{inner}",
            "--key-file",
            str(KEY_PATH),
            "--pac",
            f"127.0.0.1:{int(cfg.get('pac_port') or DEFAULTS['pac_port'])}",
        ],
        stdout=access,
        stderr=access,
        start_new_session=True,
        cwd=str(HERE),
    )
    FRONT_PID_PATH.write_text(str(proc.pid), encoding="utf-8")
    deadline = time.time() + 5
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("本机加密前端没起来")
        if tunnel_ok(mixed):
            return
        time.sleep(0.15)
    raise RuntimeError("本机加密前端端口还没就绪")


def start_ssh_mode(cfg: dict[str, str]) -> None:
    ssh_host = cfg["ssh_host"]
    inner = int(cfg.get("inner_port") or cfg["remote_port"])
    remote_port = int(cfg["remote_port"])
    clear_split_system_proxy(cfg["network_service"])
    kill_pidfile(FRONT_PID_PATH)
    kill_pidfile(SSH_PID_PATH)
    log(f"同步三层加密脚本到 {ssh_host} …")
    opts = ssh_opts(cfg)
    run_bounded(["ssh", *opts, ssh_host, "mkdir -p ~/loom_personal"], 20)
    scp_src = [str(HERE / name) for name in REMOTE_FILES]
    run_bounded(["scp", "-q", *opts, *scp_src, f"{ssh_host}:~/loom_personal/"], 20)
    run_bounded(["scp", "-q", *opts, str(KEY_PATH), f"{ssh_host}:~/loom_personal/tunnel.key"], 20)
    run_bounded(["ssh", *opts, ssh_host, "chmod 600 ~/loom_personal/tunnel.key"], 20)
    remote_cmd = (
        "cd ~/loom_personal && "
        "if [ -f remote.pid ]; then kill \"$(cat remote.pid)\" 2>/dev/null || true; sleep 0.2; fi; "
        "PY=$(command -v python3.9 || command -v python3.8 || command -v python3) && "
        f"nohup \"$PY\" remote_proxy.py --host 127.0.0.1 --port {remote_port} "
        "--key-file tunnel.key </dev/null >remote.log 2>&1 & echo $! > remote.pid; sleep 0.6; "
        f"if ! ss -lnt | grep -E -q '[:.]{remote_port}\\b'; then "
        "echo REMOTE_START_FAILED; cat remote.log; exit 1; fi"
    )
    run_bounded(["ssh", *opts, ssh_host, remote_cmd], 25)
    proc = subprocess.Popen(
        [
            "ssh",
            "-N",
            *opts,
            "-o",
            "ExitOnForwardFailure=yes",
            "-L",
            f"127.0.0.1:{inner}:127.0.0.1:{remote_port}",
            ssh_host,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    SSH_PID_PATH.write_text(str(proc.pid), encoding="utf-8")
    deadline = time.time() + 8
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("SSH 隧道没起来，检查这台电脑能不能 ssh 到服务器")
        if tunnel_ok(inner):
            start_local_front(cfg)
            return
        time.sleep(0.2)
    raise RuntimeError("SSH 隧道已开，但本机端口还没就绪")


def socket_connect(host: str, port: int, timeout: float):
    import socket

    class _C:
        def __enter__(self):
            self.s = socket.create_connection((host, port), timeout=timeout)
            return self.s

        def __exit__(self, *args):
            self.s.close()

    return _C()


def fetch_subscription(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "ClashMeta/1.0", "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    if "proxies:" not in body and "Proxy:" not in body:
        raise RuntimeError("订阅内容不是 Clash YAML，请检查 token / 地址")
    return body


def patch_local_only(text: str, mixed_port: int, api_port: int) -> str:
    rules = {
        r"^mixed-port:\s*.*$": f"mixed-port: {mixed_port}",
        r"^allow-lan:\s*.*$": "allow-lan: false",
        r"^bind-address:\s*.*$": "bind-address: 127.0.0.1",
        r"^external-controller:\s*.*$": f"external-controller: 127.0.0.1:{api_port}",
    }
    out = text
    for pat, repl in rules.items():
        if re.search(pat, out, re.M):
            out = re.sub(pat, repl, out, count=1, flags=re.M)
        elif pat.startswith(r"^mixed-port"):
            out = (
                f"mixed-port: {mixed_port}\nallow-lan: false\n"
                f"bind-address: 127.0.0.1\nexternal-controller: 127.0.0.1:{api_port}\n"
                + out
            )
    return out


def find_core() -> str | None:
    for name in ("mihomo", "clash"):
        path = shutil.which(name)
        if path:
            return path
    return None


def start_subscribe_mode(cfg: dict[str, str]) -> None:
    if not cfg.get("subscribe_url"):
        raise RuntimeError("mode=subscribe 但 subscribe_url 是空的")
    mixed = int(cfg["mixed_port"])
    api = int(cfg["api_port"])
    log("拉取 loom 订阅…")
    yaml_text = fetch_subscription(cfg["subscribe_url"])
    RUNTIME_PATH.write_text(patch_local_only(yaml_text, mixed, api), encoding="utf-8")
    core = find_core()
    if not core:
        raise RuntimeError("本机没有 mihomo/clash，订阅模式没法跑。先 brew install mihomo，或改回 mode: ssh")
    kill_pidfile(PID_PATH)
    proc = subprocess.Popen(
        [core, "-f", str(RUNTIME_PATH), "-d", str(HERE)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    PID_PATH.write_text(str(proc.pid), encoding="utf-8")
    time.sleep(0.8)
    if proc.poll() is not None:
        raise RuntimeError(f"{core} 启动失败，pid={proc.pid}")


def main() -> None:
    cfg = load_config()
    ensure(cfg)
    mixed = int(cfg["mixed_port"])
    log(f"本机分流已开: 每条连接先试校园网 1s，不通再 127.0.0.1:{mixed} → {cfg['ssh_host']}")
    log("ssh_watch 守护隧道；loop 每 2s 巡检；断线会先关系统代理再重连。Fisher 8080 没动。")
    log(f"关掉: {HERE / 'stop.sh'}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("已取消")
        sys.exit(1)
    except Exception as exc:
        log(f"失败: {type(exc).__name__}: {exc}")
        sys.exit(1)
