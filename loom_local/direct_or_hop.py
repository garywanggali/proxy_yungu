"""Campus first: try campus, hop if it fails. Sticky so a flapping campus does not thrash."""

from __future__ import annotations

import socket
import threading
import time

# (host, port) → PAC suffixes forced through the hop after a failed campus probe.
PROBE_GROUPS = (
    (
        ("www.baidu.com", 443),
        ("baidu.com", "baidu.jp", "bdstatic.com", "bdimg.com", "baidustatic.com", "bcebos.com"),
    ),
    (
        ("www.bilibili.com", 443),
        (
            "bilibili.com",
            "bilibili.cn",
            "biliapi.com",
            "biliapi.net",
            "bilivideo.com",
            "bilivideo.cn",
            "hdslb.com",
            "hdslb.net",
            "szbdyd.com",
        ),
    ),
    (
        ("api.bilibili.com", 443),
        ("bilibili.com", "biliapi.com", "biliapi.net"),
    ),
    (
        ("weixin.qq.com", 443),
        ("weixin.qq.com", "weixin.com", "wechat.com"),
    ),
)

WECHAT_PROBES = (
    ("weixin.qq.com", 443),
    ("szextshort.weixin.qq.com", 80),
    ("short.weixin.qq.com", 80),
)

SCHOOL_SUFFIXES = (
    "yungu.org",
    "yungu-inc.org",
    "yunguhs.com",
    "localhost",
)


def campus_tcp(host: str, port: int, timeout: float = 1.2) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def campus_needs_wechat_hop() -> bool:
    """True if campus cannot open the WeChat endpoints WeChat actually dials."""
    failed = 0
    for host, port in WECHAT_PROBES:
        if not campus_tcp(host, port, 1.5):
            failed += 1
    return failed > 0


class StickyCampus:
    """After a campus miss, skip the next campus tries for fail_hold seconds."""

    def __init__(self, fail_hold: float = 45.0):
        self.fail_hold = fail_hold
        self._fail_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def skip_campus(self, host: str) -> bool:
        with self._lock:
            return time.time() < self._fail_until.get(host, 0)

    def mark_fail(self, host: str) -> None:
        with self._lock:
            self._fail_until[host] = time.time() + self.fail_hold

    def mark_ok(self, host: str) -> None:
        with self._lock:
            self._fail_until.pop(host, None)


class WechatHysteresis:
    """Start hop on first fail. Only drop hop after a hold plus consecutive oks."""

    def __init__(self, ok_needed: int = 6, min_hold: float = 180.0):
        self.ok_needed = ok_needed
        self.min_hold = min_hold
        self.ok_streak = 0
        self.hold_until = 0.0

    def on_fail(self) -> None:
        self.ok_streak = 0
        self.hold_until = max(self.hold_until, time.time() + self.min_hold)

    def on_ok(self) -> None:
        self.ok_streak += 1

    def should_keep_hop(self) -> bool:
        if time.time() < self.hold_until:
            return True
        return self.ok_streak < self.ok_needed


def probe_hop_suffixes() -> tuple[str, ...]:
    need: list[str] = []
    seen: set[str] = set()
    for (host, port), suffixes in PROBE_GROUPS:
        if campus_tcp(host, port):
            continue
        for suffix in suffixes:
            if suffix not in seen:
                seen.add(suffix)
                need.append(suffix)
    return tuple(need)


def build_local_judge_pac(proxy_host: str, proxy_port: int) -> str:
    """School stays campus. Everything else goes to the local judge (short campus try, then VPS)."""
    school = ",\n        ".join(f'"{s}"' for s in SCHOOL_SUFFIXES)
    proxy = f"PROXY {proxy_host}:{proxy_port}"
    return f"""function hostMatches(host, list) {{
    var i, s;
    for (i = 0; i < list.length; i++) {{
        s = list[i];
        if (host === s || dnsDomainIs(host, "." + s)) return true;
    }}
    return false;
}}

function FindProxyForURL(url, host) {{
    if (!host) return "DIRECT";
    host = host.toLowerCase();
    if (host === "task.yungu.org" || dnsDomainIs(host, ".task.yungu.org") || host === "116.62.109.80") return "DIRECT";
    if (host.indexOf("yungu") !== -1) return "DIRECT";
    if (isPlainHostName(host)) return "DIRECT";
    if (host === "127.0.0.1" || host === "::1" || host === "localhost") return "DIRECT";
    if (host === "117.55.227.80") return "DIRECT";
    if (host === "{proxy_host}") return "DIRECT";
    try {{
        if (isInNet(host, "10.0.0.0", "255.0.0.0")) return "DIRECT";
        if (isInNet(host, "172.16.0.0", "255.240.0.0")) return "DIRECT";
        if (isInNet(host, "192.168.0.0", "255.255.0.0")) return "DIRECT";
        if (isInNet(host, "127.0.0.0", "255.0.0.0")) return "DIRECT";
    }} catch (e) {{}}
    var school = [
        {school}
    ];
    if (hostMatches(host, school)) return "DIRECT";
    return "{proxy}";
}}
"""


def build_failover_pac(proxy_host: str, proxy_port: int, hop_suffixes: tuple[str, ...] = ()) -> str:
    """School stays campus. Known-dead hosts go hop immediately. Others try DIRECT then hop."""
    school = ",\n        ".join(f'"{s}"' for s in SCHOOL_SUFFIXES)
    hop = ",\n        ".join(f'"{s}"' for s in hop_suffixes)
    proxy = f"PROXY {proxy_host}:{proxy_port}"
    return f"""function hostMatches(host, list) {{
    var i, s;
    for (i = 0; i < list.length; i++) {{
        s = list[i];
        if (host === s || dnsDomainIs(host, "." + s)) return true;
    }}
    return false;
}}

function FindProxyForURL(url, host) {{
    if (!host) return "DIRECT";
    host = host.toLowerCase();
    if (host === "task.yungu.org" || dnsDomainIs(host, ".task.yungu.org") || host === "116.62.109.80") return "DIRECT";
    if (host.indexOf("yungu") !== -1) return "DIRECT";
    if (isPlainHostName(host)) return "DIRECT";
    if (host === "127.0.0.1" || host === "::1" || host === "localhost") return "DIRECT";
    if (host === "117.55.227.80") return "DIRECT";
    if (host === "{proxy_host}") return "DIRECT";
    try {{
        if (isInNet(host, "10.0.0.0", "255.0.0.0")) return "DIRECT";
        if (isInNet(host, "172.16.0.0", "255.240.0.0")) return "DIRECT";
        if (isInNet(host, "192.168.0.0", "255.255.0.0")) return "DIRECT";
        if (isInNet(host, "127.0.0.0", "255.0.0.0")) return "DIRECT";
    }} catch (e) {{}}
    var school = [
        {school}
    ];
    if (hostMatches(host, school)) return "DIRECT";
    var hopNow = [
        {hop}
    ];
    if (hostMatches(host, hopNow)) return "{proxy}";
    return "DIRECT; {proxy}";
}}
"""


class HopProbe:
    def __init__(self, min_interval: float = 4.0):
        self.min_interval = min_interval
        self._last = 0.0
        self.suffixes: tuple[str, ...] = ()

    def refresh(self) -> tuple[str, ...]:
        now = time.time()
        if now - self._last < self.min_interval and self._last:
            return self.suffixes
        self._last = now
        self.suffixes = probe_hop_suffixes()
        return self.suffixes
