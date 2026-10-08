#!/usr/bin/env python3
"""Exercise the WeChat TCP hop (sshuttle) and print coverage + stability."""

from __future__ import annotations

import ipaddress
import socket
import ssl
import subprocess
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CIDR_PATH = HERE / "wechat_cidrs.txt"
HOSTS = (
    "weixin.qq.com",
    "szshort.weixin.qq.com",
    "short.weixin.qq.com",
    "long.weixin.qq.com",
    "extshort.weixin.qq.com",
    "minorshort.weixin.qq.com",
    "dns.weixin.qq.com",
    "login.weixin.qq.com",
)
LIVE = (
    ("43.163.178.44", 80),
    ("124.156.190.237", 80),
    ("43.137.190.166", 443),
    ("1.13.36.127", 80),
    ("1.13.132.127", 80),
    ("101.91.37.36", 8080),
)


def cidrs() -> list[ipaddress.IPv4Network]:
    out: list[ipaddress.IPv4Network] = []
    for raw in CIDR_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            out.append(ipaddress.ip_network(line, strict=False))
    return out


def covered(ip: str, nets: list[ipaddress.IPv4Network]) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in n for n in nets)


def hop_up() -> str:
    try:
        out = subprocess.check_output(
            ["pgrep", "-lf", "/opt/homebrew/bin/sshuttle -r"], text=True
        ).strip()
        return out or "down"
    except subprocess.CalledProcessError:
        return "down"


def tcp(host: str, port: int, timeout: float = 6) -> tuple[bool, float, str]:
    t0 = time.perf_counter()
    try:
        s = socket.create_connection((host, port), timeout)
        s.close()
        return True, (time.perf_counter() - t0) * 1000, ""
    except Exception as exc:
        return False, (time.perf_counter() - t0) * 1000, str(exc)


def http_get(host: str, port: int = 80, timeout: float = 8) -> tuple[bool, float, str]:
    t0 = time.perf_counter()
    try:
        s = socket.create_connection((host, port), timeout)
        s.settimeout(timeout)
        s.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        data = s.recv(48)
        s.close()
        return True, (time.perf_counter() - t0) * 1000, repr(data[:40])
    except Exception as exc:
        return False, (time.perf_counter() - t0) * 1000, str(exc)


def tls(host: str, port: int = 443, sni: str | None = None, timeout: float = 8) -> tuple[bool, float, str]:
    t0 = time.perf_counter()
    try:
        raw = socket.create_connection((host, port), timeout)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(raw, server_hostname=sni or host)
        ver = sock.version() or ""
        sock.close()
        return True, (time.perf_counter() - t0) * 1000, ver
    except Exception as exc:
        return False, (time.perf_counter() - t0) * 1000, str(exc)


def rounds(label: str, fn, n: int = 12) -> None:
    oks: list[float] = []
    fails = 0
    for _ in range(n):
        ok, ms, info = fn()
        if ok:
            oks.append(ms)
        else:
            fails += 1
            if fails <= 3:
                print(f"  fail {label} {ms:.0f}ms {info}", flush=True)
        time.sleep(0.15)
    if oks:
        oks.sort()
        print(
            f"  {label}  {len(oks)}/{n} ok  min={oks[0]:.0f} avg={sum(oks)/len(oks):.0f} max={oks[-1]:.0f}",
            flush=True,
        )
    else:
        print(f"  {label}  0/{n} ok", flush=True)


def main() -> None:
    nets = cidrs()
    print(f"hop: {hop_up()}", flush=True)
    print("=== coverage ===", flush=True)
    for host in HOSTS:
        try:
            ips = sorted({i[4][0] for i in socket.getaddrinfo(host, None, socket.AF_INET)})
        except Exception as exc:
            print(f"  DNS {host} {exc}", flush=True)
            continue
        for ip in ips:
            flag = "IN" if covered(ip, nets) else "MISS"
            print(f"  {flag} {host} {ip}", flush=True)
    print("=== live IPs ===", flush=True)
    for host, port in LIVE:
        flag = "IN" if covered(host, nets) else "MISS"
        ok, ms, err = tcp(host, port, 5)
        print(f"  {flag} {'OK' if ok else 'FAIL'} {ms:.0f}ms {host}:{port} {err}", flush=True)
    print("=== payload stability ===", flush=True)
    rounds("HTTP szshort:80", lambda: http_get("szshort.weixin.qq.com", 80))
    rounds("TLS weixin.qq.com:443", lambda: tls("weixin.qq.com", 443, "weixin.qq.com"))
    rounds("HTTP 1.13.36.127:80", lambda: http_get("1.13.36.127", 80), n=6)
    rounds("TCP 101.91.37.36:8080", lambda: tcp("101.91.37.36", 8080, 5), n=4)


if __name__ == "__main__":
    main()
