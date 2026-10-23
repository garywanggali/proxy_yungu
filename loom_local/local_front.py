#!/usr/bin/env python3
"""Browser-facing HTTP proxy. Encrypts ×3 and camouflages before the SSH hop."""

from __future__ import annotations

import argparse
import ipaddress
import select
import socket
import ssl
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn

from cn_suffixes import (
    CN_SUFFIXES,
    DIRECT_SUFFIXES,
    is_bilibili_related,
    is_campus_cn,
    is_public_ip_literal,
    is_yungu_related,
)
from crypto3 import derive_keys
from direct_or_hop import StickyCampus
from tunnel_proto import TYPE_CLOSE, TYPE_DATA, TYPE_ERR, TYPE_OK, TYPE_OPEN
from tunnel_proto import client_handshake, recv_frame, send_frame

KEYS = None
INNER_HOST = "127.0.0.1"
INNER_PORT = 17900
EXIT_HOST = "117.55.227.80"
CAMPUS_TRY = 1.0
STICKY = StickyCampus(fail_hold=45.0)
# 图片站校园网 TLS 很快，主站经常 TCP 秒连、握手挂死。不能用一次成功代表整站。
BILI_TLS_TIMEOUT = 1.2
BILI_TLS_OK_HOLD = 30.0
_BILI_LOCK = threading.Lock()
_BILI_OK_IP: dict[str, tuple[str, float]] = {}
# 出口是洛杉矶。这些站校园网经常超时，直接走服务器。
NEVER_HOP_SUFFIXES = ()


def never_hop(host: str) -> bool:
    host = (host or "").lower()
    return any(host == s or host.endswith("." + s) for s in NEVER_HOP_SUFFIXES)


VPS_SUFFIXES = (
    "cursor.sh",
    "cursor.com",
    "cursorapi.com",
    "anysphere.xyz",
    "anysphere.co",
    "steampowered.com",
    "steamcommunity.com",
    "steamstatic.com",
    "steamusercontent.com",
    "steam-chat.com",
    "steamcontent.com",
    "steamserver.net",
    "steamstat.us",
    "cloudcone.com",
    "google.com",
    "google.com.hk",
    "googleapis.com",
    "gstatic.com",
    "googleusercontent.com",
    "googlevideo.com",
    "youtube.com",
    "ytimg.com",
    "ggpht.com",
    "gvt1.com",
    "github.com",
    "githubusercontent.com",
    "chatgpt.com",
    "openai.com",
    "oaistatic.com",
    "oaiusercontent.com",
    "amap.com",
    "gaode.com",
    "autonavi.com",
)


def always_hop(host: str) -> bool:
    """国内站和 Cursor 固定走 VPS。哔哩哔哩先试校园网（通就快），不通再 hop。"""
    host = (host or "").lower()
    if never_hop(host):
        return False
    if is_yungu_related(host) or is_campus_cn(host):
        return False
    if any(host == s or host.endswith("." + s) for s in DIRECT_SUFFIXES):
        return False
    # 校园网间歇性可看 B 站；强制洛杉矶会把 API/静态资源拖到数秒级。
    if is_bilibili_related(host):
        return False
    if is_public_ip_literal(host):
        return True
    if any(host == s or host.endswith("." + s) for s in VPS_SUFFIXES):
        return True
    return any(host == s or host.endswith("." + s) for s in CN_SUFFIXES)


def load_keys(path: str):
    secret = Path(path).read_text().strip()
    return derive_keys(secret)


def open_inner():
    sock = socket.create_connection((INNER_HOST, INNER_PORT), timeout=15)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    client_handshake(sock)
    return sock


def dns_lookup_a(name: str, server: str = "223.5.5.5") -> list[str]:
    """A records from a specific resolver. Used so Bilibili is not 8.8.8.8 overseas IPs."""
    labels = name.strip(".").split(".")
    if not labels or any(not part for part in labels):
        return []
    qname = b"".join(bytes([len(part)]) + part.encode("ascii") for part in labels) + b"\x00"
    req = struct.pack("!HHHHHH", 0x3344, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1.2)
        sock.sendto(req, (server, 53))
        data, _ = sock.recvfrom(2048)
    if len(data) < 12:
        return []
    answers = struct.unpack("!H", data[6:8])[0]
    i = 12
    while i < len(data):
        if data[i] >= 0xC0:
            i += 2
            break
        if data[i] == 0:
            i += 1
            break
        i += 1 + data[i]
    i += 4
    ips: list[str] = []
    for _ in range(answers):
        if i >= len(data):
            break
        if data[i] >= 0xC0:
            i += 2
        else:
            while i < len(data) and data[i] != 0:
                if data[i] >= 0xC0:
                    i += 2
                    break
                i += 1 + data[i]
            else:
                i += 1
        if i + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[i : i + 10])
        i += 10
        if rtype == 1 and rdlen == 4 and i + 4 <= len(data):
            ip = socket.inet_ntoa(data[i : i + 4])
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                addr = None
            if addr and not (addr.is_loopback or addr.is_unspecified or addr.is_link_local):
                ips.append(ip)
        i += rdlen
    return ips


def ipv4_hop_target(host: str, port: int) -> str | None:
    """Hop by IPv4 only. A poisoned AAAA (face:b00c) makes Chrome report a failed tunnel."""
    bare = host.strip("[]")
    try:
        addr = ipaddress.ip_address(bare)
    except ValueError:
        addr = None
    if addr is not None:
        if addr.version == 6 or addr.is_loopback or addr.is_unspecified or addr.is_link_local:
            return None
        return bare
    # 洛杉矶出口自己解析。先在校园网解析会得到国内地址，那边连不上。
    if bare == "app.cloudcone.com":
        return "148.135.114.68"
    return bare


def connect_campus(host: str, port: int, timeout: float):
    """Campus TCP. Bilibili family uses AliDNS so 8.8.8.8 overseas A records are skipped."""
    ips: list[str] = []
    if is_campus_cn(host) or is_bilibili_related(host):
        for server in ("223.5.5.5", "114.114.114.114"):
            try:
                ips = dns_lookup_a(host, server)
            except OSError:
                ips = []
            if ips:
                break
    last: OSError | None = None
    for target in ips[:6] or [host]:
        try:
            sock = socket.create_connection((target, port), timeout)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            return sock
        except OSError as exc:
            last = exc
    raise last or OSError("campus connect failed")


def stay_on_campus(host: str) -> bool:
    return never_hop(host) or is_yungu_related(host) or is_campus_cn(host)


def _bili_candidates(host: str) -> list[str]:
    ips: list[str] = []
    for server in ("223.5.5.5", "114.114.114.114"):
        try:
            ips = dns_lookup_a(host, server)
        except OSError:
            ips = []
        if ips:
            break
    return ips[:3] or [host]


def bili_campus_ip(host: str, port: int) -> str | None:
    """IP whose TLS handshake finishes. None means this host should hop."""
    gate = host.lower()
    if port != 443:
        gate = "www.bilibili.com"
    now = time.time()
    cached = _BILI_OK_IP.get(gate)
    if cached and now < cached[1] and not STICKY.skip_campus(gate):
        return cached[0]
    if STICKY.skip_campus(gate):
        return None
    with _BILI_LOCK:
        now = time.time()
        cached = _BILI_OK_IP.get(gate)
        if cached and now < cached[1] and not STICKY.skip_campus(gate):
            return cached[0]
        if STICKY.skip_campus(gate):
            return None
        ctx = ssl.create_default_context()
        for ip in _bili_candidates(gate):
            sock = None
            try:
                sock = socket.create_connection((ip, 443), BILI_TLS_TIMEOUT)
                sock.settimeout(BILI_TLS_TIMEOUT)
                tls = ctx.wrap_socket(sock, server_hostname=gate)
                tls.close()
                _BILI_OK_IP[gate] = (ip, time.time() + BILI_TLS_OK_HOLD)
                STICKY.mark_ok(gate)
                return ip
            except OSError:
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
        STICKY.mark_fail(gate)
        _BILI_OK_IP.pop(gate, None)
        return None


def try_campus(host: str, port: int):
    if host in ("127.0.0.1", "::1", "localhost", EXIT_HOST):
        return None
    bili_ip = None
    if is_bilibili_related(host):
        if port == 443:
            bili_ip = bili_campus_ip(host, port)
            if bili_ip is None:
                return None
        elif bili_campus_ip("www.bilibili.com", 443) is None:
            return None
    campus_cn = is_campus_cn(host)
    if not campus_cn and not is_bilibili_related(host) and STICKY.skip_campus(host):
        return None
    try:
        if bili_ip:
            sock = socket.create_connection((bili_ip, port), CAMPUS_TRY)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            return sock
        sock = connect_campus(host, port, CAMPUS_TRY)
        STICKY.mark_ok(host)
        return sock
    except OSError:
        if not campus_cn and not is_bilibili_related(host):
            STICKY.mark_fail(host)
        if is_bilibili_related(host):
            STICKY.mark_fail(host.lower() if port == 443 else "www.bilibili.com")
        return None


def splice(a, b):
    sockets = [a, b]
    try:
        while True:
            readable, _, _ = select.select(sockets, [], [], 120)
            if not readable:
                break
            for src in readable:
                dest = b if src is a else a
                try:
                    data = src.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                try:
                    dest.sendall(data)
                except OSError:
                    return
    except Exception:
        return


def pump(browser, inner, keys):
    sockets = [browser, inner]
    try:
        while True:
            readable, _, _ = select.select(sockets, [], [], 120)
            if not readable:
                break
            if browser in readable:
                data = browser.recv(65536)
                if not data:
                    try:
                        send_frame(inner, keys, TYPE_CLOSE)
                    except OSError:
                        pass
                    return
                send_frame(inner, keys, TYPE_DATA, data)
            if inner in readable:
                typ, data = recv_frame(inner, keys)
                if typ == TYPE_DATA:
                    browser.sendall(data)
                elif typ in (TYPE_CLOSE, TYPE_ERR):
                    return
    except (OSError, ValueError):
        return


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 30

    def log_message(self, fmt, *args):
        return

    def log_via(self, via, code="-"):
        sys.stderr.write(
            "%s  %s %s  -> %s  %s\n"
            % (self.log_date_time_string(), self.command, self.path, via, code)
        )
        sys.stderr.flush()

    def log_request(self, code="-", size="-"):
        return

    def do_CONNECT(self):
        try:
            host, port_s = self.path.rsplit(":", 1)
            port = int(port_s)
        except ValueError:
            self.send_error(400)
            return
        dest = None if always_hop(host) else try_campus(host, port)
        if dest is None and stay_on_campus(host):
            try:
                dest = connect_campus(host, port, 4.0)
                STICKY.mark_ok(host)
            except OSError:
                self.send_error(504, "campus google/github/yungu/bilibili unreachable")
                return
        if dest:
            try:
                self.send_response(200, "Connection Established")
                self.end_headers()
                self.wfile.flush()
                self.log_via("campus", 200)
                splice(self.connection, dest)
            finally:
                dest.close()
            return
        target = ipv4_hop_target(host, port)
        if target is None:
            self.send_error(502, "ipv6 skipped")
            self.log_via("skip-ipv6", 502)
            return
        hostport = ("%s:%s" % (target, port)).encode("ascii", "replace")
        try:
            inner = open_inner()
        except OSError as exc:
            self.send_error(502, str(exc))
            return
        try:
            send_frame(inner, KEYS, TYPE_OPEN, hostport)
            typ, _data = recv_frame(inner, KEYS)
            if typ != TYPE_OK:
                self.send_error(502, "upstream")
                return
            self.send_response(200, "Connection Established")
            self.end_headers()
            self.log_via(EXIT_HOST, 200)
            pump(self.connection, inner, KEYS)
        except (OSError, ValueError) as exc:
            try:
                self.send_error(502, str(exc))
            except Exception:
                pass
        finally:
            inner.close()

    def _proxy_http(self):
        raw = self.path
        if not raw.startswith("http://"):
            self.send_error(400, "absolute URL required")
            return
        rest = raw[7:]
        hostport, _, path = rest.partition("/")
        path = "/" + path
        if ":" not in hostport:
            hostport = hostport + ":80"
        host, port_s = hostport.rsplit(":", 1)
        dest = None if always_hop(host) else try_campus(host, int(port_s))
        if dest is None and stay_on_campus(host):
            try:
                dest = connect_campus(host, int(port_s), 4.0)
                STICKY.mark_ok(host)
            except OSError:
                dest = None
        if dest:
            try:
                req = "%s %s %s\r\n" % (self.command, path, self.protocol_version)
                for key, value in self.headers.items():
                    if key.lower() in ("proxy-connection", "connection"):
                        continue
                    req += "%s: %s\r\n" % (key, value)
                req += "Connection: close\r\n\r\n"
                dest.sendall(req.encode("iso-8859-1", "replace"))
                length = int(self.headers.get("Content-Length") or 0)
                left = length
                while left > 0:
                    chunk = self.rfile.read(min(16384, left))
                    if not chunk:
                        break
                    dest.sendall(chunk)
                    left -= len(chunk)
                self.log_via("campus", 200)
                splice(self.connection, dest)
            finally:
                dest.close()
            return
        if is_yungu_related(host) or is_campus_cn(host):
            self.send_error(504, "campus yungu/bilibili unreachable")
            return
        try:
            inner = open_inner()
        except OSError as exc:
            self.send_error(502, str(exc))
            return
        try:
            send_frame(inner, KEYS, TYPE_OPEN, hostport.encode("ascii", "replace"))
            typ, _data = recv_frame(inner, KEYS)
            if typ != TYPE_OK:
                self.send_error(502, "upstream")
                return
            self.log_via(EXIT_HOST, 200)
            req = "%s %s %s\r\n" % (self.command, path, self.protocol_version)
            for key, value in self.headers.items():
                if key.lower() in ("proxy-connection", "connection"):
                    continue
                req += "%s: %s\r\n" % (key, value)
            req += "Connection: close\r\n\r\n"
            send_frame(inner, KEYS, TYPE_DATA, req.encode("iso-8859-1", "replace"))
            length = int(self.headers.get("Content-Length") or 0)
            left = length
            while left > 0:
                chunk = self.rfile.read(min(16384, left))
                if not chunk:
                    break
                send_frame(inner, KEYS, TYPE_DATA, chunk)
                left -= len(chunk)
            while True:
                typ, data = recv_frame(inner, KEYS)
                if typ == TYPE_DATA:
                    self.connection.sendall(data)
                else:
                    break
        except (OSError, ValueError) as exc:
            try:
                self.send_error(502, str(exc))
            except Exception:
                pass
        finally:
            inner.close()

    def do_GET(self):
        self._proxy_http()

    def do_POST(self):
        self._proxy_http()

    def do_HEAD(self):
        self._proxy_http()

    def do_PUT(self):
        self._proxy_http()

    def do_DELETE(self):
        self._proxy_http()

    def do_PATCH(self):
        self._proxy_http()


class Server(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class PacHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        path = Path(__file__).resolve().parent / "split.pac"
        if not path.exists():
            self.send_error(404)
            return
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def serve_pac(bind: str) -> None:
    host, port_s = bind.rsplit(":", 1)
    httpd = Server((host, int(port_s)), PacHandler)
    print("loom_local pac %s" % bind, flush=True)
    httpd.serve_forever()


def main():
    global KEYS, INNER_HOST, INNER_PORT
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="127.0.0.1:17890")
    parser.add_argument("--inner", default="127.0.0.1:17900")
    parser.add_argument("--pac", default="127.0.0.1:17891")
    parser.add_argument("--key-file", required=True)
    args = parser.parse_args()
    KEYS = load_keys(args.key_file)
    host, port_s = args.listen.rsplit(":", 1)
    INNER_HOST, inner_port_s = args.inner.rsplit(":", 1)
    INNER_PORT = int(inner_port_s)
    threading.Thread(target=serve_pac, args=(args.pac,), daemon=True).start()
    httpd = Server((host, int(port_s)), Handler)
    print("loom_local front %s -> %s (×3)" % (args.listen, args.inner), flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    threading.stack_size(512 * 1024)
    main()
