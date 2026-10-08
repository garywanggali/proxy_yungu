#!/usr/bin/env python3
"""Browser-facing HTTP proxy. Encrypts ×3 and camouflages before the SSH hop."""

from __future__ import annotations

import argparse
import select
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn

from cn_suffixes import CN_SUFFIXES, DIRECT_SUFFIXES
from crypto3 import derive_keys
from direct_or_hop import StickyCampus
from tunnel_proto import TYPE_CLOSE, TYPE_DATA, TYPE_ERR, TYPE_OK, TYPE_OPEN
from tunnel_proto import client_handshake, recv_frame, send_frame

KEYS = None
INNER_HOST = "127.0.0.1"
INNER_PORT = 17900
EXIT_HOST = "110.40.153.38"
CAMPUS_TRY = 1.0
STICKY = StickyCampus(fail_hold=45.0)
# VPS 到不了这些站；校园网抖也不改走服务器。
NEVER_HOP_SUFFIXES = (
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
)


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
)


def is_task_yungu(host: str) -> bool:
    host = (host or "").lower().split("%")[0].rstrip(".")
    return host == "task.yungu.org" or host.endswith(".task.yungu.org") or host == "116.62.109.80"


def always_hop(host: str) -> bool:
    """国内站和 Cursor 固定走 VPS。"""
    host = (host or "").lower()
    if never_hop(host):
        return False
    if any(host == s or host.endswith("." + s) for s in DIRECT_SUFFIXES):
        return False
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


def try_campus(host: str, port: int):
    if host in ("127.0.0.1", "::1", "localhost", EXIT_HOST):
        return None
    if STICKY.skip_campus(host):
        return None
    try:
        sock = socket.create_connection((host, port), CAMPUS_TRY)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        STICKY.mark_ok(host)
        return sock
    except OSError:
        STICKY.mark_fail(host)
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
                    data = src.recv(16384)
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
                data = browser.recv(16384)
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
        if is_task_yungu(host):
            self.send_error(403, "task.yungu.org is direct only")
            self.log_via("refuse-task", 403)
            return
        dest = None if always_hop(host) else try_campus(host, port)
        if dest is None and never_hop(host):
            try:
                dest = socket.create_connection((host, port), 4.0)
                dest.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                STICKY.mark_ok(host)
            except OSError:
                self.send_error(504, "campus google/github unreachable")
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
        hostport = self.path.encode("ascii", "replace")
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
        if is_task_yungu(host):
            self.send_error(403, "task.yungu.org is direct only")
            self.log_via("refuse-task", 403)
            return
        dest = None if always_hop(host) else try_campus(host, int(port_s))
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
