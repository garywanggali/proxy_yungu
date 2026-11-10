#!/usr/bin/env python3
"""Decrypt ×3 WebSocket-looking hop, then open the real destination.

Python 3.6 compatible. Bind 127.0.0.1 only.
"""

import argparse
import select
import socket
import sys
import threading
import time

from crypto3 import derive_keys
from tunnel_proto import TYPE_CLOSE, TYPE_DATA, TYPE_ERR, TYPE_OK, TYPE_OPEN
from tunnel_proto import recv_frame, send_frame, server_handshake


def load_keys(path):
    with open(path, "r") as fh:
        secret = fh.read().strip()
    return derive_keys(secret)


def _coalesce(sock, data, limit=65536, wait=0.04):
    """Bundle small CDN reads so each tunnel frame is not one round trip."""
    if len(data) >= limit:
        return data
    parts = [data]
    total = len(data)
    deadline = time.time() + wait
    while total < limit:
        timeout = deadline - time.time()
        if timeout <= 0:
            break
        ready, _, _ = select.select([sock], [], [], timeout)
        if not ready:
            break
        more = sock.recv(limit - total)
        if not more:
            break
        parts.append(more)
        total += len(more)
        deadline = time.time() + wait
    return b"".join(parts)


def splice_enc(inner, dest, keys):
    sockets = [inner, dest]
    try:
        while True:
            readable, _, _ = select.select(sockets, [], [], 120)
            if not readable:
                break
            if dest in readable:
                data = dest.recv(65536)
                if not data:
                    try:
                        send_frame(inner, keys, TYPE_CLOSE)
                    except OSError:
                        pass
                    return
                data = _coalesce(dest, data)
                send_frame(inner, keys, TYPE_DATA, data)
            if inner in readable:
                typ, data = recv_frame(inner, keys)
                if typ == TYPE_DATA:
                    dest.sendall(data)
                elif typ in (TYPE_CLOSE, TYPE_ERR):
                    return
    except (OSError, ValueError):
        return


def connect_ipv4(host, port, timeout=12):
    host = host.strip("[]")
    if ":" in host:
        raise OSError("ipv6 skipped")
    infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    last = OSError("no ipv4")
    for info in infos:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect(info[4])
            return sock
        except OSError as exc:
            last = exc
            sock.close()
    raise last


def handle(conn, keys):
    dest = None
    try:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        server_handshake(conn)
        typ, data = recv_frame(conn, keys)
        if typ != TYPE_OPEN:
            send_frame(conn, keys, TYPE_ERR, b"bad open")
            return
        hostport = data.decode("ascii", "replace")
        host, port_s = hostport.rsplit(":", 1)
        dest = connect_ipv4(host, int(port_s), timeout=12)
        dest.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        send_frame(conn, keys, TYPE_OK)
        splice_enc(conn, dest, keys)
    except (OSError, ValueError, UnicodeError):
        try:
            send_frame(conn, keys, TYPE_ERR)
        except Exception:
            pass
    finally:
        if dest is not None:
            dest.close()
        conn.close()


def serve(host, port, keys):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(64)
    sys.stdout.write("loom_local remote ×3 %s:%s\n" % (host, port))
    sys.stdout.flush()
    while True:
        conn, _addr = srv.accept()
        t = threading.Thread(target=handle, args=(conn, keys))
        t.daemon = True
        t.start()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=17900)
    parser.add_argument("--key-file", default="tunnel.key")
    args = parser.parse_args()
    keys = load_keys(args.key_file)
    serve(args.host, args.port, keys)


if __name__ == "__main__":
    main()
