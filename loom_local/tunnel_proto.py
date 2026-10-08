#!/usr/bin/env python3
"""Framed triple-encrypted tunnel with a WebSocket-looking handshake.

Python 3.6 compatible. The on-wire bytes are not HTTP CONNECT / SOCKS.
"""

import base64
import hashlib
import os
import struct

from crypto3 import open3, seal3

TYPE_OPEN = 1
TYPE_DATA = 2
TYPE_OK = 3
TYPE_ERR = 4
TYPE_CLOSE = 5

_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_MAX_FRAME = 2 * 1024 * 1024


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("closed")
        buf += chunk
    return buf


def send_frame(sock, keys, typ, data=b""):
    pad = os.urandom(16 + (os.urandom(1)[0] % 48))
    payload = struct.pack("BB", typ, len(pad)) + pad + data
    blob = seal3(keys, payload)
    sock.sendall(struct.pack(">I", len(blob)) + blob)


def recv_frame(sock, keys):
    raw_len = _recv_exact(sock, 4)
    (length,) = struct.unpack(">I", raw_len)
    if length <= 0 or length > _MAX_FRAME:
        raise ValueError("bad frame")
    blob = _recv_exact(sock, length)
    payload = open3(keys, blob)
    if len(payload) < 2:
        raise ValueError("short payload")
    typ = payload[0]
    padlen = payload[1]
    data = payload[2 + padlen :]
    return typ, data


def camouflage_request():
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    req = (
        "GET /cdn/static/app.7f3c2.js HTTP/1.1\r\n"
        "Host: update.windows.com\r\n"
        "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36\r\n"
        "Accept: */*\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "\r\n"
    ) % key
    return req.encode("ascii"), key


def camouflage_accept(ws_key):
    digest = hashlib.sha1((ws_key + _WS_GUID).encode("ascii")).digest()
    accept = base64.b64encode(digest).decode("ascii")
    return (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n"
        "\r\n"
    ) % accept


def read_http_headers(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise OSError("closed")
        data += chunk
        if len(data) > 16384:
            raise ValueError("headers too large")
    headers, rest = data.split(b"\r\n\r\n", 1)
    return headers.decode("iso-8859-1", "replace"), rest


def client_handshake(sock):
    req, key = camouflage_request()
    sock.sendall(req)
    headers, rest = read_http_headers(sock)
    if "101" not in headers.split("\r\n", 1)[0]:
        raise ValueError("handshake failed")
    if rest:
        raise ValueError("unexpected extra")
    return key


def server_handshake(sock):
    headers, rest = read_http_headers(sock)
    if rest:
        raise ValueError("unexpected extra")
    ws_key = ""
    for line in headers.split("\r\n"):
        if line.lower().startswith("sec-websocket-key:"):
            ws_key = line.split(":", 1)[1].strip()
    if not ws_key:
        raise ValueError("not ws")
    sock.sendall(camouflage_accept(ws_key).encode("ascii"))
