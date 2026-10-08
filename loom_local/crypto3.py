#!/usr/bin/env python3
"""Three-layer HMAC-SHA256-CTR + MAC. Stdlib only. Python 3.6+."""

import hashlib
import hmac
import os
import struct


def derive_keys(secret):
    if not isinstance(secret, bytes):
        secret = secret.encode("utf-8")
    keys = []
    for i in (1, 2, 3):
        keys.append(hashlib.sha256(secret + ("|loom-k%d" % i).encode("ascii")).digest())
    return keys


def _crypt(key, nonce, data):
    out = bytearray(len(data))
    counter = 0
    i = 0
    n = len(data)
    while i < n:
        block = hmac.new(key, nonce + struct.pack(">Q", counter), hashlib.sha256).digest()
        take = min(32, n - i)
        for j in range(take):
            out[i + j] = data[i + j] ^ block[j]
        i += take
        counter += 1
    return bytes(out)


def seal_once(key, plaintext):
    nonce = os.urandom(16)
    ct = _crypt(key, nonce, plaintext)
    tag = hmac.new(key, nonce + ct, hashlib.sha256).digest()
    return nonce + tag + ct


def open_once(key, blob):
    if len(blob) < 48:
        raise ValueError("short")
    nonce, tag, ct = blob[:16], blob[16:48], blob[48:]
    expect = hmac.new(key, nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expect):
        raise ValueError("mac")
    return _crypt(key, nonce, ct)


def seal3(keys, plaintext):
    x = plaintext
    for key in keys:
        x = seal_once(key, x)
    return x


def open3(keys, blob):
    x = blob
    for key in reversed(keys):
        x = open_once(key, x)
    return x
