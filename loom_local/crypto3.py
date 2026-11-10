#!/usr/bin/env python3
"""AES-128-GCM tunnel crypto via libcrypto. Python 3.6+."""

import ctypes
import ctypes.util
import hashlib
import os


def derive_keys(secret):
    if not isinstance(secret, bytes):
        secret = secret.encode("utf-8")
    keys = []
    for i in (1, 2, 3):
        keys.append(hashlib.sha256(secret + ("|loom-k%d" % i).encode("ascii")).digest())
    return keys


# One AES-128-GCM inside the SSH tunnel. The old HMAC-SHA256 keystream
# capped the Los Angeles box near 280 KB/s and stalled live video.
_EVP_CTRL_GCM_SET_IVLEN = 0x9
_EVP_CTRL_GCM_GET_TAG = 0x10
_EVP_CTRL_GCM_SET_TAG = 0x11
_LIB = None


def _crypto_lib():
    global _LIB
    if _LIB is not None:
        return _LIB
    path = ctypes.util.find_library("crypto")
    if not path:
        for cand in (
            "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
            "/opt/homebrew/lib/libcrypto.dylib",
        ):
            try:
                open(cand, "rb").close()
            except OSError:
                continue
            path = cand
            break
    if not path:
        raise OSError("libcrypto not found")
    lib = ctypes.CDLL(path)
    lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
    lib.EVP_aes_128_gcm.restype = ctypes.c_void_p
    lib.EVP_EncryptInit_ex.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ]
    lib.EVP_DecryptInit_ex.argtypes = lib.EVP_EncryptInit_ex.argtypes
    lib.EVP_EncryptUpdate.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.c_void_p, ctypes.c_int,
    ]
    lib.EVP_DecryptUpdate.argtypes = lib.EVP_EncryptUpdate.argtypes
    lib.EVP_EncryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
    lib.EVP_DecryptFinal_ex.argtypes = lib.EVP_EncryptFinal_ex.argtypes
    lib.EVP_CIPHER_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
    _LIB = lib
    return lib


def _aes_key(keys):
    return keys[0][:16]


def seal3(keys, plaintext):
    lib = _crypto_lib()
    key = _aes_key(keys)
    nonce = os.urandom(12)
    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        raise OSError("cipher ctx")
    try:
        if lib.EVP_EncryptInit_ex(ctx, lib.EVP_aes_128_gcm(), None, None, None) != 1:
            raise ValueError("gcm init")
        if lib.EVP_CIPHER_CTX_ctrl(ctx, _EVP_CTRL_GCM_SET_IVLEN, 12, None) != 1:
            raise ValueError("gcm iv")
        key_buf = ctypes_buf(key)
        nonce_buf = ctypes_buf(nonce)
        if lib.EVP_EncryptInit_ex(ctx, None, None, key_buf, nonce_buf) != 1:
            raise ValueError("gcm key")
        out = bytearray(len(plaintext))
        out_buf = (ctypes.c_char * len(out)).from_buffer(out) if out else None
        in_buf = ctypes_buf(plaintext) if plaintext else None
        outlen = ctypes.c_int()
        if lib.EVP_EncryptUpdate(ctx, out_buf, ctypes.byref(outlen), in_buf, len(plaintext)) != 1:
            raise ValueError("gcm update")
        final = ctypes.create_string_buffer(16)
        finlen = ctypes.c_int()
        if lib.EVP_EncryptFinal_ex(ctx, final, ctypes.byref(finlen)) != 1:
            raise ValueError("gcm final")
        tag = ctypes.create_string_buffer(16)
        if lib.EVP_CIPHER_CTX_ctrl(ctx, _EVP_CTRL_GCM_GET_TAG, 16, tag) != 1:
            raise ValueError("gcm tag")
        return nonce + tag.raw + bytes(out[: outlen.value]) + final.raw[: finlen.value]
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)


def open3(keys, blob):
    if len(blob) < 28:
        raise ValueError("short")
    lib = _crypto_lib()
    key = _aes_key(keys)
    nonce, tag, ct = blob[:12], blob[12:28], blob[28:]
    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        raise OSError("cipher ctx")
    try:
        if lib.EVP_DecryptInit_ex(ctx, lib.EVP_aes_128_gcm(), None, None, None) != 1:
            raise ValueError("gcm init")
        if lib.EVP_CIPHER_CTX_ctrl(ctx, _EVP_CTRL_GCM_SET_IVLEN, 12, None) != 1:
            raise ValueError("gcm iv")
        if lib.EVP_DecryptInit_ex(ctx, None, None, ctypes_buf(key), ctypes_buf(nonce)) != 1:
            raise ValueError("gcm key")
        out = bytearray(len(ct))
        out_buf = (ctypes.c_char * len(out)).from_buffer(out) if out else None
        outlen = ctypes.c_int()
        if lib.EVP_DecryptUpdate(ctx, out_buf, ctypes.byref(outlen), ctypes_buf(ct) if ct else None, len(ct)) != 1:
            raise ValueError("gcm update")
        if lib.EVP_CIPHER_CTX_ctrl(ctx, _EVP_CTRL_GCM_SET_TAG, 16, ctypes_buf(tag)) != 1:
            raise ValueError("gcm tag")
        final = ctypes.create_string_buffer(16)
        finlen = ctypes.c_int()
        if lib.EVP_DecryptFinal_ex(ctx, final, ctypes.byref(finlen)) != 1:
            raise ValueError("mac")
        return bytes(out[: outlen.value]) + final.raw[: finlen.value]
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)


def ctypes_buf(data):
    import ctypes
    buf = ctypes.create_string_buffer(len(data))
    buf.raw = data
    return buf
