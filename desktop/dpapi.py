"""Bọc Windows DPAPI (CryptProtectData / CryptUnprotectData) qua ctypes.

Dùng để mã hóa file session (token + payload key) ở local. DPAPI trói dữ liệu vào
TÀI KHOẢN WINDOWS hiện tại trên MÁY này -> copy file mã hóa sang máy/khác user khác thì
giải mã thất bại -> bí mật vô dụng. Không cần cài thư viện ngoài (crypt32 có sẵn trên Windows).
"""
import ctypes
from ctypes import wintypes


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char))]


_crypt32 = ctypes.windll.crypt32
_kernel32 = ctypes.windll.kernel32
_CRYPTPROTECT_UI_FORBIDDEN = 0x01


def _to_blob(data: bytes) -> _DATA_BLOB:
    buf = ctypes.create_string_buffer(data, len(data))
    return _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))


def _from_blob(blob: _DATA_BLOB) -> bytes:
    n = int(blob.cbData)
    out = ctypes.create_string_buffer(n)
    ctypes.memmove(out, blob.pbData, n)
    return out.raw


def protect(data: bytes) -> bytes:
    """Mã hóa data (raise OSError nếu lỗi)."""
    blob_in = _to_blob(data)
    blob_out = _DATA_BLOB()
    ok = _crypt32.CryptProtectData(ctypes.byref(blob_in), None, None, None, None,
                                   _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out))
    if not ok:
        raise OSError("CryptProtectData failed")
    try:
        return _from_blob(blob_out)
    finally:
        _kernel32.LocalFree(blob_out.pbData)


def unprotect(blob: bytes) -> bytes:
    """Giải mã blob (raise OSError nếu lỗi — vd file từ máy/user khác)."""
    blob_in = _to_blob(blob)
    blob_out = _DATA_BLOB()
    ok = _crypt32.CryptUnprotectData(ctypes.byref(blob_in), None, None, None, None,
                                     _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out))
    if not ok:
        raise OSError("CryptUnprotectData failed")
    try:
        return _from_blob(blob_out)
    finally:
        _kernel32.LocalFree(blob_out.pbData)
