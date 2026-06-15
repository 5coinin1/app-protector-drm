"""Rate-limit đăng nhập đơn giản (chống brute-force mật khẩu).

Sliding-window trong bộ nhớ, theo từng key (thường là IP). Đủ cho phạm vi đồ án; môi trường
thật nhiều tiến trình thì dùng Redis. Reset khi đăng nhập thành công.
"""
import time

from ..config import settings

# key -> danh sách mốc thời gian (monotonic) các lần fail gần đây
_failures: dict[str, list[float]] = {}


def seconds_locked(key: str) -> float:
    """Số giây còn bị khóa (0 nếu chưa khóa). Cũng dọn các lần fail đã quá cửa sổ."""
    window = settings.login_window_seconds
    now = time.monotonic()
    recent = [t for t in _failures.get(key, []) if now - t < window]
    _failures[key] = recent
    if len(recent) >= settings.login_max_attempts:
        return max(0.0, window - (now - recent[0]))  # mở khóa khi fail cũ nhất rời cửa sổ
    return 0.0


def record_failure(key: str) -> None:
    _failures.setdefault(key, []).append(time.monotonic())


def reset(key: str) -> None:
    _failures.pop(key, None)
