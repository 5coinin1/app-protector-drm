"""Đóng gói app ngay trên server bằng Protector CLI (C).

Dashboard nhận file app (1 file thực thi hoặc 1 .zip thư mục app) -> service này gọi
`protector.exe pack` (mã hóa AES-256-GCM + ký manifest Ed25519, KHÔNG viết lại crypto bằng
Python) -> trả về payload key (b64) và thư mục chứa các file phát hành.

Tái dùng đúng công cụ developer; chỉ tự động hóa việc chạy nó từ web.
"""
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

from ..config import settings
from ..services.storage import ALLOWED_FILES, package_storage_dir


class PackError(Exception):
    """Lỗi nghiệp vụ khi đóng gói (hiển thị cho admin trên dashboard)."""


def _protector_env() -> dict:
    """PATH có thư mục DLL MinGW để protector.exe (link MSYS2) chạy được."""
    env = os.environ.copy()
    mingw = settings.mingw_bin
    if mingw and Path(mingw).is_dir():
        env["PATH"] = mingw + os.pathsep + env.get("PATH", "")
    return env


ARCHIVE_EXTS = (".zip", ".rar", ".7z")


def _extract_archive(filename: str, archive_path: Path, dest: Path) -> None:
    """Giải nén archive vào dest. .zip dùng Python; .rar/.7z dùng công cụ ngoài.

    Ném PackError với hướng dẫn rõ ràng nếu định dạng không hỗ trợ / thiếu công cụ.
    """
    name = filename.lower()
    if name.endswith(".zip"):
        try:
            with zipfile.ZipFile(archive_path) as zf:
                zf.extractall(dest)
        except zipfile.BadZipFile:
            raise PackError("File .zip không hợp lệ.")
        return

    if name.endswith(".rar"):
        ex = Path(settings.unrar_exe)
        if not ex.is_file():
            raise PackError("Server chưa cài UnRAR/WinRAR để giải nén .rar. "
                            "Hãy nén app lại thành .zip rồi upload.")
        cmd = [str(ex), "x", "-y", "-idq", str(archive_path), str(dest) + os.sep]
    elif name.endswith(".7z"):
        ex = Path(settings.sevenzip_exe)
        if not ex.is_file():
            raise PackError("Server chưa cài 7-Zip để giải nén .7z. "
                            "Hãy nén app lại thành .zip rồi upload.")
        cmd = [str(ex), "x", str(archive_path), "-o" + str(dest), "-y"]
    else:
        raise PackError(f"Định dạng nén không hỗ trợ. Dùng một trong: {', '.join(ARCHIVE_EXTS)}.")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise PackError(f"Không giải nén được archive: {e}")
    if proc.returncode != 0:
        raise PackError(f"Giải nén thất bại: {(proc.stderr or proc.stdout).strip()[:300]}")


def _autodetect_entry(input_dir: Path) -> str:
    """Tự dò file thực thi trong app. Trả về đường dẫn tương đối (dùng '/').

    Ưu tiên .exe; nếu không có thì .bat/.cmd (launcher chạy entry qua cmd nên đều được).
    Trong mỗi nhóm: đúng 1 file -> chọn luôn; nhiều file -> ưu tiên file ở thư mục gốc;
    nếu vẫn nhiều -> yêu cầu nhập tay.
    """
    for patterns in (("*.exe",), ("*.bat", "*.cmd")):
        found = sorted(p for pat in patterns for p in input_dir.rglob(pat))
        if not found:
            continue
        if len(found) == 1:
            return found[0].relative_to(input_dir).as_posix()
        roots = [e for e in found if e.parent == input_dir]
        if len(roots) == 1:
            return roots[0].relative_to(input_dir).as_posix()
        names = ", ".join(e.relative_to(input_dir).as_posix() for e in found[:10])
        raise PackError(f"Có nhiều file thực thi, hãy nhập 'entry' là một trong: {names}")

    raise PackError("Không tìm thấy file thực thi (.exe/.bat/.cmd) — hãy nhập 'entry' thủ công.")


def protect_app(filename: str, data: bytes, product_id: str, version: str,
                entry: str | None) -> str:
    """Đóng gói file app đã upload thành protected package trên server.

    - `filename`/`data`: file admin upload. Nếu là .zip -> giải nén làm thư mục app;
      ngược lại coi là 1 file thực thi.
    - `entry`: tên file thực thi sẽ chạy. Với upload 1 file, mặc định = tên file đó;
      với .zip thì bắt buộc nhập.

    Trả về payload key (base64) để caller đăng ký vào DB. Đồng thời copy
    payload.enc / manifest.signed.json / public_key.pem vào storage của product.
    Ném PackError nếu thất bại.
    """
    exe = Path(settings.protector_exe)
    if not exe.is_file():
        raise PackError(f"Không tìm thấy protector.exe tại {exe}. Hãy build protector trước.")

    is_archive = filename.lower().endswith(ARCHIVE_EXTS)
    if not is_archive:
        entry = entry or filename   # upload 1 file -> entry mặc định là tên file đó

    with tempfile.TemporaryDirectory(prefix="pk_pack_") as tmp:
        tmp_path = Path(tmp)
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        if is_archive:
            arch_path = tmp_path / ("app" + Path(filename).suffix.lower())
            arch_path.write_bytes(data)
            _extract_archive(filename, arch_path, input_dir)
            # Nếu archive chỉ chứa đúng 1 thư mục con, dùng thư mục đó làm input.
            entries = [p for p in input_dir.iterdir()]
            if len(entries) == 1 and entries[0].is_dir():
                input_dir = entries[0]
            # Để trống entry -> TỰ DÒ file thực thi trong app.
            if not entry:
                entry = _autodetect_entry(input_dir)
        else:
            (input_dir / filename).write_bytes(data)

        if not (input_dir / entry).is_file():
            raise PackError(f"Không thấy entry '{entry}' trong app đã upload.")

        cmd = [
            str(exe), "pack",
            "--input", str(input_dir),
            "--entry", entry,
            "--product-id", product_id,
            "--output", str(output_dir),
            "--version", version,
            "--keys", settings.protector_keys_dir,
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  env=_protector_env(), timeout=120)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise PackError(f"Không chạy được protector: {e}")
        if proc.returncode != 0:
            raise PackError(f"protector lỗi (exit {proc.returncode}): "
                            f"{(proc.stderr or proc.stdout).strip()[:400]}")

        key_file = output_dir / "SECRET_payload_key.b64"
        if not key_file.is_file():
            raise PackError("protector chạy xong nhưng thiếu SECRET_payload_key.b64.")
        payload_key_b64 = key_file.read_text(encoding="utf-8").strip()

        # Copy các file phát hành vào storage của product (đè bản cũ nếu có).
        dest = package_storage_dir(product_id)
        dest.mkdir(parents=True, exist_ok=True)
        for name in ALLOWED_FILES:
            src = output_dir / name
            if not src.is_file():
                raise PackError(f"protector thiếu output {name}.")
            shutil.copyfile(src, dest / name)

        return payload_key_b64
