"""Tải protected package về client (tự động cài đặt — luồng 'Install' kiểu Steam).

Bất biến #1 (server-side verification): chỉ user có entitlement **active** mới tải được.
Lưu ý: payload.enc vẫn ở dạng mã hóa AES-256-GCM; payload key KHÔNG nằm trong package,
chỉ được cấp lúc Play qua /runtime/issue-token. Tải package ≠ chạy được app.
"""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user
from ..models import Entitlement, User
from ..services.audit import log_event
from ..services.storage import ALLOWED_FILES, is_valid_product_id, package_storage_dir

router = APIRouter(prefix="/me/packages", tags=["packages"])


def _check_product_id(product_id: str) -> str:
    if not is_valid_product_id(product_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="product_id không hợp lệ")
    return product_id


def _require_entitlement(db: Session, user: User, product_id: str) -> None:
    ent = db.scalar(
        select(Entitlement).where(
            Entitlement.user_id == user.id,
            Entitlement.product_id == product_id,
            Entitlement.status == "active",
        )
    )
    if ent is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Bạn không sở hữu app này")


@router.get("/{product_id}")
def package_info(product_id: str, user: User = Depends(get_current_user),
                 db: Session = Depends(get_db)):
    """Danh sách file + kích thước của package (để client biết cần tải gì)."""
    pid = _check_product_id(product_id)
    _require_entitlement(db, user, pid)

    d = package_storage_dir(pid)
    files = [
        {"name": name, "size": (d / name).stat().st_size}
        for name in ALLOWED_FILES
        if (d / name).is_file()
    ]
    if not files:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Product chưa được publish (chưa có package trên server)")
    return {"product_id": pid, "files": files}


@router.get("/{product_id}/{filename}")
def download(product_id: str, filename: str, request: Request,
             user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Tải một file của package. Whitelist filename + check entitlement + audit."""
    pid = _check_product_id(product_id)
    if filename not in ALLOWED_FILES:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File không hợp lệ")
    _require_entitlement(db, user, pid)

    path = package_storage_dir(pid) / filename
    if not path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Không tìm thấy file")

    log_event(db, event_type="download", result="success", user_id=user.id, product_id=pid,
              ip_address=(request.client.host if request.client else None), message=filename)
    return FileResponse(path, filename=filename, media_type="application/octet-stream")
