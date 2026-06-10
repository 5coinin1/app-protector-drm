"""Runtime API: cấp entitlement token đã ký + payload key sau khi xác nhận quyền sở hữu.

Đây là nơi thực thi "server-side verification": client KHÔNG tự quyết được quyền chạy.
"""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..deps import get_current_user
from ..models import Device, Entitlement, ProductKey, User
from ..schemas import IssueTokenIn
from ..services.audit import log_event
from ..services.tokens import issue_entitlement_token, server_public_key_b64

router = APIRouter(prefix="/runtime", tags=["runtime"])


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.get("/public-key")
def public_key():
    """Public key Ed25519 của server (để launcher verify entitlement token)."""
    return {"server_public_key_b64": server_public_key_b64(), "alg": "Ed25519"}


@router.post("/issue-token")
def issue_token(body: IssueTokenIn, request: Request,
                user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    ip = _ip(request)

    # 1. Kiểm tra quyền sở hữu (entitlement active)
    ent = db.scalar(
        select(Entitlement).where(
            Entitlement.user_id == user.id,
            Entitlement.product_id == body.product_id,
            Entitlement.status == "active",
        )
    )
    if ent is None:
        log_event(db, event_type="run_app", result="fail", user_id=user.id,
                  product_id=body.product_id, ip_address=ip, message="khong so huu app")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Bạn không sở hữu app này")

    # 2. Đăng ký / kiểm tra thiết bị + device limit + revocation
    dev = db.scalar(
        select(Device).where(Device.user_id == user.id, Device.hardware_hash == body.hardware_hash)
    )
    if dev is None:
        active_count = db.scalar(
            select(func.count()).select_from(Device).where(
                Device.user_id == user.id, Device.status == "active"
            )
        ) or 0
        if active_count >= settings.device_limit:
            log_event(db, event_type="run_app", result="fail", user_id=user.id,
                      product_id=body.product_id, ip_address=ip,
                      message=f"vuot gioi han thiet bi ({settings.device_limit})")
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail=f"Vượt giới hạn {settings.device_limit} thiết bị")
        dev = Device(user_id=user.id, hardware_hash=body.hardware_hash,
                     device_name=body.device_name, status="active")
        db.add(dev)
        log_event(db, event_type="device_register", result="success", user_id=user.id,
                  product_id=body.product_id, ip_address=ip, message=body.device_name)
    else:
        if dev.status != "active":
            log_event(db, event_type="run_app", result="fail", user_id=user.id,
                      product_id=body.product_id, ip_address=ip, message="thiet bi bi thu hoi")
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Thiết bị đã bị thu hồi")
        if body.device_name:
            dev.device_name = body.device_name
    db.commit()

    # 3. Lấy payload key (server-side key)
    pkey = db.scalar(
        select(ProductKey).where(
            ProductKey.product_id == body.product_id, ProductKey.status == "active"
        )
    )
    if pkey is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Product chưa đăng ký payload key trên server")

    # 4. Ký entitlement token
    token = issue_entitlement_token(user.id, body.product_id, body.hardware_hash,
                                    settings.offline_grace_days)

    log_event(db, event_type="run_app", result="success", user_id=user.id,
              product_id=body.product_id, ip_address=ip, message="cap entitlement token")

    return {
        "token": token,
        "payload_key_b64": pkey.encrypted_payload_key,
        "server_public_key_b64": server_public_key_b64(),
        "offline_until": token["offline_until"],
    }
