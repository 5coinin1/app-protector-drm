"""Admin API: quản lý product, user, entitlement (grant/revoke), xem audit log & device."""
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import require_admin
from ..models import Device, Entitlement, Product, ProductKey, User
from ..schemas import (
    AdminUserIn,
    AuditOut,
    GrantIn,
    ProductIn,
    ProductOut,
    SetKeyIn,
    UserOut,
)
from ..security import hash_password
from ..services.audit import log_event
from ..services.storage import ALLOWED_FILES, is_valid_product_id, package_storage_dir

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_admin)])


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


# ---------- Products ----------
@router.post("/products", response_model=ProductOut, status_code=status.HTTP_201_CREATED)
def create_product(body: ProductIn, db: Session = Depends(get_db)):
    if db.scalar(select(Product).where(Product.product_id == body.product_id)):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="product_id đã tồn tại")
    product = Product(product_id=body.product_id, name=body.name, version=body.version)
    db.add(product)
    db.commit()
    db.refresh(product)
    return product


@router.get("/products", response_model=list[ProductOut])
def list_products(db: Session = Depends(get_db)):
    return list(db.scalars(select(Product).order_by(Product.id)))


@router.post("/products/{product_id}/key", status_code=status.HTTP_200_OK)
def set_product_key(product_id: str, body: SetKeyIn, db: Session = Depends(get_db)):
    """Đăng ký payload key (base64) cho product — developer chạy sau khi pack.

    Key này được protector sinh ra (SECRET_payload_key.b64); KHÔNG đóng vào bản phát hành.
    """
    if db.scalar(select(Product).where(Product.product_id == product_id)) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Product không tồn tại")

    existing = db.scalar(
        select(ProductKey).where(ProductKey.product_id == product_id, ProductKey.status == "active")
    )
    if existing:
        existing.encrypted_payload_key = body.payload_key_b64
    else:
        db.add(ProductKey(product_id=product_id, encrypted_payload_key=body.payload_key_b64))
    db.commit()
    return {"detail": "Đã đăng ký payload key", "product_id": product_id}


@router.post("/products/{product_id}/package", status_code=status.HTTP_200_OK)
def upload_package(
    product_id: str,
    payload: UploadFile = File(...),
    manifest: UploadFile = File(...),
    public_key: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """Upload các file phát hành của package lên server (developer chạy sau khi pack).

    Client tải về qua GET /me/packages/{id}/{file} (có check entitlement).
    KHÔNG nhận SECRET_payload_key.b64 — key đăng ký riêng qua /products/{id}/key.
    """
    if not is_valid_product_id(product_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="product_id không hợp lệ")
    if db.scalar(select(Product).where(Product.product_id == product_id)) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Product không tồn tại")

    d = package_storage_dir(product_id)
    d.mkdir(parents=True, exist_ok=True)
    uploads = {
        "payload.enc": payload,
        "manifest.signed.json": manifest,
        "public_key.pem": public_key,
    }
    for name, up in uploads.items():
        (d / name).write_bytes(up.file.read())
    return {"detail": "Đã upload package", "product_id": product_id, "files": list(ALLOWED_FILES)}


# ---------- Users ----------
@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(body: AdminUserIn, db: Session = Depends(get_db)):
    if db.scalar(select(User).where(User.email == body.email)):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email đã tồn tại")
    user = User(email=body.email, password_hash=hash_password(body.password), role=body.role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.get("/users", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db)):
    return list(db.scalars(select(User).order_by(User.id)))


# ---------- Entitlements ----------
@router.post("/entitlements/grant", status_code=status.HTTP_200_OK)
def grant(body: GrantIn, request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.get(User, body.user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User không tồn tại")
    product = db.scalar(select(Product).where(Product.product_id == body.product_id))
    if product is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Product không tồn tại")

    ent = db.scalar(
        select(Entitlement).where(
            Entitlement.user_id == body.user_id, Entitlement.product_id == body.product_id
        )
    )
    if ent is None:
        ent = Entitlement(user_id=body.user_id, product_id=body.product_id, status="active")
        db.add(ent)
    else:
        ent.status = "active"
    db.commit()

    log_event(db, event_type="grant", result="success", user_id=body.user_id,
              product_id=body.product_id, ip_address=_ip(request),
              message=f"admin {admin.email} cấp {body.product_id}")
    return {"detail": "Đã cấp quyền", "user_id": body.user_id, "product_id": body.product_id}


@router.post("/entitlements/revoke", status_code=status.HTTP_200_OK)
def revoke(body: GrantIn, request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    ent = db.scalar(
        select(Entitlement).where(
            Entitlement.user_id == body.user_id, Entitlement.product_id == body.product_id
        )
    )
    if ent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Không tìm thấy entitlement")
    ent.status = "revoked"
    db.commit()

    log_event(db, event_type="revoke", result="success", user_id=body.user_id,
              product_id=body.product_id, ip_address=_ip(request),
              message=f"admin {admin.email} thu hồi {body.product_id}")
    return {"detail": "Đã thu hồi quyền", "user_id": body.user_id, "product_id": body.product_id}


# ---------- Devices ----------
@router.get("/devices")
def list_devices(db: Session = Depends(get_db)):
    rows = db.scalars(select(Device).order_by(Device.id))
    return [
        {
            "id": d.id,
            "user_id": d.user_id,
            "hardware_hash": d.hardware_hash,
            "device_name": d.device_name,
            "status": d.status,
            "first_seen_at": d.first_seen_at,
            "last_seen_at": d.last_seen_at,
        }
        for d in rows
    ]


@router.post("/devices/{device_id}/revoke", status_code=status.HTTP_200_OK)
def revoke_device(device_id: int, request: Request, admin: User = Depends(require_admin),
                  db: Session = Depends(get_db)):
    dev = db.get(Device, device_id)
    if dev is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Không tìm thấy thiết bị")
    dev.status = "revoked"
    db.commit()
    log_event(db, event_type="device_revoke", result="success", user_id=dev.user_id,
              ip_address=_ip(request), message=f"admin {admin.email} thu hoi device {device_id}")
    return {"detail": "Đã thu hồi thiết bị", "device_id": device_id}


# ---------- Audit logs ----------
@router.get("/audit-logs", response_model=list[AuditOut])
def audit_logs(limit: int = 200, db: Session = Depends(get_db)):
    from ..models import AuditLog

    return list(db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)))
