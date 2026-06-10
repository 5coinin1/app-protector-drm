"""Admin Dashboard (giao diện web, server-rendered Jinja2).

Xác thực bằng cookie (access token JWT) cho phù hợp trình duyệt — khác với API /admin/* dùng Bearer.
Chỉ user role=admin mới vào được.
"""
from pathlib import Path

import jwt
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AuditLog, Device, Entitlement, Product, ProductKey, User
from ..security import create_access_token, decode_token, hash_password, verify_password
from ..services.audit import log_event

router = APIRouter(prefix="/dashboard", tags=["dashboard"], include_in_schema=False)
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))

COOKIE = "dash_token"


def current_admin(request: Request, db: Session) -> User | None:
    tok = request.cookies.get(COOKIE)
    if not tok:
        return None
    try:
        uid = decode_token(tok, "access")
    except jwt.PyJWTError:
        return None
    u = db.get(User, uid)
    if u and u.role == "admin" and u.status == "active":
        return u
    return None


def _redirect_login():
    return RedirectResponse("/dashboard/login", status_code=303)


# ---------- Auth ----------
@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"request": request, "error": None})


@router.post("/login")
def login_submit(request: Request, email: str = Form(...), password: str = Form(...),
                 db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == email))
    if user is None or not verify_password(password, user.password_hash) or user.role != "admin":
        log_event(db, event_type="login", result="fail",
                  user_id=user.id if user else None, message="dashboard login fail")
        return templates.TemplateResponse(
            request, "login.html", {"error": "Sai thông tin hoặc không phải admin"},
            status_code=401)
    log_event(db, event_type="login", result="success", user_id=user.id, message="dashboard")
    resp = RedirectResponse("/dashboard", status_code=303)
    resp.set_cookie(COOKIE, create_access_token(user.id), httponly=True, samesite="lax")
    return resp


@router.get("/logout")
def logout():
    resp = _redirect_login()
    resp.delete_cookie(COOKIE)
    return resp


# ---------- Overview ----------
@router.get("", response_class=HTMLResponse)
def index(request: Request, db: Session = Depends(get_db)):
    admin = current_admin(request, db)
    if not admin:
        return _redirect_login()
    stats = {
        "users": db.scalar(select(func.count()).select_from(User)),
        "products": db.scalar(select(func.count()).select_from(Product)),
        "entitlements": db.scalar(select(func.count()).select_from(Entitlement).where(Entitlement.status == "active")),
        "devices": db.scalar(select(func.count()).select_from(Device).where(Device.status == "active")),
    }
    recent = list(db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(8)))
    return templates.TemplateResponse(request, "index.html",
                                      {"request": request, "admin": admin, "stats": stats, "recent": recent})


# ---------- Products ----------
@router.get("/products", response_class=HTMLResponse)
def products_page(request: Request, db: Session = Depends(get_db), msg: str = "", error: str = ""):
    admin = current_admin(request, db)
    if not admin:
        return _redirect_login()
    products = list(db.scalars(select(Product).order_by(Product.id)))
    keyed = {k.product_id for k in db.scalars(select(ProductKey).where(ProductKey.status == "active"))}
    return templates.TemplateResponse(request, "products.html",
                                      {"request": request, "admin": admin, "products": products,
                                       "keyed": keyed, "msg": msg, "error": error})


@router.post("/products")
def create_product(request: Request, product_id: str = Form(...), name: str = Form(...),
                   version: str = Form("1.0.0"), db: Session = Depends(get_db)):
    if not current_admin(request, db):
        return _redirect_login()
    if db.scalar(select(Product).where(Product.product_id == product_id)):
        return RedirectResponse("/dashboard/products?error=product_id đã tồn tại", status_code=303)
    db.add(Product(product_id=product_id, name=name, version=version))
    db.commit()
    return RedirectResponse("/dashboard/products?msg=Đã tạo product", status_code=303)


@router.post("/products/{product_id}/key")
def set_key(request: Request, product_id: str, payload_key_b64: str = Form(...),
            db: Session = Depends(get_db)):
    if not current_admin(request, db):
        return _redirect_login()
    existing = db.scalar(select(ProductKey).where(ProductKey.product_id == product_id,
                                                  ProductKey.status == "active"))
    if existing:
        existing.encrypted_payload_key = payload_key_b64.strip()
    else:
        db.add(ProductKey(product_id=product_id, encrypted_payload_key=payload_key_b64.strip()))
    db.commit()
    return RedirectResponse("/dashboard/products?msg=Đã đăng ký payload key", status_code=303)


# ---------- Users ----------
@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request, db: Session = Depends(get_db), msg: str = "", error: str = ""):
    admin = current_admin(request, db)
    if not admin:
        return _redirect_login()
    users = list(db.scalars(select(User).order_by(User.id)))
    products = list(db.scalars(select(Product).order_by(Product.product_id)))
    owned: dict[int, list[str]] = {}
    for ent in db.scalars(select(Entitlement).where(Entitlement.status == "active")):
        owned.setdefault(ent.user_id, []).append(ent.product_id)
    return templates.TemplateResponse(request, "users.html",
                                      {"request": request, "admin": admin, "users": users,
                                       "products": products, "owned": owned, "msg": msg, "error": error})


@router.post("/users")
def create_user(request: Request, email: str = Form(...), password: str = Form(...),
                role: str = Form("user"), db: Session = Depends(get_db)):
    if not current_admin(request, db):
        return _redirect_login()
    if db.scalar(select(User).where(User.email == email)):
        return RedirectResponse("/dashboard/users?error=Email đã tồn tại", status_code=303)
    db.add(User(email=email, password_hash=hash_password(password), role=role))
    db.commit()
    return RedirectResponse("/dashboard/users?msg=Đã tạo user", status_code=303)


@router.post("/users/{user_id}/grant")
def grant(request: Request, user_id: int, product_id: str = Form(...), db: Session = Depends(get_db)):
    admin = current_admin(request, db)
    if not admin:
        return _redirect_login()
    ent = db.scalar(select(Entitlement).where(Entitlement.user_id == user_id,
                                              Entitlement.product_id == product_id))
    if ent:
        ent.status = "active"
    else:
        db.add(Entitlement(user_id=user_id, product_id=product_id, status="active"))
    db.commit()
    log_event(db, event_type="grant", result="success", user_id=user_id, product_id=product_id,
              message=f"dashboard {admin.email}")
    return RedirectResponse("/dashboard/users?msg=Đã cấp quyền", status_code=303)


@router.post("/users/{user_id}/revoke")
def revoke(request: Request, user_id: int, product_id: str = Form(...), db: Session = Depends(get_db)):
    admin = current_admin(request, db)
    if not admin:
        return _redirect_login()
    ent = db.scalar(select(Entitlement).where(Entitlement.user_id == user_id,
                                              Entitlement.product_id == product_id))
    if ent:
        ent.status = "revoked"
        db.commit()
        log_event(db, event_type="revoke", result="success", user_id=user_id, product_id=product_id,
                  message=f"dashboard {admin.email}")
    return RedirectResponse("/dashboard/users?msg=Đã thu hồi quyền", status_code=303)


# ---------- Devices ----------
@router.get("/devices", response_class=HTMLResponse)
def devices_page(request: Request, db: Session = Depends(get_db), msg: str = ""):
    admin = current_admin(request, db)
    if not admin:
        return _redirect_login()
    rows = db.execute(select(Device, User.email).join(User, User.id == Device.user_id)
                      .order_by(Device.id)).all()
    return templates.TemplateResponse(request, "devices.html",
                                      {"request": request, "admin": admin, "rows": rows, "msg": msg})


@router.post("/devices/{device_id}/revoke")
def revoke_device(request: Request, device_id: int, db: Session = Depends(get_db)):
    admin = current_admin(request, db)
    if not admin:
        return _redirect_login()
    dev = db.get(Device, device_id)
    if dev:
        dev.status = "revoked"
        db.commit()
        log_event(db, event_type="device_revoke", result="success", user_id=dev.user_id,
                  message=f"dashboard {admin.email} device {device_id}")
    return RedirectResponse("/dashboard/devices?msg=Đã thu hồi thiết bị", status_code=303)


# ---------- Audit ----------
@router.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request, db: Session = Depends(get_db)):
    admin = current_admin(request, db)
    if not admin:
        return _redirect_login()
    logs = list(db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(200)))
    emails = {u.id: u.email for u in db.scalars(select(User))}
    return templates.TemplateResponse(request, "audit.html",
                                      {"request": request, "admin": admin, "logs": logs, "emails": emails})
