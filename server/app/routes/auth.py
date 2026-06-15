"""Auth: register / login / refresh / logout."""
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user
from ..models import User
from ..schemas import AuthResult, LoginIn, RefreshIn, RegisterIn, TokenPair, UserOut
from ..security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from ..services import ratelimit
from ..services.audit import log_event

router = APIRouter(prefix="/auth", tags=["auth"])


def _tokens(user_id: int) -> TokenPair:
    return TokenPair(
        access_token=create_access_token(user_id),
        refresh_token=create_refresh_token(user_id),
    )


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.post("/register", response_model=AuthResult, status_code=status.HTTP_201_CREATED)
def register(body: RegisterIn, request: Request, db: Session = Depends(get_db)):
    exists = db.scalar(select(User).where(User.email == body.email))
    if exists:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email đã được đăng ký")

    user = User(email=body.email, password_hash=hash_password(body.password), role="user")
    db.add(user)
    db.commit()
    db.refresh(user)

    log_event(db, event_type="register", result="success", user_id=user.id, ip_address=_client_ip(request))
    return AuthResult(user=UserOut.model_validate(user), tokens=_tokens(user.id))


@router.post("/login", response_model=AuthResult)
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    ip = _client_ip(request) or "unknown"
    rl_key = f"login:{ip}"
    locked = ratelimit.seconds_locked(rl_key)
    if locked > 0:
        log_event(db, event_type="login", result="fail", ip_address=ip,
                  message=f"rate limited ({body.email})")
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail=f"Quá nhiều lần đăng nhập sai. Thử lại sau {int(locked) + 1}s.")

    user = db.scalar(select(User).where(User.email == body.email))
    if user is None or not verify_password(body.password, user.password_hash):
        ratelimit.record_failure(rl_key)
        log_event(
            db,
            event_type="login",
            result="fail",
            user_id=user.id if user else None,
            ip_address=ip,
            message=f"login fail cho {body.email}",
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Email hoặc mật khẩu sai")

    ratelimit.reset(rl_key)  # creds đúng -> xóa bộ đếm fail
    if user.status != "active":
        log_event(db, event_type="login", result="fail", user_id=user.id, ip_address=_client_ip(request),
                  message="tài khoản bị khóa")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tài khoản bị khóa")

    log_event(db, event_type="login", result="success", user_id=user.id, ip_address=_client_ip(request))
    return AuthResult(user=UserOut.model_validate(user), tokens=_tokens(user.id))


@router.post("/refresh", response_model=TokenPair)
def refresh(body: RefreshIn, db: Session = Depends(get_db)):
    try:
        user_id = decode_token(body.refresh_token, expected_type="refresh")
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token không hợp lệ hoặc hết hạn")

    user = db.get(User, user_id)
    if user is None or user.status != "active":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Người dùng không hợp lệ")
    return _tokens(user.id)


@router.post("/logout", status_code=status.HTTP_200_OK)
def logout(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # JWT stateless: client tự xóa token. Ghi log để truy vết.
    log_event(db, event_type="logout", result="success", user_id=user.id, ip_address=_client_ip(request))
    return {"detail": "Đã đăng xuất"}
