"""ORM models — DB schema theo đề bài §6.

Giai đoạn 1 dùng: users, products, entitlements, audit_logs.
devices / product_devices đã định nghĩa sẵn để giai đoạn 5 (hardware binding) dùng tiếp.
"""
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="user")  # "user" | "admin"
    status: Mapped[str] = mapped_column(String(20), default="active")  # "active" | "disabled"
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    entitlements: Mapped[list["Entitlement"]] = relationship(back_populates="user")
    devices: Mapped[list["Device"]] = relationship(back_populates="user")


class Product(Base):
    __tablename__ = "products"

    id: Mapped[int] = mapped_column(primary_key=True)
    product_id: Mapped[str] = mapped_column(String(100), unique=True, index=True)  # slug, vd "demo_app"
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(50), default="1.0.0")
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Entitlement(Base):
    __tablename__ = "entitlements"
    __table_args__ = (UniqueConstraint("user_id", "product_id", name="uq_user_product"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    product_id: Mapped[str] = mapped_column(String(100), index=True)  # tham chiếu products.product_id
    status: Mapped[str] = mapped_column(String(20), default="active")  # "active" | "revoked"
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped["User"] = relationship(back_populates="entitlements")


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("user_id", "hardware_hash", name="uq_user_device"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    hardware_hash: Mapped[str] = mapped_column(String(128), index=True)
    device_name: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(20), default="active")  # "active" | "revoked"
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    user: Mapped["User"] = relationship(back_populates="devices")


class ProductKey(Base):
    """Payload key của product, do developer đăng ký lên server (server-side key).

    Lưu ý: trong môi trường thật, encrypted_payload_key nên được mã hóa khi lưu (KMS/DPAPI).
    Bài này lưu base64 trực tiếp cho đơn giản và ghi chú rõ.
    """
    __tablename__ = "product_keys"

    id: Mapped[int] = mapped_column(primary_key=True)
    product_id: Mapped[str] = mapped_column(String(100), index=True)
    key_version: Mapped[int] = mapped_column(default=1)
    encrypted_payload_key: Mapped[str] = mapped_column(String(128))  # base64 32 byte AES key
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    product_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    event_type: Mapped[str] = mapped_column(String(50))  # vd "login", "run_app", "grant"
    result: Mapped[str] = mapped_column(String(20))  # "success" | "fail"
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    message: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
