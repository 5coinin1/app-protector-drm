"""Pydantic schemas (request/response)."""
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


# ---------- Auth ----------
class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class RefreshIn(BaseModel):
    refresh_token: str


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: EmailStr
    role: str
    status: str
    created_at: datetime


class AuthResult(BaseModel):
    user: UserOut
    tokens: TokenPair


# ---------- Products ----------
class ProductIn(BaseModel):
    product_id: str = Field(min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9_\-]+$")
    name: str
    version: str = "1.0.0"


class ProductOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    product_id: str
    name: str
    version: str
    status: str
    created_at: datetime


# ---------- Library / Entitlements ----------
class LibraryItem(BaseModel):
    product_id: str
    name: str
    version: str
    status: str
    granted_at: datetime
    expires_at: datetime | None = None


class GrantIn(BaseModel):
    user_id: int
    product_id: str


# ---------- Admin: users ----------
class AdminUserIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    role: str = Field(default="user", pattern=r"^(user|admin)$")


# ---------- Runtime (launcher/client) ----------
class IssueTokenIn(BaseModel):
    product_id: str
    hardware_hash: str = Field(min_length=4, max_length=128)
    device_name: str = ""


class SetKeyIn(BaseModel):
    payload_key_b64: str = Field(min_length=10, max_length=128)


# ---------- Audit ----------
class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    user_id: int | None
    product_id: str | None
    event_type: str
    result: str
    ip_address: str | None
    message: str
    created_at: datetime
