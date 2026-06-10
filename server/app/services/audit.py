"""Ghi audit log — gọi ở mọi sự kiện nhạy cảm (login, grant, revoke, run app...)."""
from sqlalchemy.orm import Session

from ..models import AuditLog


def log_event(
    db: Session,
    *,
    event_type: str,
    result: str,
    user_id: int | None = None,
    product_id: str | None = None,
    ip_address: str | None = None,
    message: str = "",
) -> AuditLog:
    entry = AuditLog(
        user_id=user_id,
        product_id=product_id,
        event_type=event_type,
        result=result,
        ip_address=ip_address,
        message=message,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry
