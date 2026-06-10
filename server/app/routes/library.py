"""Thư viện của người dùng: các app đã sở hữu (entitlement active)."""
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user
from ..models import Entitlement, Product, User
from ..schemas import LibraryItem

router = APIRouter(tags=["library"])


@router.get("/me/library", response_model=list[LibraryItem])
def my_library(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.execute(
        select(Entitlement, Product)
        .join(Product, Product.product_id == Entitlement.product_id)
        .where(Entitlement.user_id == user.id, Entitlement.status == "active")
    ).all()

    return [
        LibraryItem(
            product_id=ent.product_id,
            name=prod.name,
            version=prod.version,
            status=ent.status,
            granted_at=ent.granted_at,
            expires_at=ent.expires_at,
        )
        for ent, prod in rows
    ]
