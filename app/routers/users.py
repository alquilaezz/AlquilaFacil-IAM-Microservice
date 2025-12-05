from fastapi import APIRouter, Depends, HTTPException, status, Header
from sqlalchemy.orm import Session

from .. import models, schemas
from ..deps import get_db, get_admin_user, get_current_user
from ..security import decode_token

router = APIRouter(prefix="/api/v1/users", tags=["Users"])

def _extract_token(authorization: str) -> str:
    try:
        scheme, token = authorization.split()
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid auth header")
    return token

@router.get("/", response_model=list[schemas.UserOut])
def list_users(
    authorization: str = Header(...),
    db: Session = Depends(get_db),
):
    token = _extract_token(authorization)
    admin = get_admin_user(token, db)
    users = db.query(models.User).all()
    return [
        schemas.UserOut(id=u.id, username=u.username, email=u.email, role=u.role.role)
        for u in users
    ]

@router.get("/{user_id}", response_model=schemas.UserOut)
def get_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return schemas.UserOut(id=user.id, username=user.username, email=user.email, role=user.role.role)

@router.put("/{user_id}", response_model=schemas.UserOut)
def update_user(
    user_id: int,
    payload: schemas.UserUpdate,
    authorization: str = Header(...),
    db: Session = Depends(get_db),
):
    token = _extract_token(authorization)
    data = decode_token(token)
    requester_id = int(data.get("sub"))
    # solo el propio usuario o ADMIN
    requester = db.query(models.User).filter(models.User.id == requester_id).first()
    if not requester:
        raise HTTPException(status_code=401, detail="Invalid token")

    if requester.id != user_id and requester.role.role != "ADMIN":
        raise HTTPException(status_code=403, detail="Not enough permissions")

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if payload.username is not None:
        user.username = payload.username
    if payload.email is not None:
        user.email = payload.email

    db.add(user)
    db.commit()
    db.refresh(user)

    return schemas.UserOut(id=user.id, username=user.username, email=user.email, role=user.role.role)

@router.get("/get-username/{user_id}")
def get_username(user_id: int, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"username": user.username}
