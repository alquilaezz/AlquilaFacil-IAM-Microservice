from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from jose import JWTError

from .database import SessionLocal
from .security import decode_token
from . import models

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str, db: Session) -> models.User:
    try:
        payload = decode_token(token)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")

    user_id = int(payload.get("sub"))
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

def get_admin_user(token: str, db: Session):
    user = get_current_user(token, db)
    if user.role.role != "ADMIN":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    return user
