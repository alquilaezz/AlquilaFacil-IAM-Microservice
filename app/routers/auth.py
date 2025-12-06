from fastapi import APIRouter, Depends, HTTPException, status, Header
from sqlalchemy.orm import Session

from .. import models, schemas
from ..deps import get_db
from ..security import (
    hash_password,
    verify_password,
    create_access_token,
    create_mfa_temp_token,
    generate_mfa_secret,
    get_totp,
    verify_totp,
    decode_token,
)
import pyotp

router = APIRouter(prefix="/api/v1/authentication", tags=["Authentication"])

@router.post("/sign-up", response_model=schemas.UserOut, status_code=201)
def sign_up(payload: schemas.UserCreate, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if db.query(models.User).filter(models.User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")

    # rol por defecto USER (id=1 por ejemplo)
    role = db.query(models.UserRole).filter(models.UserRole.role == "USER").first()
    if not role:
        role = models.UserRole(role="USER")
        db.add(role)
        db.flush()

    user = models.User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role_id=role.id,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    response = {
        "message": "Usuario registrado"
    }

    return response

@router.post("/sign-in", response_model=schemas.LoginResponse)
def sign_in(payload: schemas.LoginRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    role = user.role.role

    # Si no tiene MFA → devolvemos access_token directo
    if not user.mfa_key:
        token = create_access_token(user.id, role)
        return schemas.LoginResponse(requires_mfa=False, access_token=token)

    # Tiene MFA → devolvemos temp_token
    temp_token = create_mfa_temp_token(user.id)
    return schemas.LoginResponse(requires_mfa=True, temp_token=temp_token)

@router.post("/verify-mfa", response_model=schemas.Token)
def verify_mfa(payload: schemas.VerifyMfaRequest, db: Session = Depends(get_db)):
    # temp_token solo sirve para identificar usuario
    data = decode_token(payload.temp_token)
    if data.get("type") != "mfa_pending":
        raise HTTPException(status_code=400, detail="Invalid temp token")
    user_id = int(data.get("sub"))

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user or not user.mfa_key:
        raise HTTPException(status_code=400, detail="User has no MFA enabled")

    # primero probamos TOTP
    if verify_totp(user.mfa_key, payload.code):
        pass
    else:
        # opcional: verificar recovery codes
        rec = (
            db.query(models.MfaCode)
            .filter(models.MfaCode.user_id == user.id, models.MfaCode.code == payload.code)
            .first()
        )
        if not rec:
            raise HTTPException(status_code=401, detail="Invalid MFA code")
        db.delete(rec)
        db.commit()

    access_token = create_access_token(user.id, user.role.role)
    return schemas.Token(access_token=access_token)

@router.post("/mfa/enable", response_model=schemas.EnableMfaResponse)
def enable_mfa(authorization: str = Header(...), db: Session = Depends(get_db)):
    # Authorization: Bearer <token>
    try:
        scheme, token = authorization.split()
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid auth header")

    data = decode_token(token)
    if data.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")

    user_id = int(data.get("sub"))
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    secret = generate_mfa_secret()
    user.mfa_key = secret
    db.add(user)
    db.commit()
    db.refresh(user)

    totp = get_totp(secret)
    otpauth_url = totp.provisioning_uri(name=user.email, issuer_name="YourAppName")

    return schemas.EnableMfaResponse(secret=secret, otpauth_url=otpauth_url)
