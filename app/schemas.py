from pydantic_settings import BaseModel, EmailStr
from typing import Optional

class UserBase(BaseModel):
    username: str
    email: EmailStr

class UserCreate(UserBase):
    password: str

class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None

class UserOut(UserBase):
    id: int
    role: str

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    requires_mfa: bool
    access_token: Optional[str] = None
    temp_token: Optional[str] = None

class VerifyMfaRequest(BaseModel):
    temp_token: str
    code: str

class EnableMfaResponse(BaseModel):
    secret: str
    otpauth_url: str
