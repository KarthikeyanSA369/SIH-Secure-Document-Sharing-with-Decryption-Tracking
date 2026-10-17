import os
import hashlib
import hmac
import datetime
from typing import Optional
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from config import settings
from database import get_db
from models import User

security = HTTPBearer()

def hash_password(password: str) -> str:
    """Hash password using PBKDF2-HMAC-SHA256 with a unique 16-byte salt."""
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    return salt.hex() + ":" + key.hex()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against stored salt:hash."""
    try:
        parts = hashed_password.split(":")
        if len(parts) != 2:
            return False
        salt = bytes.fromhex(parts[0])
        expected_key = bytes.fromhex(parts[1])
        actual_key = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, 100000)
        return hmac.compare_digest(actual_key, expected_key)
    except Exception:
        return False

def create_access_token(user: User) -> str:
    """Create a signed JWT access token."""
    now = datetime.datetime.utcnow()
    expire = now + datetime.timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": user.id,
        "username": user.username,
        "role": user.role,
        "name": user.name,
        "exp": expire,
        "iat": now
    }
    encoded_jwt = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """Validate bearer token and retrieve current user."""
    token = credentials.credentials
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except Exception:
        raise credentials_exception

    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception
    return user

def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Enforce ADMIN role."""
    if current_user.role != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: Admin privilege required"
        )
    return current_user

def require_recipient(current_user: User = Depends(get_current_user)) -> User:
    """Enforce RECIPIENT role."""
    if current_user.role != "RECIPIENT":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: Recipient privilege required"
        )
    return current_user

def require_investigator(current_user: User = Depends(get_current_user)) -> User:
    """Enforce INVESTIGATOR role."""
    if current_user.role != "INVESTIGATOR":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: Investigator privilege required"
        )
    return current_user
