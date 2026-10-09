import logging
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.services.security.auth import (
    create_access_token,
    hash_password,
    verify_password,
)
from app.services.security.rbac import get_current_user
from app.services.security.rate_limiter import rate_limit

logger = logging.getLogger("socialshield.security")
router = APIRouter(prefix="/api/auth", tags=["Authentication"])


class UserRegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: str = Field(min_length=5, max_length=255, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: str = Field(min_length=8, max_length=128)
    role: str = Field(default="analyst")


class UserLoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str


class UserProfileResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool


@router.post("/register", response_model=UserProfileResponse)
def register(
    data: UserRegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
    _limiter: None = Depends(rate_limit(max_calls=15, window_seconds=60)),
):
    client_ip = request.client.host if request.client else "unknown"

    # Enforce allowed roles on registration (only admin or analyst/viewer)
    role = data.role.lower()
    if role not in ["admin", "analyst", "viewer"]:
        role = "analyst"

    existing_user = db.query(User).filter(
        (User.username == data.username) | (User.email == data.email)
    ).first()

    if existing_user:
        logger.warning(f"[SECURITY_AUDIT] Registration failed (conflict) for {data.username} from {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already registered.",
        )

    new_user = User(
        username=data.username,
        email=data.email,
        hashed_password=hash_password(data.password),
        role=role,
        is_active=True,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    logger.info(f"[SECURITY_AUDIT] User registered: {new_user.username} (role: {new_user.role}) from {client_ip}")

    return UserProfileResponse(
        id=new_user.id,
        username=new_user.username,
        email=new_user.email,
        role=new_user.role,
        is_active=new_user.is_active,
    )


@router.post("/login", response_model=TokenResponse)
def login(
    data: UserLoginRequest,
    request: Request,
    db: Session = Depends(get_db),
    _limiter: None = Depends(rate_limit(max_calls=20, window_seconds=60)),
):
    client_ip = request.client.host if request.client else "unknown"

    user = db.query(User).filter(User.username == data.username).first()

    if not user or not verify_password(data.password, user.hashed_password):
        logger.warning(f"[SECURITY_AUDIT] Failed login attempt for '{data.username}' from {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        logger.warning(f"[SECURITY_AUDIT] Inactive user login attempt for '{data.username}' from {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive.",
        )

    access_token = create_access_token(
        data={"sub": user.username, "role": user.role},
        expires_delta=timedelta(hours=24),
    )

    logger.info(f"[SECURITY_AUDIT] Successful login for '{user.username}' (role: {user.role}) from {client_ip}")

    return TokenResponse(
        access_token=access_token,
        username=user.username,
        role=user.role,
    )


@router.get("/me", response_model=UserProfileResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return UserProfileResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        role=current_user.role,
        is_active=current_user.is_active,
    )
