from datetime import datetime, timedelta
from typing import Optional, Union, Callable
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from database import get_db
from models import User
from schemas import TokenData

# Security configuration
SECRET_KEY = "YOUR_SECRET_KEY"  # In production, use a secure random key from environment variables
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

# Verify password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Hash password
def get_password_hash(password):
    return pwd_context.hash(password)

# Authenticate user
def authenticate_user(db: Session, username: str, password: str):
    # Temporarily remove the deleted_at filter
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return False
    if not verify_password(password, user.password_hash):
        return False
    return user

# Create access token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Get current user from token
async def get_current_user_from_token(token: str, db: Session):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == token_data.username, User.deleted_at == None).first()
    if user is None:
        raise credentials_exception
    return user

# Conditional authentication dependency
async def conditional_auth(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    # Always require authentication for non-GET methods
    if request.method != "GET":
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return await get_current_user_from_token(token, db)
    
    # For GET requests, check if it's a user-related endpoint
    path = request.url.path
    user_related_paths = ["/users/", "/users/me/"]
    
    # Check if the path starts with any of the user-related paths
    requires_auth = any(path.startswith(user_path) for user_path in user_related_paths)
    
    if requires_auth:
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required for user data",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return await get_current_user_from_token(token, db)
    
    # For non-user GET requests, authentication is optional
    if token:
        try:
            return await get_current_user_from_token(token, db)
        except HTTPException:
            # If token is invalid, continue without authentication
            return None
    return None

# Get current active user (modified to use conditional auth)
async def get_current_active_user(current_user: User = Depends(conditional_auth)):
    if current_user is None:
        return None
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# Check if user is superadmin
async def get_current_superadmin(current_user: User = Depends(get_current_active_user)):
    if current_user is None or not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user

# Check if user has access to a region
def check_region_access(user: User, region_id: int):
    # If no user (unauthenticated GET request), deny access to restricted operations
    if user is None:
        return False
    
    # Superadmins have access to all regions
    if user.is_superadmin:
        return True
    
    # Regular admins only have access to their assigned regions
    for region in user.regions:
        if region.id == region_id and region.deleted_at is None:
            return True
    
    return False

