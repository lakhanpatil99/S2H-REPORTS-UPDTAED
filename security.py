import jwt
import datetime
import secrets
import hashlib
from typing import Optional, Tuple
from fastapi import Depends, HTTPException, Security, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.core.config import settings
import structlog

logger = structlog.get_logger()

security = HTTPBearer()


class TokenType:
    ACCESS = "access"
    REFRESH = "refresh"


def create_device_token(device_id: str, token_type: str = TokenType.ACCESS) -> str:
    """
    Create a JWT token for device authentication.
    
    Args:
        device_id: Unique device identifier
        token_type: Either 'access' (short-lived) or 'refresh' (long-lived)
    
    Returns:
        Encoded JWT token string
    """
    now = datetime.datetime.utcnow()
    
    if token_type == TokenType.ACCESS:
        exp_delta = datetime.timedelta(days=settings.JWT_ACCESS_TOKEN_EXPIRE_DAYS)
    else:
        exp_delta = datetime.timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    
    payload = {
        "sub": device_id,
        "type": token_type,
        "exp": now + exp_delta,
        "iat": now,
        "jti": secrets.token_urlsafe(16),  # Unique token ID for revocation support
    }
    
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_token_pair(device_id: str) -> dict:
    """
    Create both access and refresh tokens for a device.
    
    Returns:
        Dict with access_token, refresh_token, and expiration info
    """
    return {
        "access_token": create_device_token(device_id, TokenType.ACCESS),
        "refresh_token": create_device_token(device_id, TokenType.REFRESH),
        "token_type": "Bearer",
        "expires_in": settings.JWT_ACCESS_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,  # seconds
        "refresh_expires_in": settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
    }


def verify_device_token(
    credentials: HTTPAuthorizationCredentials = Security(security),
    expected_type: str = TokenType.ACCESS
) -> str:
    """
    Verify and decode a JWT token.
    
    Args:
        credentials: HTTP Bearer credentials
        expected_type: Expected token type (access or refresh)
    
    Returns:
        Device ID from the token
        
    Raises:
        HTTPException: If token is invalid, expired, or wrong type
    """
    token = credentials.credentials
    
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )
        
        # Verify token type
        token_type = payload.get("type", TokenType.ACCESS)
        if token_type != expected_type:
            logger.warning(
                "token_type_mismatch",
                expected=expected_type,
                actual=token_type,
                device_id=payload.get("sub")
            )
            raise HTTPException(
                status_code=401,
                detail=f"Invalid token type. Expected {expected_type} token."
            )
        
        device_id = payload.get("sub")
        if not device_id:
            raise HTTPException(status_code=401, detail="Invalid token payload")
            
        # VERIFY DEVICE STILL EXISTS IN DATABASE
        # Prevents foreign key violations if device was deleted or DB wiped
        from app.db import supabase_client
        try:
            res = supabase_client.supabase.table("devices").select("id").eq("id", device_id).execute()
            if not hasattr(res, 'data') or not res.data:
                logger.warning("device_not_found_in_db", device_id=device_id)
                raise HTTPException(status_code=401, detail="Device has been deleted or un-enrolled")
        except HTTPException:
            raise
        except Exception as e:
            logger.error("db_check_failed", error=str(e))
            raise HTTPException(status_code=500, detail="Internal server error verifying device")
            
        return device_id
        
    except jwt.ExpiredSignatureError:
        logger.info("token_expired", token_hash=hashlib.sha256(token.encode()).hexdigest()[:16])
        raise HTTPException(
            status_code=401,
            detail="Token has expired. Please refresh your token.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except jwt.InvalidTokenError as e:
        logger.warning("token_invalid", error=str(e))
        raise HTTPException(
            status_code=401,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"}
        )


def verify_refresh_token(
    credentials: HTTPAuthorizationCredentials = Security(security)
) -> str:
    """Verify a refresh token specifically."""
    return verify_device_token(credentials, expected_type=TokenType.REFRESH)


def get_token_expiry(token: str) -> Optional[datetime.datetime]:
    """
    Get the expiration time of a token without full verification.
    Useful for clients to know when to refresh.
    """
    try:
        # Decode without verification to get expiry
        payload = jwt.decode(
            token,
            options={"verify_signature": False, "verify_exp": False}
        )
        exp = payload.get("exp")
        if exp:
            return datetime.datetime.utcfromtimestamp(exp)
    except jwt.InvalidTokenError:
        pass
    return None


def hash_token_for_logging(token: str) -> str:
    """Create a safe hash of a token for logging purposes."""
    return hashlib.sha256(token.encode()).hexdigest()[:16]
