from fastapi import APIRouter, Depends, Request, HTTPException
from app.schemas.auth_schema import EnrollmentRequest, AuthResponse, TokenRefreshResponse
from app.core.security import create_device_token, create_token_pair, verify_device_token, verify_refresh_token
from app.core.config import settings
from app.core.audit import audit_logger, AuditEventType
from app.services.auth_service import process_enrollment, generate_enrollment_token
from app.db import supabase_client
from slowapi import Limiter
def safe_get_remote_address(request) -> str:
    if not request.client or not hasattr(request.client, 'host'):
        return '127.0.0.1'
    return request.client.host

import structlog

logger = structlog.get_logger()

router = APIRouter()

# Rate limiter for auth endpoints (more restrictive)
limiter = Limiter(key_func=safe_get_remote_address)


@router.post("/generate-token")
@limiter.limit("10/minute")
async def generate_token(request: Request):
    """
    Generate a short-lived enrollment token for deploying Desktop Agents.
    
    The caller must provide a valid Supabase access token (dashboard login JWT)
    in the Authorization header. The admin's user_id is embedded in the
    enrollment token so that enrolled devices are automatically owned by them.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization header")
    
    sb_token = auth_header.split("Bearer ", 1)[1]
    
    try:
        # Verify the Supabase JWT and extract the dashboard user
        user_resp = supabase_client.supabase.auth.get_user(sb_token)
        if not user_resp or not user_resp.user:
            raise HTTPException(status_code=401, detail="Invalid Supabase session")
        user_id = str(user_resp.user.id)
    except HTTPException:
        raise
    except Exception as e:
        logger.warning("generate_token_auth_failed", error=str(e))
        raise HTTPException(status_code=401, detail="Failed to verify dashboard session")
    
    enrollment_token = generate_enrollment_token(user_id)
    return {"enrollment_token": enrollment_token, "expires_in_hours": 24}


@router.post("/enroll", response_model=AuthResponse)
@limiter.limit("5/minute")  # Strict rate limit for enrollment
def enroll_device(request: Request, req: EnrollmentRequest):
    """
    Enroll a new device and obtain authentication tokens.
    
    Rate limited to 5 requests per minute per IP.
    """
    try:
        process_enrollment(req)
        tokens = create_token_pair(str(req.device_id))
        
        # Audit log successful enrollment
        audit_logger.log_auth_event(
            event_type=AuditEventType.AUTH_ENROLL,
            device_id=str(req.device_id),
            request=request,
            success=True,
        )
        
        return AuthResponse(
            device_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            expires_in=tokens["expires_in"],
        )
    except Exception as e:
        # Audit log failed enrollment
        audit_logger.log_auth_event(
            event_type=AuditEventType.AUTH_ENROLL_FAILED,
            device_id=str(req.device_id),
            request=request,
            success=False,
            error=str(e),
        )
        raise


@router.post("/rotate", response_model=AuthResponse)
@limiter.limit("10/minute")  # Rate limit token rotation
def rotate_token(request: Request, device_id: str = Depends(verify_device_token)):
    """
    Rotate the access token using the current valid token.
    
    This endpoint allows obtaining a new access token without
    using the refresh token. Use this for proactive rotation.
    """
    tokens = create_token_pair(device_id)
    
    # Audit log token rotation
    audit_logger.log_auth_event(
        event_type=AuditEventType.AUTH_TOKEN_ROTATE,
        device_id=device_id,
        request=request,
        success=True,
    )
    
    return AuthResponse(
        device_token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        expires_in=tokens["expires_in"],
    )


@router.post("/refresh", response_model=TokenRefreshResponse)
@limiter.limit("10/minute")
def refresh_token(request: Request, device_id: str = Depends(verify_refresh_token)):
    """
    Obtain a new access token using a valid refresh token.
    
    Use this endpoint when the access token has expired but
    the refresh token is still valid.
    """
    access_token = create_device_token(device_id)
    
    # Audit log token refresh
    audit_logger.log_auth_event(
        event_type=AuditEventType.AUTH_TOKEN_ROTATE,
        device_id=device_id,
        request=request,
        success=True,
    )
    
    return TokenRefreshResponse(
        access_token=access_token,
        token_type="Bearer",
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
    )
