from fastapi import APIRouter, Depends, Request
from app.schemas.device_schema import HeartbeatRequest
from app.core.security import verify_device_token
from app.core.audit import audit_logger, AuditEventType
from app.db import supabase_client
from slowapi import Limiter
def safe_get_remote_address(request) -> str:
    if not request.client or not hasattr(request.client, 'host'):
        return '127.0.0.1'
    return request.client.host

import uuid
import structlog

router = APIRouter()
logger = structlog.get_logger()

limiter = Limiter(key_func=safe_get_remote_address)


@router.post("/heartbeat")
@limiter.limit("60/minute")  # Allow frequent heartbeats
def heartbeat(
    request: Request,
    req: HeartbeatRequest,
    device_id: str = Depends(verify_device_token)
):
    """
    Receive device heartbeat with health metrics.
    
    Updates device status and stores health telemetry.
    Rate limited to 60 requests per minute per device.
    """
    try:
        supabase_client.supabase.table("devices").update({
            "last_sync": req.timestamp.isoformat(),
            "status": "online",
            "agent_version": req.agent_version
        }).eq("id", device_id).execute()
        
        supabase_client.supabase.table("device_health").insert({
            "id": str(uuid.uuid4()),
            "device_id": device_id,
            "cpu_usage_pct": req.cpu_usage_pct,
            "memory_usage_pct": req.memory_usage_pct,
            "disk_usage_pct": req.disk_usage_pct,
            "active_monitors": req.active_monitors,
            "created_at": req.timestamp.isoformat()
        }).execute()
        
        # Audit log heartbeat
        audit_logger.log(
            event_type=AuditEventType.DEVICE_HEARTBEAT,
            device_id=device_id,
            request=request,
            details={
                "cpu_usage_pct": req.cpu_usage_pct,
                "memory_usage_pct": req.memory_usage_pct,
                "active_monitors": req.active_monitors,
            }
        )
        
        return {"status": "acknowledged"}
    except Exception as e:
        logger.error("heartbeat_error", error=str(e), device_id=device_id)
        return {"status": "error", "detail": "Failed to update heartbeat"}
