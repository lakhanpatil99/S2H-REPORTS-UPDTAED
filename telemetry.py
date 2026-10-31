from fastapi import APIRouter, Depends, HTTPException, Request
from app.schemas.telemetry_schema import TelemetrySyncRequest
from app.core.security import verify_device_token
from app.core.audit import audit_logger
from app.services.ingestion_service import process_telemetry
from slowapi import Limiter
def safe_get_remote_address(request) -> str:
    if not request.client or not hasattr(request.client, 'host'):
        return '127.0.0.1'
    return request.client.host

import structlog

router = APIRouter()
logger = structlog.get_logger()

limiter = Limiter(key_func=safe_get_remote_address)


@router.post("/sync", status_code=201)
@limiter.limit("30/minute")  # Rate limit telemetry sync
async def sync_telemetry(
    request: Request,
    payload: TelemetrySyncRequest,
    device_id: str = Depends(verify_device_token)
):
    """
    Synchronize telemetry data from a device.
    
    Accepts batched predictions, decisions, responses, and recoveries
    from the desktop agent for cloud storage.
    
    Rate limited to 30 requests per minute per device.
    """
    try:
        processed = process_telemetry(device_id, payload)
        
        # Audit log successful sync
        audit_logger.log_telemetry_sync(
            device_id=device_id,
            records_processed=processed,
            request=request,
            success=True,
        )
        
        return {
            "status": "success",
            "records_processed": processed,
            "message": "Telemetry ingested successfully"
        }
    except Exception as e:
        # Audit log failed sync
        audit_logger.log_telemetry_sync(
            device_id=device_id,
            records_processed={},
            request=request,
            success=False,
            error=str(e),
        )
        
        logger.exception("Telemetry ingestion failed:", device_id=device_id)
        raise HTTPException(status_code=500, detail="Database transaction failed")
