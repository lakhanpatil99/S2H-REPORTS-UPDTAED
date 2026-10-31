"""
Audit Logging Service for RansomShield Backend.

Provides structured audit logging for security-relevant events including:
- Authentication events (login, logout, token refresh)
- Device enrollment and management
- Telemetry synchronization
- Administrative actions
"""

import datetime
import uuid
from typing import Optional, Dict, Any
from enum import Enum
from fastapi import Request
import structlog

logger = structlog.get_logger()


class AuditEventType(str, Enum):
    """Types of audit events."""
    # Authentication events
    AUTH_ENROLL = "auth.enroll"
    AUTH_ENROLL_FAILED = "auth.enroll.failed"
    AUTH_TOKEN_ROTATE = "auth.token.rotate"
    AUTH_TOKEN_EXPIRED = "auth.token.expired"
    AUTH_TOKEN_INVALID = "auth.token.invalid"
    
    # Device events
    DEVICE_HEARTBEAT = "device.heartbeat"
    DEVICE_STATUS_CHANGE = "device.status.change"
    DEVICE_CONFIG_UPDATE = "device.config.update"
    
    # Telemetry events
    TELEMETRY_SYNC = "telemetry.sync"
    TELEMETRY_SYNC_FAILED = "telemetry.sync.failed"
    
    # Security events
    SECURITY_THREAT_DETECTED = "security.threat.detected"
    SECURITY_RESPONSE_EXECUTED = "security.response.executed"
    SECURITY_RECOVERY_COMPLETED = "security.recovery.completed"
    
    # Admin events
    ADMIN_CONFIG_CHANGE = "admin.config.change"
    ADMIN_USER_ACTION = "admin.user.action"
    
    # Rate limiting
    RATE_LIMIT_EXCEEDED = "rate_limit.exceeded"


class AuditSeverity(str, Enum):
    """Severity levels for audit events."""
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class AuditLogger:
    """
    Centralized audit logging service.
    
    All security-relevant events should be logged through this service
    to ensure consistent formatting and potential database persistence.
    """
    
    def __init__(self):
        self._logger = structlog.get_logger("audit")
    
    def log(
        self,
        event_type: AuditEventType,
        severity: AuditSeverity = AuditSeverity.INFO,
        device_id: Optional[str] = None,
        user_id: Optional[str] = None,
        request: Optional[Request] = None,
        details: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> str:
        """
        Log an audit event.
        
        Args:
            event_type: Type of audit event
            severity: Event severity level
            device_id: Associated device ID if applicable
            user_id: Associated user ID if applicable
            request: FastAPI request object for extracting metadata
            details: Additional event details
            error: Error message if event is an error
            
        Returns:
            Unique audit event ID
        """
        audit_id = str(uuid.uuid4())
        timestamp = datetime.datetime.utcnow().isoformat() + "Z"
        
        # Extract request metadata
        request_metadata = {}
        if request:
            request_metadata = {
                "client_ip": self._get_client_ip(request),
                "user_agent": request.headers.get("user-agent", "unknown"),
                "request_path": str(request.url.path),
                "request_method": request.method,
                "request_id": getattr(request.state, 'request_id', None),
            }
        
        # Build audit record
        audit_record = {
            "audit_id": audit_id,
            "timestamp": timestamp,
            "event_type": event_type.value,
            "severity": severity.value,
            "device_id": device_id,
            "user_id": user_id,
            **request_metadata,
        }
        
        if details:
            audit_record["details"] = details
        if error:
            audit_record["error"] = error
        
        # Log based on severity
        if severity == AuditSeverity.CRITICAL:
            self._logger.critical("audit_event", **audit_record)
        elif severity == AuditSeverity.ERROR:
            self._logger.error("audit_event", **audit_record)
        elif severity == AuditSeverity.WARNING:
            self._logger.warning("audit_event", **audit_record)
        else:
            self._logger.info("audit_event", **audit_record)
        
        return audit_id
    
    def log_auth_event(
        self,
        event_type: AuditEventType,
        device_id: str,
        request: Optional[Request] = None,
        success: bool = True,
        error: Optional[str] = None,
    ) -> str:
        """Log an authentication-related event."""
        severity = AuditSeverity.INFO if success else AuditSeverity.WARNING
        return self.log(
            event_type=event_type,
            severity=severity,
            device_id=device_id,
            request=request,
            details={"success": success},
            error=error,
        )
    
    def log_telemetry_sync(
        self,
        device_id: str,
        records_processed: Dict[str, int],
        request: Optional[Request] = None,
        success: bool = True,
        error: Optional[str] = None,
    ) -> str:
        """Log a telemetry synchronization event."""
        severity = AuditSeverity.INFO if success else AuditSeverity.ERROR
        event_type = AuditEventType.TELEMETRY_SYNC if success else AuditEventType.TELEMETRY_SYNC_FAILED
        
        return self.log(
            event_type=event_type,
            severity=severity,
            device_id=device_id,
            request=request,
            details={
                "success": success,
                "records_processed": records_processed,
            },
            error=error,
        )
    
    def log_security_event(
        self,
        event_type: AuditEventType,
        device_id: str,
        threat_level: Optional[str] = None,
        action_taken: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Log a security-related event."""
        severity = AuditSeverity.WARNING
        if threat_level in ("HIGH", "CRITICAL"):
            severity = AuditSeverity.CRITICAL
        
        event_details = details or {}
        if threat_level:
            event_details["threat_level"] = threat_level
        if action_taken:
            event_details["action_taken"] = action_taken
        
        return self.log(
            event_type=event_type,
            severity=severity,
            device_id=device_id,
            details=event_details,
        )
    
    def log_rate_limit(
        self,
        request: Request,
        limit: str,
    ) -> str:
        """Log a rate limit exceeded event."""
        return self.log(
            event_type=AuditEventType.RATE_LIMIT_EXCEEDED,
            severity=AuditSeverity.WARNING,
            request=request,
            details={"limit": limit},
        )
    
    @staticmethod
    def _get_client_ip(request: Request) -> str:
        """Extract client IP, handling proxies."""
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if not request.client or not hasattr(request.client, 'host'):
            return "unknown"
        return request.client.host


# Global audit logger instance
audit_logger = AuditLogger()
