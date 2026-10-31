from fastapi import Request, status, HTTPException
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
import structlog
from typing import Optional

logger = structlog.get_logger()


class APIError(HTTPException):
    """Base class for API errors with RFC 7807 Problem Details format."""
    
    def __init__(
        self,
        status_code: int,
        detail: str,
        error_type: str = "api-error",
        title: Optional[str] = None,
        instance: Optional[str] = None,
        **extra
    ):
        super().__init__(status_code=status_code, detail=detail)
        self.error_type = error_type
        self.title = title or self._get_default_title(status_code)
        self.instance = instance
        self.extra = extra
    
    @staticmethod
    def _get_default_title(status_code: int) -> str:
        titles = {
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            409: "Conflict",
            422: "Unprocessable Entity",
            429: "Too Many Requests",
            500: "Internal Server Error",
            503: "Service Unavailable",
        }
        return titles.get(status_code, "Error")


class AuthenticationError(APIError):
    """Raised when authentication fails."""
    def __init__(self, detail: str = "Authentication required"):
        super().__init__(
            status_code=401,
            detail=detail,
            error_type="authentication-error",
        )


class AuthorizationError(APIError):
    """Raised when user lacks permission."""
    def __init__(self, detail: str = "Permission denied"):
        super().__init__(
            status_code=403,
            detail=detail,
            error_type="authorization-error",
        )


class ResourceNotFoundError(APIError):
    """Raised when a resource is not found."""
    def __init__(self, resource: str, identifier: str):
        super().__init__(
            status_code=404,
            detail=f"{resource} with identifier '{identifier}' not found",
            error_type="resource-not-found",
            resource=resource,
            identifier=identifier,
        )


class ValidationError(APIError):
    """Raised for business logic validation failures."""
    def __init__(self, detail: str, field: Optional[str] = None):
        super().__init__(
            status_code=422,
            detail=detail,
            error_type="validation-error",
            field=field,
        )


class RateLimitError(APIError):
    """Raised when rate limit is exceeded."""
    def __init__(self, retry_after: int = 60):
        super().__init__(
            status_code=429,
            detail=f"Rate limit exceeded. Please retry after {retry_after} seconds.",
            error_type="rate-limit-exceeded",
            retry_after=retry_after,
        )


class DatabaseError(APIError):
    """Raised for database operation failures."""
    def __init__(self, detail: str = "Database operation failed"):
        super().__init__(
            status_code=500,
            detail=detail,
            error_type="database-error",
        )


def _build_error_response(
    status_code: int,
    error_type: str,
    title: str,
    detail: str,
    instance: str,
    **extra
) -> dict:
    """Build RFC 7807 Problem Details response."""
    response = {
        "type": f"https://api.ransomshield.internal/errors/{error_type}",
        "title": title,
        "status": status_code,
        "detail": detail,
        "instance": instance,
    }
    response.update(extra)
    return response


async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle Pydantic validation errors."""
    errors = exc.errors()
    
    logger.warning(
        "validation_failed",
        path=request.url.path,
        errors=errors,
        request_id=getattr(request.state, 'request_id', None),
    )
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=_build_error_response(
            status_code=422,
            error_type="validation-error",
            title="Unprocessable Entity",
            detail="Request payload validation failed",
            instance=request.url.path,
            errors=[
                {
                    "field": ".".join(str(loc) for loc in e.get("loc", [])),
                    "message": e.get("msg", ""),
                    "type": e.get("type", ""),
                }
                for e in errors
            ]
        )
    )


async def api_error_handler(request: Request, exc: APIError):
    """Handle custom API errors."""
    logger.warning(
        "api_error",
        path=request.url.path,
        error_type=exc.error_type,
        detail=exc.detail,
        request_id=getattr(request.state, 'request_id', None),
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content=_build_error_response(
            status_code=exc.status_code,
            error_type=exc.error_type,
            title=exc.title,
            detail=exc.detail,
            instance=exc.instance or request.url.path,
            **exc.extra
        )
    )


async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle standard HTTP exceptions."""
    logger.warning(
        "http_error",
        path=request.url.path,
        status_code=exc.status_code,
        detail=exc.detail,
        request_id=getattr(request.state, 'request_id', None),
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content=_build_error_response(
            status_code=exc.status_code,
            error_type="http-error",
            title=APIError._get_default_title(exc.status_code),
            detail=exc.detail,
            instance=request.url.path,
        ),
        headers=getattr(exc, 'headers', None)
    )
