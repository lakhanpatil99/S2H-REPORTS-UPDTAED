from supabase import create_client, Client
from app.core.config import settings
import structlog

logger = structlog.get_logger()

# SUPABASE_SECRET_KEY is normalized in config (falls back to the legacy
# SUPABASE_SERVICE_ROLE_KEY when only that is provided).
try:
    supabase: Client = create_client(settings.SUPABASE_URL, settings.SUPABASE_SECRET_KEY)
except Exception as exc:
    # During pytest collection the real client may fail (httpx proxy kwarg
    # removal in newer versions).  conftest.py patches this module before any
    # test actually executes, so a None sentinel is safe here.
    # In production the health-check will surface the None and return 503.
    logger.error(
        "supabase_init_failed",
        error=str(exc),
        hint="Supabase client failed to initialize. "
             "Verify SUPABASE_URL and SUPABASE_SECRET_KEY in .env",
    )
    supabase = None  # type: ignore[assignment]
