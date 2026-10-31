from pydantic_settings import BaseSettings
from pydantic import field_validator, model_validator
from typing import List
import secrets


class Settings(BaseSettings):
    """
    Application settings with secure defaults.
    
    CRITICAL: All secrets MUST be provided via environment variables.
    The application will fail to start if required secrets are missing.
    """
    PROJECT_NAME: str = "RansomShield Backend API"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Required secrets - no defaults, must be set via environment
    SUPABASE_URL: str
    # Server-side Supabase key. Canonical name is SUPABASE_SECRET_KEY (new
    # Supabase key format, e.g. "sb_secret_..."). SUPABASE_SERVICE_ROLE_KEY is
    # retained as a legacy alias for backward compatibility; either may be set.
    SUPABASE_SECRET_KEY: str = ""
    SUPABASE_SERVICE_ROLE_KEY: str = ""
    # Optional: publishable/anon key and JWKS endpoint (JWT signature verification).
    SUPABASE_PUBLISHABLE_KEY: str = ""
    SUPABASE_JWKS_URL: str = ""
    JWT_SECRET_KEY: str
    ENROLLMENT_MASTER_KEY: str
    
    # JWT Configuration
    JWT_ACCESS_TOKEN_EXPIRE_DAYS: int = 7  # Reduced from 90 days
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    JWT_ALGORITHM: str = "HS256"
    
    # CORS Configuration
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: List[str] = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    # Restrict to the headers the dashboard/agent actually send instead of "*".
    CORS_ALLOW_HEADERS: List[str] = ["Authorization", "Content-Type", "X-Request-ID"]
    
    # Rate Limiting Configuration
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_BURST: int = 10
    
    # Security Settings
    REQUIRE_HTTPS: bool = False  # Set to True in production
    
    @field_validator('SUPABASE_URL')
    @classmethod
    def validate_supabase_url(cls, v: str) -> str:
        if not v or v == "":
            raise ValueError("SUPABASE_URL must be set in environment variables")
        if not v.startswith("https://"):
            raise ValueError("SUPABASE_URL must use HTTPS")
        return v
    
    @model_validator(mode="after")
    def _normalize_supabase_keys(self):
        """
        Reconcile the canonical SUPABASE_SECRET_KEY with the legacy
        SUPABASE_SERVICE_ROLE_KEY, derive the JWKS URL when omitted, and
        validate that a real server-side key is present.
        """
        # Prefer the new secret key; fall back to the legacy service role key.
        if not self.SUPABASE_SECRET_KEY and self.SUPABASE_SERVICE_ROLE_KEY:
            self.SUPABASE_SECRET_KEY = self.SUPABASE_SERVICE_ROLE_KEY
        if not self.SUPABASE_SERVICE_ROLE_KEY and self.SUPABASE_SECRET_KEY:
            self.SUPABASE_SERVICE_ROLE_KEY = self.SUPABASE_SECRET_KEY

        # Derive the JWKS URL from the project URL when not explicitly provided.
        if not self.SUPABASE_JWKS_URL and self.SUPABASE_URL:
            self.SUPABASE_JWKS_URL = (
                f"{self.SUPABASE_URL.rstrip('/')}/auth/v1/.well-known/jwks.json"
            )

        key = self.SUPABASE_SECRET_KEY
        invalid_prefixes = ("mock-", "default", "your-", "replace")
        if not key or key.startswith(invalid_prefixes):
            raise ValueError(
                "A valid Supabase server key must be set via SUPABASE_SECRET_KEY "
                "(or the legacy SUPABASE_SERVICE_ROLE_KEY) in environment variables"
            )
        return self

    @field_validator('JWT_SECRET_KEY')
    @classmethod
    def validate_jwt_secret(cls, v: str) -> str:
        if not v or v == "" or v.startswith("generate-") or v.startswith("default"):
            raise ValueError("JWT_SECRET_KEY must be set to a secure value in environment variables")
        if len(v) < 32:
            raise ValueError("JWT_SECRET_KEY must be at least 32 characters for security")
        return v
    
    @field_validator('ENROLLMENT_MASTER_KEY')
    @classmethod  
    def validate_enrollment_key(cls, v: str) -> str:
        if not v or v == "" or v.startswith("default") or v == "test_enrollment_key":
            raise ValueError("ENROLLMENT_MASTER_KEY must be set to a secure value in environment variables")
        if len(v) < 16:
            raise ValueError("ENROLLMENT_MASTER_KEY must be at least 16 characters for security")
        return v
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


def generate_secure_key(length: int = 64) -> str:
    """Generate a cryptographically secure random key for configuration."""
    return secrets.token_urlsafe(length)


settings = Settings()
