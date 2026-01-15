from pydantic_settings import BaseSettings
from typing import List
import os

class Settings(BaseSettings):
    """Application settings"""
    
    # Environment
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    DEBUG: bool = os.getenv("DEBUG", "true").lower() == "true"
    
    # API Configuration
    API_V1_PREFIX: str = "/api/v1"
    PROJECT_NAME: str = "PhishGuard AI"
    VERSION: str = "1.0.0"
    
    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:3001",
        "https://*.vercel.app",
        os.getenv("FRONTEND_URL", "")
    ]
    
    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://postgres:postgres@localhost:5432/phishguard"
    )
    
    # Redis
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
    API_KEY_HEADER: str = "X-API-Key"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_PER_HOUR: int = 1000
    
    # Malware Scanning
    CLAMAV_HOST: str = os.getenv("CLAMAV_HOST", "localhost")
    CLAMAV_PORT: int = int(os.getenv("CLAMAV_PORT", "3310"))
    MAX_FILE_SIZE_MB: int = 25
    
    # External APIs
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    URLHAUS_API_URL: str = "https://urlhaus-api.abuse.ch/v1/"
    PHISHTANK_API_KEY: str = os.getenv("PHISHTANK_API_KEY", "")
    
    # SIEM Integration
    SPLUNK_HEC_URL: str = os.getenv("SPLUNK_HEC_URL", "")
    SPLUNK_HEC_TOKEN: str = os.getenv("SPLUNK_HEC_TOKEN", "")
    AZURE_SENTINEL_WORKSPACE_ID: str = os.getenv("AZURE_SENTINEL_WORKSPACE_ID", "")
    AZURE_SENTINEL_SHARED_KEY: str = os.getenv("AZURE_SENTINEL_SHARED_KEY", "")
    
    # Email Gateway Integration
    O365_CLIENT_ID: str = os.getenv("O365_CLIENT_ID", "")
    O365_CLIENT_SECRET: str = os.getenv("O365_CLIENT_SECRET", "")
    O365_TENANT_ID: str = os.getenv("O365_TENANT_ID", "")
    GMAIL_CREDENTIALS: str = os.getenv("GMAIL_CREDENTIALS", "")
    
    # File Storage
    S3_BUCKET: str = os.getenv("S3_BUCKET", "phishguard-reports")
    S3_REGION: str = os.getenv("S3_REGION", "us-east-1")
    AWS_ACCESS_KEY_ID: str = os.getenv("AWS_ACCESS_KEY_ID", "")
    AWS_SECRET_ACCESS_KEY: str = os.getenv("AWS_SECRET_ACCESS_KEY", "")

ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
    
    # Celery
    CELERY_BROKER_URL: str = os.getenv("CELERY_BROKER_URL", REDIS_URL)
    CELERY_RESULT_BACKEND: str = os.getenv("CELERY_RESULT_BACKEND", REDIS_URL)
    
    # Monitoring
    SENTRY_DSN: str = os.getenv("SENTRY_DSN", "")
    
    # Pricing Tiers
    TIER_FREE_API_CALLS: int = 100
    TIER_PRO_API_CALLS: int = 5000
    TIER_ENTERPRISE_API_CALLS: int = 50000
    
    class Config:
        case_sensitive = True
        env_file = ".env"

settings = Settings()