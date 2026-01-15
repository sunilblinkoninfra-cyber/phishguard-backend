# PhishGuard AI - Environment Configuration
# Copy this file to .env and fill in your values

# ============================================================================
# ENVIRONMENT
# ============================================================================
ENVIRONMENT=development  # development, staging, production
DEBUG=true

# ============================================================================
# API CONFIGURATION
# ============================================================================
API_V1_PREFIX=/api/v1
PROJECT_NAME=PhishGuard AI
VERSION=1.0.0

# ============================================================================
# DATABASE
# ============================================================================
# Local PostgreSQL
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/phishguard

# Railway/Production (will be auto-populated by Railway)
# DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/railway

# ============================================================================
# REDIS
# ============================================================================
# Local Redis
REDIS_URL=redis://localhost:6379/0

# Upstash/Production (will be auto-populated)
# REDIS_URL=redis://default:password@host:6379

# ============================================================================
# SECURITY
# ============================================================================
# IMPORTANT: Generate a strong secret key for production
# python -c "import secrets; print(secrets.token_urlsafe(32))"
SECRET_KEY=your-secret-key-change-in-production-min-32-characters

# API Key Header Name
API_KEY_HEADER=X-API-Key

# JWT Token Expiration (minutes)
ACCESS_TOKEN_EXPIRE_MINUTES=10080  # 7 days

# ============================================================================
# CORS
# ============================================================================
# Add your frontend URLs (comma-separated)
FRONTEND_URL=http://localhost:3000
# Production example:
# FRONTEND_URL=https://app.phishguard.ai,https://phishguard.vercel.app

# ============================================================================
# RATE LIMITING
# ============================================================================
RATE_LIMIT_PER_MINUTE=60
RATE_LIMIT_PER_HOUR=1000

# ============================================================================
# MALWARE SCANNING
# ============================================================================
# ClamAV Configuration
CLAMAV_HOST=localhost
CLAMAV_PORT=3310
MAX_FILE_SIZE_MB=25

# ============================================================================
# EXTERNAL THREAT INTELLIGENCE APIs
# ============================================================================

# VirusTotal API (Optional but recommended)
# Get free API key: https://www.virustotal.com/gui/my-apikey
VIRUSTOTAL_API_KEY=

# URLhaus API (Free, no key required)
URLHAUS_API_URL=https://urlhaus-api.abuse.ch/v1/

# PhishTank API (Optional)
# Register: https://www.phishtank.com/api_register.php
PHISHTANK_API_KEY=

# ============================================================================
# SIEM INTEGRATIONS
# ============================================================================

# Splunk HEC Integration
SPLUNK_HEC_URL=
SPLUNK_HEC_TOKEN=

# Microsoft Azure Sentinel
AZURE_SENTINEL_WORKSPACE_ID=
AZURE_SENTINEL_SHARED_KEY=

# ============================================================================
# EMAIL GATEWAY INTEGRATIONS
# ============================================================================

# Office 365 / Microsoft Graph API
O365_CLIENT_ID=
O365_CLIENT_SECRET=
O365_TENANT_ID=

# Gmail API
GMAIL_CREDENTIALS=

# ============================================================================
# FILE STORAGE (Reports & Evidence)
# ============================================================================

# AWS S3
S3_BUCKET=phishguard-reports
S3_REGION=us-east-1
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=

# Alternative: Cloudflare R2 (S3-compatible)
# S3_ENDPOINT_URL=https://account.r2.cloudflarestorage.com

# ============================================================================
# BACKGROUND JOBS (Celery)
# ============================================================================
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0

# ============================================================================
# MONITORING & LOGGING
# ============================================================================

# Sentry Error Tracking (Optional)
# Get DSN: https://sentry.io/
SENTRY_DSN=

# Log Level
LOG_LEVEL=INFO  # DEBUG, INFO, WARNING, ERROR, CRITICAL

# ============================================================================
# PRICING TIERS (API Call Limits)
# ============================================================================
TIER_FREE_API_CALLS=100
TIER_PRO_API_CALLS=5000
TIER_ENTERPRISE_API_CALLS=50000

# ============================================================================
# STRIPE PAYMENT INTEGRATION (Optional)
# ============================================================================
STRIPE_PUBLISHABLE_KEY=
STRIPE_SECRET_KEY=
STRIPE_WEBHOOK_SECRET=

# ============================================================================
# DEVELOPMENT / TESTING
# ============================================================================

# Enable/Disable Features
ENABLE_CLAMAV=true
ENABLE_VIRUSTOTAL=true
ENABLE_URL_REPUTATION=true

# Mock External Services (for testing without API keys)
MOCK_EXTERNAL_APIS=false

# ============================================================================
# FRONTEND ENVIRONMENT VARIABLES
# ============================================================================
# These go in frontend/.env.local

# REACT_APP_API_URL=http://localhost:8000
# REACT_APP_API_KEY=your-tenant-api-key

# Production:
# REACT_APP_API_URL=https://api.phishguard.ai
# REACT_APP_API_KEY=will-be-set-by-user-after-signup

# ============================================================================
# NOTES
# ============================================================================
# 1. NEVER commit .env file to version control
# 2. Use strong, unique SECRET_KEY in production
# 3. Rotate API keys regularly
# 4. Use environment-specific values
# 5. Keep production credentials secure
# 6. Enable monitoring in production
# 7. Set up automated backups for production database
# ============================================================================