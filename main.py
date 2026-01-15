import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from prometheus_client import make_asgi_app

from api.routes import auth, scan, soc, siem, reports, tenants
from core.config import settings
from core.database import init_db, close_db
from core.redis_client import init_redis, close_redis

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_db()
    await init_redis()
    logger.info("PhishGuard AI backend started successfully")
    yield
    # Shutdown
    await close_db()
    await close_redis()
    logger.info("PhishGuard AI backend shutdown")

# Create FastAPI app
app = FastAPI(
    title="PhishGuard AI API",
    description="AI-powered phishing detection and security API",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting middleware
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Prometheus metrics
app.mount("/metrics", make_asgi_app())

# Exception handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors(), "body": exc.body},
    )

# Health check endpoint
@app.get("/health")
async def health_check():
    """Root endpoint"""
    return {
        "service": "PhishGuard AI API",
        "version": "1.0.0",
        "docs": "/docs" if settings.ENVIRONMENT == "development" else None,
        "status": "operational"
    }

# Include routers (fixed: direct router objects, no .router slip!)
app.include_router(auth, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(scan, prefix="/api/v1/scan", tags=["Scanning"])
app.include_router(soc, prefix="/api/v1/soc", tags=["SOC"])
app.include_router(siem, prefix="/api/v1/siem", tags=["SIEM"])
app.include_router(reports, prefix="/api/v1/reports", tags=["Reports"])
app.include_router(tenants, prefix="/api/v1/tenants", tags=["Tenants"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",  # Fixed: Use "main:app" since file is main.py
        host="0.0.0.0",
        port=int(os.getenv("PORT", 8000)),
        reload=settings.ENVIRONMENT == "development"
    )