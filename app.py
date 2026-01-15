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
    """Application lifespan events"""
    # Startup
    logger.info("Starting PhishGuard AI API...")
    await init_db()
    await init_redis()
    logger.info("PhishGuard AI API started successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down PhishGuard AI API...")
    await close_db()
    await close_redis()
    logger.info("PhishGuard AI API shut down successfully")

# Initialize FastAPI app
app = FastAPI(
    title="PhishGuard AI API",
    description="Enterprise Phishing, Malware & SOC Platform",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.ENVIRONMENT == "development" else None,
    redoc_url="/redoc" if settings.ENVIRONMENT == "development" else None,
)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Prometheus metrics
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

# Exception handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors"""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "Validation Error",
            "details": exc.errors(),
            "body": exc.body
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred" if settings.ENVIRONMENT == "production" else str(exc)
        }
    )

# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "PhishGuard AI",
        "version": "1.0.0"
    }

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "PhishGuard AI API",
        "version": "1.0.0",
        "docs": "/docs" if settings.ENVIRONMENT == "development" else None,
        "status": "operational"
    }

# Include routers
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(scan.router, prefix="/api/v1", tags=["Scanning"])
app.include_router(soc.router, prefix="/api/v1/soc", tags=["SOC"])
app.include_router(siem.router, prefix="/api/v1/siem", tags=["SIEM"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])
app.include_router(tenants.router, prefix="/api/v1/tenants", tags=["Tenants"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", 8000)),
        reload=settings.ENVIRONMENT == "development"
    )