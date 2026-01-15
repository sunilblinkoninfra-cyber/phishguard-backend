import logging
from typing import Optional
from fastapi import Header, HTTPException, status, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from models.database import Tenant
from core.config import settings

logger = logging.getLogger(__name__)

async def get_current_tenant(
    x_api_key: str = Header(..., alias="X-API-Key"),
    db: AsyncSession = Depends(get_db)
) -> Tenant:
    """
    Validate API key and return current tenant
    
    Raises:
        HTTPException: If API key is invalid or tenant is inactive
    """
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key is required"
        )
    
    # Query tenant by API key
    stmt = select(Tenant).where(Tenant.api_key == x_api_key)
    result = await db.execute(stmt)
    tenant = result.scalar_one_or_none()
    
    if not tenant:
        logger.warning(f"Invalid API key attempt: {x_api_key[:10]}...")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
    if not tenant.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive. Please contact support."
        )
    
    # Check API call limits
    if tenant.api_calls_used >= tenant.api_calls_limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"API call limit exceeded. Your plan allows {tenant.api_calls_limit} calls per month."
        )
    
    return tenant

async def get_optional_tenant(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_db)
) -> Optional[Tenant]:
    """
    Optional API key authentication for public endpoints
    """
    if not x_api_key:
        return None
    
    try:
        return await get_current_tenant(x_api_key, db)
    except HTTPException:
        return None