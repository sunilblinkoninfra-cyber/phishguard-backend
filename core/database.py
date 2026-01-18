from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from core.config import settings

import logging
logger = logging.getLogger(__name__)
engine = create_async_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=300,
    pool_timeout=60,  # Boost to 60 secs for slow wakes!
    connect_args={"connect_timeout": 60},  # Asyncpg connect timeout boost
    echo=settings.DEBUG
)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

Base = declarative_base()

async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise

async def init_db():
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("DB tables created!")
    except Exception as e:
        logger.error(f"DB init failed: {e}")
        # Retry once after 5 secs
        import asyncio
        await asyncio.sleep(5)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

async def close_db():
    await engine.dispose()