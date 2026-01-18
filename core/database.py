from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from core.config import settings
import logging
import asyncio

logger = logging.getLogger(__name__)

# Supercharged engine with max retries & timeouts
engine = create_async_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,  # Ping to keep pool fresh!
    pool_recycle=300,    # Recycle every 5 mins
    pool_timeout=120,    # Max pool wait 2 mins
    connect_args={"command_timeout": 120},  # Asyncpg command timeout 2 mins
    echo=settings.DEBUG  # Log queries in dev
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

async def init_db(max_retries=3):
    for attempt in range(max_retries):
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("DB tables created successfully!")
            return  # Success – exit loop
        except Exception as e:
            logger.error(f"DB init attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(10 * (attempt + 1))  # Backoff: 10s, 20s, 30s
            else:
                logger.error("DB init failed after all retries – using without tables (MVP mode)")
                return  # Graceful fail – app runs without tables for MVP

async def close_db():
    await engine.dispose()