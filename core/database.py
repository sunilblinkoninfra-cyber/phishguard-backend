from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from core.config import settings

engine = create_async_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,  # Ping to keep pool fresh!
    pool_recycle=300,    # Recycle connections every 5 mins
    pool_timeout=30,     # Boost timeout to 30 secs
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

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def close_db():
    await engine.dispose()