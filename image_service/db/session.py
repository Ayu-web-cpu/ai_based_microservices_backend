from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from core.config import get_settings

settings = get_settings()

# Async database engine
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=True,        # Debug SQL queries in console
    future=True
)

# Async session maker
async_session_maker = async_sessionmaker(
    bind=engine,
    expire_on_commit=False,
    class_=AsyncSession
)

# Dependency for FastAPI routes
async def get_session() -> AsyncSession:
    async with async_session_maker() as session:
        yield session
