from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from core.config import get_settings

# ✅ Get database URL from settings
settings = get_settings()
DATABASE_URL = settings.DATABASE_URL

# ✅ Engine with async support
engine = create_async_engine(DATABASE_URL, echo=True, future=True)

# ✅ Async session maker
async_session_maker = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

# ✅ Dependency for FastAPI
async def get_session() -> AsyncSession:
    async with async_session_maker() as session:
        yield session
