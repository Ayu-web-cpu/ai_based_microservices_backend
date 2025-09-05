from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    APP_ENV: str = "dev"

    # Image service ka apna database
    DATABASE_URL: str = "postgresql+asyncpg://postgres:ayush@localhost:5432/search_db"

    class Config:
        env_file = ".env"   # env vars isi file se uthenge

@lru_cache
def get_settings() -> Settings:
    return Settings()
