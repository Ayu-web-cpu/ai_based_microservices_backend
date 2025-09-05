from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    APP_ENV: str = "dev"

    # Har microservice ka apna DB hoga
    DATABASE_URL: str = "postgresql+asyncpg://postgres:ayush@localhost:5432/auth_db"

    # JWT settings
    JWT_SECRET: str = "supersecret"
    JWT_ALG: str = "HS256"

    # ⬇️ Access token 60 minutes (1 hour)
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # ⬇️ Refresh token 30 days
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30

    class Config:
        env_file = ".env"

@lru_cache
def get_settings() -> Settings:
    return Settings()
