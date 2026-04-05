"""Application configuration."""

from pydantic_settings import BaseSettings
from pathlib import Path


class Settings(BaseSettings):
    APP_NAME: str = "CyberNest"
    VERSION: str = "0.1.0"
    DEBUG: bool = True

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./cybernest.db"

    # Auth
    SECRET_KEY: str = "cybernest-dev-secret-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Redis (for Celery task queue)
    REDIS_URL: str = "redis://localhost:6379/0"

    # SIEM
    LOG_RETENTION_DAYS: int = 90
    MAX_EVENTS_PER_QUERY: int = 10000
    RULES_DIR: Path = Path(__file__).parent.parent.parent / "config" / "rules"

    # SOAR
    PLAYBOOKS_DIR: Path = Path(__file__).parent.parent.parent / "config" / "playbooks"
    MAX_CONCURRENT_PLAYBOOKS: int = 10

    model_config = {"env_file": ".env", "env_prefix": "CYBERNEST_"}


settings = Settings()
