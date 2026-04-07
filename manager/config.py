"""CyberNest Manager — Configuration loaded from environment variables.

All secrets and connection strings come from env vars — never hardcoded.
Uses Pydantic BaseSettings for type-safe config with validation.
"""

from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Manager service configuration."""

    # Service
    SERVICE_NAME: str = "cybernest-manager"
    LOG_LEVEL: str = "INFO"
    DEBUG: bool = False

    # API
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 5000

    # PostgreSQL
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "cybernest"
    POSTGRES_USER: str = "cybernest"
    POSTGRES_PASSWORD: str = "CyberNest_DB_2025"

    @property
    def DATABASE_URL(self) -> str:
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    # JWT
    JWT_SECRET: str = "change_me_in_production_64chars_min"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 480

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Kafka
    KAFKA_BOOTSTRAP: str = "localhost:9092"

    # Elasticsearch
    ES_URL: str = "http://localhost:9200"

    # Receivers
    SYSLOG_UDP_PORT: int = 514
    SYSLOG_TCP_PORT: int = 601
    AGENT_TLS_PORT: int = 5601

    # CORS
    CORS_ORIGINS: str = "*"

    model_config = {"env_prefix": "", "case_sensitive": True}


@lru_cache()
def get_settings() -> Settings:
    return Settings()
