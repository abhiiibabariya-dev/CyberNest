"""
CyberNest Manager -- Configuration loaded from environment variables.

All secrets and connection strings come from env vars -- never hardcoded.
Uses Pydantic BaseSettings for type-safe config with validation.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings


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
    JWT_REFRESH_EXPIRE_MINUTES: int = 10080  # 7 days

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Kafka
    KAFKA_BOOTSTRAP: str = "localhost:9092"

    # Elasticsearch
    ES_URL: str = "http://localhost:9200"
    ES_INDEX_EVENTS: str = "cybernest-events-*"
    ES_INDEX_ALERTS: str = "cybernest-alerts-*"

    # Receivers
    SYSLOG_UDP_PORT: int = 514
    SYSLOG_TCP_PORT: int = 601
    AGENT_TLS_PORT: int = 5601

    # CORS
    CORS_ORIGINS: str = "*"

    # Rate limiting
    RATE_LIMIT_DEFAULT: int = 1000  # requests per minute per user
    RATE_LIMIT_AUTH: int = 10  # requests per minute on /auth/login by IP

    # File uploads
    UPLOAD_DIR: str = "/data/attachments"
    MAX_UPLOAD_SIZE: int = 52_428_800  # 50 MB

    model_config = {"env_prefix": "", "case_sensitive": True}


@lru_cache()
def get_settings() -> Settings:
    return Settings()
