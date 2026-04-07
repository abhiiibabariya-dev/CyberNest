"""CyberNest Manager — Configuration via environment variables."""

from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # Service
    SERVICE_NAME: str = "cybernest-manager"
    CYBERNEST_ENV: str = "development"
    DEBUG: bool = False

    # PostgreSQL
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "cybernest"
    POSTGRES_USER: str = "cybernest"
    POSTGRES_PASSWORD: str = "cybernest_secret"

    @property
    def DATABASE_URL(self) -> str:
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def DATABASE_URL_SYNC(self) -> str:
        return (
            f"postgresql+psycopg2://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    # JWT Authentication
    JWT_SECRET_KEY: str = "change-me-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 480

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Kafka
    KAFKA_BOOTSTRAP_SERVERS: str = "localhost:9092"

    # Elasticsearch
    ELASTICSEARCH_URL: str = "http://localhost:9200"

    # Syslog
    SYSLOG_UDP_PORT: int = 514
    SYSLOG_TCP_PORT: int = 514

    # SIEM
    LOG_RETENTION_DAYS: int = 365
    MAX_EVENTS_PER_QUERY: int = 10000
    RULES_DIR: str = "/app/config/rules"
    PLAYBOOKS_DIR: str = "/app/config/playbooks"
    MAX_CONCURRENT_PLAYBOOKS: int = 10

    model_config = {"env_prefix": "", "case_sensitive": True}


@lru_cache()
def get_settings() -> Settings:
    return Settings()
