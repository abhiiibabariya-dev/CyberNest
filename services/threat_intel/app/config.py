"""CyberNest Threat Intel — Service configuration via environment variables."""

import os
from pydantic_settings import BaseSettings
from functools import lru_cache


class ThreatIntelSettings(BaseSettings):
    """Configuration for the Threat Intelligence service.

    All secrets loaded from environment variables — never hardcoded.
    """
    SERVICE_NAME: str = "cybernest-threat-intel"

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

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Feed refresh interval (seconds)
    FEED_REFRESH_INTERVAL: int = 3600

    # API Keys for threat intel providers
    OTX_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""

    # IOC default TTL (days)
    IOC_DEFAULT_TTL_DAYS: int = 90

    model_config = {"env_prefix": "", "case_sensitive": True}


@lru_cache()
def get_settings() -> ThreatIntelSettings:
    return ThreatIntelSettings()
