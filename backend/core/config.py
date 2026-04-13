"""Application configuration."""
from pydantic_settings import BaseSettings
from pathlib import Path
import os

class Settings(BaseSettings):
    APP_NAME: str = "CyberNest"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    DATABASE_URL: str = "sqlite:///./cybernest.db"
    SECRET_KEY: str = "cybernest-dev-secret-CHANGE-IN-PRODUCTION-use-256bit-random"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480
    REDIS_URL: str = "redis://localhost:6379/0"
    LOG_RETENTION_DAYS: int = 90
    MAX_EVENTS_PER_QUERY: int = 10000
    RULES_DIR: Path = Path(__file__).resolve().parent.parent.parent / "config" / "rules"
    PLAYBOOKS_DIR: Path = Path(__file__).resolve().parent.parent.parent / "config" / "playbooks"
    MAX_CONCURRENT_PLAYBOOKS: int = 10
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    SHODAN_API_KEY: str = ""
    OTX_API_KEY: str = ""
    SLACK_WEBHOOK_URL: str = ""
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "cybernest@yourdomain.com"
    PAGERDUTY_INTEGRATION_KEY: str = ""
    FIREWALL_TYPE: str = "iptables"
    AWS_NACL_ID: str = ""
    AWS_REGION: str = "us-east-1"
    SYSLOG_UDP_PORT: int = 5514
    SYSLOG_TCP_PORT: int = 6601

    model_config = {"env_file": ".env", "env_prefix": "CYBERNEST_"}

settings = Settings()
