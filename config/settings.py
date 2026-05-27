# config/settings.py — FusionOps configuration
# All environment variables are loaded from .env

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ThreatFade API connection
    threatfade_api_url: str = "http://localhost:8000"

    # FusionOps API
    fusionops_port: int = 8080
    fusionops_env: str = "development"

    # Security
    secret_key: str = "change-this-in-production"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


# Single shared instance — import this everywhere
settings = Settings()