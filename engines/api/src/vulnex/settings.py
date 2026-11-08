from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration from VULNEX_* environment variables.

    The API connects as the least-privileged `vulnex_app` role (ADR-0005). The migration
    (owner) URL is deliberately not here: only Alembic reads it, so the API process never holds it.
    """

    model_config = SettingsConfigDict(env_prefix="VULNEX_")

    database_url: SecretStr
    log_level: str = "INFO"
