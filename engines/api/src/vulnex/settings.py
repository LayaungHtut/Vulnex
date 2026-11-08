from ipaddress import IPv4Network, IPv6Network, ip_network
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration from VULNEX_* environment variables.

    The API connects as the least-privileged `vulnex_app` role (ADR-0005). The migration
    (owner) URL is deliberately not here: only Alembic reads it, so the API process never holds it.
    """

    model_config = SettingsConfigDict(env_prefix="VULNEX_")

    database_url: SecretStr
    log_level: str = "INFO"

    # Sessions: absolute lifetime and idle timeout (OWASP ASVS V7 ranges for a security tool).
    session_ttl_hours: int = Field(default=12, ge=1, le=24 * 7)
    session_idle_minutes: int = Field(default=30, ge=5, le=24 * 60)

    # Failed sign-ins tolerated per email and per source address within the window.
    login_window_minutes: int = Field(default=15, ge=1, le=24 * 60)
    login_max_failures_per_email: int = Field(default=5, ge=1)
    login_max_failures_per_ip: int = Field(default=20, ge=1)

    # Comma-separated CIDRs whose X-Forwarded-For is believed (the console, a reverse proxy).
    # Empty: the direct peer address is the client address.
    trusted_proxies: str = ""

    # Scanner enrollment (ADR-0006 §1). The URL workers connect to (the mTLS gateway) and the CA
    # that issued its TLS certificate, which goes into each enrollment bundle for pinning.
    # Both unset: enrollment is refused with 503.
    worker_endpoint_url: str = ""
    worker_endpoint_ca_file: Path | None = None
    # Worker API only (vulnex.worker_api): directory holding worker-ca.* and scope-signing.key.
    worker_pki_dir: Path | None = None

    @property
    def trusted_proxy_networks(self) -> list[IPv4Network | IPv6Network]:
        return [ip_network(n.strip()) for n in self.trusted_proxies.split(",") if n.strip()]
