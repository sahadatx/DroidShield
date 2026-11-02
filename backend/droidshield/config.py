import sys
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DROIDSHIELD_", env_file=".env", extra="ignore")

    environment: Literal["development", "test", "production"] = "development"
    database_url: str = "sqlite:///./var/droidshield.db"
    cors_origins: list[str] = Field(default_factory=list)
    allowed_hosts: list[str] = Field(default_factory=lambda: ["localhost", "127.0.0.1"])
    token_ttl_hours: int = Field(default=12, ge=1, le=168)
    storage_root: Path = Path("var/artifacts")
    max_apk_bytes: int = Field(default=100 * 1024**2, ge=1024, le=2 * 1024**3)
    max_concurrent_uploads: int = Field(default=2, ge=1, le=16)
    upload_timeout_seconds: int = Field(default=120, ge=1, le=900)
    apk_max_entries: int = Field(default=10_000, ge=10, le=100_000)
    apk_max_uncompressed_bytes: int = Field(default=512 * 1024**2, ge=1024, le=2 * 1024**3)
    apk_max_manifest_bytes: int = Field(default=4 * 1024**2, ge=1024, le=16 * 1024**2)
    apk_max_compression_ratio: int = Field(default=100, ge=1, le=1000)
    sandbox_executable: str = "/usr/bin/bwrap"
    sandbox_python: str = "/usr/bin/python3"
    analysis_timeout_seconds: int = Field(default=30, ge=1, le=120)
    analysis_cpu_seconds: int = Field(default=15, ge=1, le=120)
    analysis_memory_mb: int = Field(default=256, ge=64, le=2048)
    analysis_output_bytes: int = Field(default=1024**2, ge=4096, le=4 * 1024**2)
    worker_lease_seconds: int = Field(default=120, ge=10, le=3600)
    worker_poll_seconds: float = Field(default=0.5, ge=0.1, le=30)
    worker_heartbeat_seconds: float = Field(default=1.0, ge=0.1, le=10)
    dex_max_files: int = Field(default=16, ge=1, le=128)
    dex_max_bytes: int = Field(default=64 * 1024**2, ge=1024, le=512 * 1024**2)
    dex_max_ids: int = Field(default=100_000, ge=100, le=1_000_000)
    dex_max_code_units: int = Field(default=4_000_000, ge=1000, le=32_000_000)
    mobsf_url: str | None = None
    mobsf_api_key: SecretStr | None = Field(default=None, exclude=True, repr=False)
    mobsf_timeout_seconds: int = Field(default=180, ge=10, le=600)
    mobsf_max_report_bytes: int = Field(default=8 * 1024**2, ge=4096, le=32 * 1024**2)
    lab_devices: list[dict[str, str]] = Field(default_factory=list)
    adb_executable: str = "/usr/bin/adb"
    dynamic_timeout_seconds: int = Field(default=90, ge=10, le=120)
    dynamic_max_output_bytes: int = Field(default=64 * 1024, ge=4096, le=1024**2)
    frida_version: Literal["17.9.10"] = "17.9.10"
    frida_server_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    frida_token: SecretStr | None = Field(default=None, exclude=True, repr=False)
    frida_python: str = sys.executable
    frida_observation_seconds: int = Field(default=3, ge=1, le=10)
    proxy_ca_cert: Path | None = None
    proxy_ca_key: Path | None = Field(default=None, exclude=True, repr=False)
    proxy_observation_seconds: int = Field(default=5, ge=1, le=15)
    proxy_max_requests: int = Field(default=20, ge=1, le=60)
    api_secret_store: Path | None = Field(default=None, exclude=True, repr=False)
    api_allowed_networks: list[str] = Field(default_factory=list)
    api_ca_bundle: Path | None = None
    api_timeout_seconds: int = Field(default=120, ge=10, le=300)
    api_request_timeout_seconds: int = Field(default=10, ge=1, le=30)
    api_max_response_bytes: int = Field(default=65536, ge=1024, le=262144)
    api_max_requests: int = Field(default=60, ge=1, le=120)

    @field_validator("sandbox_executable", "sandbox_python", "adb_executable", "frida_python")
    @classmethod
    def absolute_executables(cls, value: str) -> str:
        if not Path(value).is_absolute() or "\x00" in value:
            raise ValueError("Sandbox executables require an absolute path")
        return value

    @field_validator("api_allowed_networks")
    @classmethod
    def explicit_networks(cls, values):
        import ipaddress

        result = []
        for value in values:
            network = ipaddress.ip_network(value, strict=True)
            if network.prefixlen == 0:
                raise ValueError("Default routes cannot authorize API egress")
            result.append(str(network))
        return sorted(set(result))

    @field_validator("mobsf_url")
    @classmethod
    def mobsf_service(cls, value: str | None) -> str | None:
        if value is None:
            return None
        from urllib.parse import urlsplit

        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or any(c.isspace() for c in value)
        ):
            raise ValueError("MobSF requires a fixed service URL without credentials or query")
        if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("Unencrypted MobSF connections are restricted to loopback")
        return value.rstrip("/")

    @field_validator("cors_origins", "allowed_hosts")
    @classmethod
    def no_wildcards(cls, values: list[str]) -> list[str]:
        if any("*" in value for value in values):
            raise ValueError("Explicit origins and hosts are required")
        return values

    @model_validator(mode="after")
    def production_database(self) -> "Settings":
        visible_runtime = {Path(path).resolve() for path in ("/usr", "/lib", "/lib64")}
        if any(self.storage_root.resolve().is_relative_to(path) for path in visible_runtime):
            raise ValueError("Protected storage must be outside sandbox runtime directories")
        parsed_url = make_url(self.database_url)
        if parsed_url.get_backend_name() == "sqlite" and parsed_url.database not in {
            None,
            "",
            ":memory:",
        }:
            database_file = Path(parsed_url.database).expanduser().resolve()
            if any(database_file.is_relative_to(path) for path in visible_runtime):
                raise ValueError("SQLite data must be outside sandbox runtime directories")
        if self.environment == "production" and not self.database_url.startswith(
            "postgresql+psycopg://"
        ):
            raise ValueError("Production requires PostgreSQL using the psycopg driver")
        if self.environment == "production" and not self.storage_root.is_absolute():
            raise ValueError("Production requires an absolute protected storage root")
        if self.worker_lease_seconds <= 3 * self.worker_heartbeat_seconds:
            raise ValueError("Worker lease must exceed three heartbeat intervals")
        return self
