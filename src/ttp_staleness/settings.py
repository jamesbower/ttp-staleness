from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TTP_", env_file=".env", extra="ignore")

    cache_dir: Path = Path.home() / ".cache" / "ttp-staleness"
    cache_ttl_hours: int = 24
    attack_domain: str = "enterprise-attack"
    no_cache: bool = False


settings = Settings()
