import logging
import os
from typing import Any
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class TokenPricing(BaseModel):
    """Per-million-token pricing used by the LLM usage tracker."""
    model_config = ConfigDict(frozen=True)
    input: float = 0.0
    output: float = 0.0
    cached: float = 0.0


class AppConfig(BaseSettings):
    """
    Centralized configuration.
    Pydantic automatically matches these lowercase variables to the UPPERCASE keys in the .env file.
    """
    model_config = SettingsConfigDict(
        env_file='.env',
        env_file_encoding='utf-8',
        env_nested_delimiter='__',
        extra='ignore',
    )

    
    cheap_subscription_key: str
    cheap_headers: str = ""
    cheap_api_version: str = ""
    cheap_model_id: str
    cheap_deployment: str = ""
    cheap_base_url: str
    cheap_api_style: str = "chat_responses"

    
    strong_subscription_key: str
    strong_headers: str = ""
    strong_api_version: str = ""
    strong_model_id: str
    strong_deployment: str = ""
    strong_base_url: str
    strong_api_style: str = "chat_responses"
    triage_model_tier: str = "cheap"

    
    cheap_token_pricing: TokenPricing = Field(default_factory=TokenPricing)
    strong_token_pricing: TokenPricing = Field(default_factory=TokenPricing)


    
    
    codegraph_tls_verify: bool = True

    
    neo4j_uri: str = "neo4j://127.0.0.1:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str



try:
    settings = AppConfig()
except ValidationError as e:
    missing = [
        str(error["loc"][0])
        for error in e.errors()
        if error.get("type") == "missing"
    ]
    invalid = [
        str(error["loc"][0])
        for error in e.errors()
        if error.get("type") != "missing"
    ]

    logger.critical("Configuration could not be loaded.")
    if not os.path.exists(".env"):
        logger.critical("No .env file was found in the current directory.")
    if missing:
        logger.critical("Missing required settings: %s", ", ".join(missing))
    if invalid:
        logger.critical("Invalid settings: %s", ", ".join(invalid))
    logger.critical(
        "Create or update .env using the configuration variables documented "
        "in readme.md, then run the command again."
    )
    raise SystemExit(2)
except Exception as e:
    logger.critical("Configuration could not be loaded: %s", e)
    raise SystemExit(2)
