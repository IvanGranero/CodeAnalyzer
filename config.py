import logging
import os
from typing import Optional
from pydantic import ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

class AppConfig(BaseSettings):
    """
    Centralized configuration. 
    Pydantic automatically matches these lowercase variables to the UPPERCASE keys in the .env file.
    """
    model_config = SettingsConfigDict(env_file='.env', env_file_encoding='utf-8', extra='ignore')

    # --- Cheap tier ("orchestrator") -----------------------------------------
    cheap_subscription_key: str
    cheap_default_headers: str = ""
    cheap_extra_query: str = ""
    cheap_model_id: str
    cheap_base_url: str

    # --- Strong tier ("code analyzer") ---------------------------------------
    strong_subscription_key: str
    strong_default_headers: str = ""
    strong_extra_query: str = ""
    strong_model_id: str
    strong_base_url: str

    # --- Optional pricing ----------------------------------------------------
    # Using Optional[float] = None means if you comment these out in the .env, 
    # they just become None in Python without crashing the app.
    cheap_usd_input: Optional[float] = None
    cheap_usd_output: Optional[float] = None
    
    strong_usd_input: Optional[float] = None
    strong_usd_output: Optional[float] = None

    # --- Scan admission control ---------------------------------------------
    scan_max_concurrent_llm_calls: int = 5
    scan_max_calls: int = 0
    scan_max_tokens: int = 0
    scan_max_cost_usd: float = 0.0
    scan_max_candidates_per_target: int = 12

    # --- Optional TLS override -----------------------------------------------
    # Pydantic natively understands "false", "0", "off" from the .env file
    codegraph_tls_verify: bool = True 

    # --- Neo4j / GraphDB -----------------------------------------------------
    neo4j_uri: str = "neo4j://127.0.0.1:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str


# Initialize the settings globally
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
