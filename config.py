import logging
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

class AppConfig(BaseSettings):
    """
    Centralized configuration. 
    Pydantic automatically matches these lowercase variables to the UPPERCASE keys in the .env file.
    """
    model_config = SettingsConfigDict(env_file='.env', env_file_encoding='utf-8', extra='ignore')

    # --- GenAI / Auth --------------------------------------------------------
    # No default value means this MUST be present in the .env file
    genai_subscription_key: str 
    genai_subscription_header: str = "genaiplatform-farm-subscription-key"

    # --- Cheap tier ("orchestrator") -----------------------------------------
    cheap_model_id: str
    cheap_base_url: str
    cheap_api_version: str

    # --- Strong tier ("code analyzer") ---------------------------------------
    strong_model_id: str
    strong_base_url: str
    strong_api_version: str

    # --- Optional pricing ----------------------------------------------------
    # Using Optional[float] = None means if you comment these out in the .env, 
    # they just become None in Python without crashing the app.
    cheap_usd_per_1k_input: Optional[float] = None
    cheap_usd_per_1k_output: Optional[float] = None
    cheap_usd_per_1k_cached_input: Optional[float] = None
    
    strong_usd_per_1k_input: Optional[float] = None
    strong_usd_per_1k_output: Optional[float] = None
    strong_usd_per_1k_cached_input: Optional[float] = None

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
except Exception as e:
    logger.critical(f"Configuration Error. Missing or invalid environment variables:\n{e}")
    raise SystemExit(1)
