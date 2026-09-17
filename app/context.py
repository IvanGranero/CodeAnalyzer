import logging
from dataclasses import dataclass

from llm.service import LLMService
from llm.router import TieredLLMService
from tools.graph.manager import GraphManager
from config import settings
from llm.tracker import TokenTracker

logger = logging.getLogger(__name__)

@dataclass
class AppContext:
    llm: TieredLLMService
    graph: GraphManager


def build_app_context() -> AppContext:
    """Bootstraps the LLM service and graph manager from validated Settings."""
    tracker = TokenTracker()
    cheap_llm = LLMService(
        api_key=settings.cheap_subscription_key,
        model_name=settings.cheap_model_id,
        deployment=settings.cheap_deployment,
        base_url=settings.cheap_base_url,
        default_headers=settings.cheap_headers,
        api_version=settings.cheap_api_version,
        api_style=settings.cheap_api_style,
        pricing=settings.cheap_token_pricing,
        tracker=tracker,
    )
    strong_llm = LLMService(
        api_key=settings.strong_subscription_key,
        model_name=settings.strong_model_id,
        deployment=settings.strong_deployment,
        base_url=settings.strong_base_url,
        default_headers=settings.strong_headers,
        api_version=settings.strong_api_version,
        api_style=settings.strong_api_style,
        pricing=settings.strong_token_pricing,
        tracker=tracker,
    )
    graph = GraphManager(
        uri=settings.neo4j_uri,
        user=settings.neo4j_user,
        password=settings.neo4j_password,
    )
    llm = TieredLLMService(cheap_llm, strong_llm)
    return AppContext(llm=llm, graph=graph)


def shutdown(app_context: AppContext) -> None:
    if hasattr(app_context.llm, "log_summary"):
        app_context.llm.log_summary()
    elif hasattr(app_context.llm, "tracker"):
        app_context.llm.tracker.log_summary()
    app_context.graph.close()
    logger.info("Database connection closed.")
