import logging
from dataclasses import dataclass

from llm.service import LLMService
from llm.router import TieredLLMService
from llm.runtime import AgentRuntime
from tools.graph.manager import GraphManager
from tools.graph.resolver import GraphResolver
from config import settings
from llm.tracker import TokenTracker

logger = logging.getLogger(__name__)

@dataclass
class AppContext:
    llm: TieredLLMService
    runtime: AgentRuntime
    graph: GraphManager


def build_app_context() -> AppContext:
    """Bootstraps the LLM service and graph manager from validated Settings."""
    tracker = TokenTracker()
    cheap_llm = LLMService(
        api_key=settings.cheap_subscription_key,
        model_name=settings.cheap_model_id,
        base_url=settings.cheap_base_url,
        default_headers=settings.cheap_default_headers,
        extra_query=settings.cheap_extra_query,
        pricing=settings.cheap_token_pricing,
        tracker=tracker,
    )
    strong_llm = LLMService(
        api_key=settings.strong_subscription_key,
        model_name=settings.strong_model_id,
        base_url=settings.strong_base_url,
        default_headers=settings.strong_default_headers,
        extra_query=settings.strong_extra_query,
        pricing=settings.strong_token_pricing,
        tracker=tracker,
    )
    graph = GraphManager(
        uri=settings.neo4j_uri,
        user=settings.neo4j_user,
        password=settings.neo4j_password,
    )
    graph.resolver = GraphResolver(graph.db)
    llm = TieredLLMService(cheap_llm, strong_llm)
    return AppContext(llm=llm, runtime=AgentRuntime(llm), graph=graph)


def shutdown(app_context: AppContext) -> None:
    if hasattr(app_context.llm, "log_summary"):
        app_context.llm.log_summary()
    elif hasattr(app_context.llm, "tracker"):
        app_context.llm.tracker.log_summary()
    app_context.graph.close()
    logger.info("Database connection closed.")
