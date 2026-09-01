import logging
from dataclasses import dataclass

from llm.service import LLMService
from graph.manager import GraphManager
from graph.resolver import GraphResolver

logger = logging.getLogger(__name__)


@dataclass
class AppContext:
    llm: LLMService
    graph: GraphManager


def build_app_context(settings) -> AppContext:
    """Bootstraps the LLM service and graph manager from validated Settings."""
    llm_service = LLMService(
        api_key=settings.genai_subscription_key,
        model_name=settings.strong_model_id,
        base_url=settings.strong_base_url,
        api_version=settings.strong_api_version,
        api_key_header=settings.genai_subscription_header,
        usd_per_1m_input=settings.strong_usd_input,
        usd_per_1m_output=settings.strong_usd_output,
    )
    graph = GraphManager(
        uri=settings.neo4j_uri,
        user=settings.neo4j_user,
        password=settings.neo4j_password,
    )
    graph.resolver = GraphResolver(graph.db)
    return AppContext(llm=llm_service, graph=graph)


def shutdown(app_context: AppContext) -> None:
    if hasattr(app_context.llm, "tracker"):
        app_context.llm.tracker.log_summary()
    app_context.graph.close()
    logger.info("Database connection closed.")
