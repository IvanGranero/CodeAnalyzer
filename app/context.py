import logging
from dataclasses import dataclass

from llm.service import LLMService
from llm.router import TieredLLMService
from tools.graph.manager import GraphManager
from tools.graph.resolver import GraphResolver
from tools.scanning.scheduler import ScanBudget

logger = logging.getLogger(__name__)


@dataclass
class AppContext:
    llm: TieredLLMService
    graph: GraphManager
    scan_budget: ScanBudget


def build_app_context(settings) -> AppContext:
    """Bootstraps the LLM service and graph manager from validated Settings."""
    cheap_llm = LLMService(
        api_key=settings.genai_subscription_key,
        model_name=settings.cheap_model_id,
        base_url=settings.cheap_base_url,
        api_version=settings.cheap_api_version,
        api_key_header=settings.genai_subscription_header,
        usd_per_1m_input=settings.cheap_usd_input,
        usd_per_1m_output=settings.cheap_usd_output,
    )
    strong_llm = LLMService(
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
    budget = ScanBudget(
        max_concurrent=settings.scan_max_concurrent_llm_calls,
        max_calls=settings.scan_max_calls,
        max_tokens=settings.scan_max_tokens,
        max_cost_usd=settings.scan_max_cost_usd,
    )
    return AppContext(llm=TieredLLMService(cheap_llm, strong_llm), graph=graph, scan_budget=budget)


def shutdown(app_context: AppContext) -> None:
    if hasattr(app_context.llm, "log_summary"):
        app_context.llm.log_summary()
    elif hasattr(app_context.llm, "tracker"):
        app_context.llm.tracker.log_summary()
    app_context.graph.close()
    logger.info("Database connection closed.")
