import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

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


def build_discovery_context(discovery: Mapping[str, Any]) -> dict[str, Any]:
    """Return bounded repository-level discovery facts for downstream agents."""
    def values(value: Any, limit: int = 24) -> list[str]:
        if isinstance(value, dict):
            value = value.get("items", value.get("names", []))
        if not isinstance(value, list):
            return []
        result = []
        seen = set()
        for item in value:
            if isinstance(item, dict):
                item = item.get("path", item.get("name", item.get("domain", "")))
            text = str(item).strip()
            if text and text.casefold() not in seen:
                result.append(text)
                seen.add(text.casefold())
        if len(result) > limit:
            return [*result[:limit], f"... (+{len(result) - limit} more)"]
        return result

    platform = {
        name: discovery[source]
        for name, source in (
            ("mcu", "mcu_guess"),
            ("silicon_vendor", "silicon_vendor"),
            ("ecu_role", "ecu_role"),
            ("autosar_stack_vendor", "autosar_stack_vendor"),
            ("autosar_stack_product", "autosar_stack_product"),
        )
        if discovery.get(source) not in (None, "")
    }
    architecture = {
        name: items
        for name, source in (
            ("modules", "modules"),
            ("configuration_structures", "config_structures"),
            ("diagnostics", "diagnostics"),
            ("hsm", "hsm"),
            ("communications", "comms"),
            ("software_components", "swc"),
            ("rte", "rte"),
        )
        if (items := values(discovery.get(source)))
    }
    scope = {
        name: items
        for name, source in (
            ("application_roots", "application_roots"),
            ("application_domains", "app_domain_guesses"),
            ("vendor_folders", "vendor_folders"),
            ("configuration_extensions", "config_file_extensions"),
            ("configuration_filename_patterns", "config_filename_patterns"),
        )
        if (items := values(discovery.get(source)))
    }
    manifest = discovery.get("repository_manifest")
    repository = {}
    if isinstance(manifest, dict):
        repository = {
            key: manifest[key]
            for key in ("root", "directory_count", "file_count")
            if manifest.get(key) is not None
        }
        top_level_directories = values(manifest.get("top_level_directories"))
        if top_level_directories:
            repository["top_level_directories"] = top_level_directories
    repository_name = discovery.get("repository_name")
    if repository_name and "root" not in repository:
        repository["root"] = repository_name
    repository["configuration_file_count"] = discovery.get(
        "configuration_file_count", len(discovery.get("config_files") or [])
    )
    repository["application_folder_count"] = discovery.get(
        "application_folder_count", len(discovery.get("app_folders") or [])
    )

    confidence = discovery.get("confidence", discovery.get("confidence_scores", {}))
    if not isinstance(confidence, dict):
        confidence = {}
    return {
        "schema_version": "1.0",
        "platform": platform,
        "architecture": architecture,
        "scope": scope,
        "repository": repository,
        "confidence": {
            key: value
            for key, value in confidence.items()
            if isinstance(value, (str, int, float, bool))
        },
    }


def build_app_context() -> AppContext:
    """Bootstraps the LLM service and graph manager from validated Settings."""
    tracker = TokenTracker()
    lite_llm = LLMService(
        api_key=settings.lite_subscription_key,
        model_name=settings.lite_model_id,
        deployment=settings.lite_deployment,
        base_url=settings.lite_base_url,
        default_headers=settings.lite_headers,
        api_version=settings.lite_api_version,
        api_style=settings.lite_api_style,
        pricing=settings.lite_token_pricing,
        tracker=tracker,
    )
    medium_llm = LLMService(
        api_key=settings.medium_subscription_key,
        model_name=settings.medium_model_id,
        deployment=settings.medium_deployment,
        base_url=settings.medium_base_url,
        default_headers=settings.medium_headers,
        api_version=settings.medium_api_version,
        api_style=settings.medium_api_style,
        pricing=settings.medium_token_pricing,
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
    llm = TieredLLMService(lite_llm, medium_llm, strong_llm)
    return AppContext(llm=llm, graph=graph)


def shutdown(app_context: AppContext) -> None:
    if hasattr(app_context.llm, "log_summary"):
        app_context.llm.log_summary()
    elif hasattr(app_context.llm, "tracker"):
        app_context.llm.tracker.log_summary()
    app_context.graph.close()
    logger.info("Database connection closed.")
