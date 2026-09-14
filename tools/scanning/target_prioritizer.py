"""Deterministic scan target selection."""

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)


async def prioritize_targets(
    graph_resolver: Any,
    max_targets: int,
    domain_filter: str | None = None,
    file_filter: str | None = None,
    vendor_folders: list[str] | None = None,
    application_roots: list[str] | None = None,
) -> list[str]:
    """Select scan targets through the graph resolver without LLM ranking."""
    logger.info(
        "Starting target prioritization (max=%s, domain=%s, file=%s)",
        max_targets,
        domain_filter,
        file_filter,
    )
    try:
        targets = graph_resolver.get_prioritized_targets(
            max_targets=max_targets,
            domain_filter=domain_filter,
            file_filter=file_filter,
            vendor_folders=vendor_folders,
            application_roots=application_roots,
        )
        logger.info("Target selection complete: %d targets", len(targets))
        return targets
    except asyncio.CancelledError:
        logger.warning("Prioritization was cancelled.")
        raise
    except Exception:
        logger.exception("Target selection failed")
        return []
