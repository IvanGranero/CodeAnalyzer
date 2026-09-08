import logging
import os
from typing import Any, Dict

logger = logging.getLogger(__name__)


class PrioritizationMixin:
    """Deterministic (non-LLM) selection of the highest-risk scan targets."""

    def get_prioritized_targets(self, max_targets: int, domain_filter: str = None, file_filter: str = None) -> list:
        # domain_filter/file_filter previously reached Cypher via f-string interpolation
        # (a Cypher-injection vector -- both values can originate from CLI args / the
        # Phase-1 discovery LLM output). Bound as query parameters instead; only the
        # LIMIT integer (validated as int by argparse/callers) is still interpolated.
        cypher_filter = ""
        params: Dict[str, Any] = {}

        if domain_filter:
            cypher_filter += " AND (f.storage_uri CONTAINS $domain_slash OR f.storage_uri CONTAINS $domain_backslash)"
            params["domain_slash"] = f"/{domain_filter}/"
            params["domain_backslash"] = f"\\{domain_filter}\\"

        if file_filter:
            params["file_basename"] = os.path.basename(file_filter)
            cypher_filter += " AND f.storage_uri CONTAINS $file_basename"

        query = f"""
        MATCH (f:Function)
        // 1. STRICT FILTERS: Must be app code, not dead, not a stub, not a header
        WHERE coalesce(f.is_vendor_code, false) = false
          AND coalesce(f.is_dead_code, false) = false
          AND NOT f:Stub
          AND NOT f.storage_uri ENDS WITH '.h'
          {cypher_filter}

        // 2. RISK FILTERS: Only pick functions that actually have attack surface
        AND (
            coalesce(f.has_data_race_risk, false) = true OR
            coalesce(f.tainted_by_uds, false) = true OR
            coalesce(f.is_dangerous_sink, false) = true OR
            coalesce(f.is_hardware_entry, false) = true
        )

        RETURN f.name AS FunctionName,
               coalesce(f.has_data_race_risk, false) AS DataRace,
               coalesce(f.tainted_by_uds, false) AS UdsTaint
        ORDER BY DataRace DESC, UdsTaint DESC
        """

        # If max_targets is 0 (uncapped), we drop the LIMIT clause entirely.
        # max_targets is an int from argparse/internal callers, never user-controlled text.
        if max_targets > 0:
            query += " LIMIT $max_targets"
            params["max_targets"] = max_targets

        try:
            with self.db.driver.session() as session:
                results = session.run(query, **params).data()
                return [r["FunctionName"] for r in results]
        except Exception as e:
            logger.error(f"Failed to get prioritized targets: {e}")
            return []
