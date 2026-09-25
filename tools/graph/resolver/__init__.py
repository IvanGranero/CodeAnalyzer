"""Ordered Neo4j enrichment passes composed into the public graph resolver."""

import logging
from typing import Any

from tools.graph.resolver.concurrency import ConcurrencyMixin
from tools.graph.resolver.dangerous_sinks import DangerousSinksMixin
from tools.graph.resolver.dcm_did import DcmDidMixin
from tools.graph.resolver.macro_aliases import MacroAliasMixin
from tools.graph.resolver.prioritization import PrioritizationMixin
from tools.graph.resolver.rte_data_flow import RteDataFlowMixin
from tools.graph.resolver.runnables import RunnableBindingMixin
from tools.graph.resolver.serialization import SerializationMixin
from tools.graph.resolver.stub_pruning import StubPruningMixin
from tools.graph.resolver.uds_taint import UdsTaintMixin

logger = logging.getLogger(__name__)


class GraphResolver(
    DcmDidMixin,
    MacroAliasMixin,
    StubPruningMixin,
    RunnableBindingMixin,
    ConcurrencyMixin,
    UdsTaintMixin,
    RteDataFlowMixin,
    DangerousSinksMixin,
    SerializationMixin,
    PrioritizationMixin,
):
    """
    Executes Post-Ingestion graph completion passes.
    Bakes semantic meaning (taint, data flow, dead code, concurrency) directly into Neo4j.

    Each resolution pass lives in its own module under graph/resolver/ (one
    responsibility per file, mirroring the app/ phase split) and is mixed into this
    single class so every existing caller (`graph_manager.resolver.<method>`) keeps
    working unchanged -- this is a pure structural move, no behavior changed.
    """

    def __init__(self, db: Any):
        self.db = db
        self.discovery_context: dict[str, Any] = {}

    def set_discovery_context(self, context: dict[str, Any] | None) -> None:
        """Make bounded discovery evidence available to resolver passes."""
        self.discovery_context = dict(context or {})
        logger.info(
            "Resolver discovery context: MCU=%s vendor=%s modules=%d structures=%d",
            self.discovery_context.get("mcu", "unknown"),
            self.discovery_context.get("vendor", "unknown"),
            len(self.discovery_context.get("modules", [])),
            len(self.discovery_context.get("config_structures", [])),
        )

    def run_all_passes(self):
        """
        Executes the full suite of resolution passes in the correct order.

        Later passes depend on earlier ones (e.g. _resolve_data_races reads
        OS_LOCK_ACTION edges written by _resolve_os_concurrency). Each pass used to
        swallow its own exceptions and continue, so a mid-run outage (a transient
        Neo4j error, for instance) would silently leave every downstream pass
        computing over a half-resolved graph with no visible failure. Passes still run
        to completion (so one broken pass doesn't hide unrelated failures in others),
        but any failure is now collected and raised at the end so the caller (run.py)
        knows resolution did not fully succeed instead of proceeding to scan a
        half-resolved graph.
        """
        logger.info("=== Starting Graph Resolution & Completion Passes ===")
        passes = [
            
            
            
            self._resolve_dcm_did_table_entries,
            self._resolve_macro_call_aliases,
            self._prune_local_variable_stubs,
            self._bind_runnables_to_tasks,
            self._resolve_os_concurrency,
            self._resolve_uds_taint,
            self._resolve_dcm_security_requirements,
            
            
            self._flag_dead_code,
            self._resolve_rte_data_flow,
            self._flag_dangerous_sinks,
            self._resolve_data_races,
        ]
        failures = []
        for pass_fn in passes:
            pass_name = pass_fn.__name__
            before = self._relationship_counts()
            logger.debug(
                "Resolver pass %s before: relationships=%d by_type=%s",
                pass_name,
                before["total"],
                before["by_type"],
            )
            try:
                pass_fn()
            except Exception as e:
                failures.append((pass_fn.__name__, e))
            after = self._relationship_counts()
            logger.debug(
                "Resolver pass %s after: relationships=%d delta=%+d by_type=%s",
                pass_name,
                after["total"],
                after["total"] - before["total"],
                after["by_type"],
            )
        if failures:
            summary = "; ".join(f"{name}: {err}" for name, err in failures)
            logger.error(f"=== Graph Resolution FAILED for {len(failures)} pass(es): {summary} ===")
            raise RuntimeError(f"Graph resolution failed for pass(es): {summary}")
        logger.info("=== Graph Resolution Complete ===")

    def _relationship_counts(self) -> dict[str, Any]:
        """Return deterministic relationship totals for resolver-stage diagnostics."""
        query = """
        MATCH ()-[r]->()
        RETURN type(r) AS relationship_type, count(r) AS relationship_count
        ORDER BY relationship_type
        """
        try:
            with self.db.driver.session() as session:
                rows = session.run(query).data()
            by_type = {
                row["relationship_type"]: row["relationship_count"]
                for row in rows
            }
            return {"total": sum(by_type.values()), "by_type": by_type}
        except Exception as exc:
            logger.warning("Unable to collect resolver relationship counts: %s", exc)
            return {"total": -1, "by_type": {}}
