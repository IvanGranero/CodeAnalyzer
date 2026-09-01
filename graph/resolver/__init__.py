import logging
from typing import Any

from graph.resolver.concurrency import ConcurrencyMixin
from graph.resolver.dangerous_sinks import DangerousSinksMixin
from graph.resolver.dcm_did import DcmDidMixin
from graph.resolver.macro_aliases import MacroAliasMixin
from graph.resolver.prioritization import PrioritizationMixin
from graph.resolver.rte_data_flow import RteDataFlowMixin
from graph.resolver.runnables import RunnableBindingMixin
from graph.resolver.serialization import SerializationMixin
from graph.resolver.stub_pruning import StubPruningMixin
from graph.resolver.uds_taint import UdsTaintMixin

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
            # _resolve_dcm_did_table_entries must run BEFORE _resolve_macro_call_aliases:
            # it needs to read the alias_target property off a "stub::<name>" node that
            # the alias pass deletes once it has redirected that stub's CALLS edges.
            self._resolve_dcm_did_table_entries,
            self._resolve_macro_call_aliases,
            self._prune_local_variable_stubs,
            self._bind_runnables_to_tasks,
            self._resolve_os_concurrency,
            self._resolve_uds_taint,
            self._flag_dead_code,
            self._resolve_rte_data_flow,
            self._flag_dangerous_sinks,
            self._resolve_data_races,
        ]
        failures = []
        for pass_fn in passes:
            try:
                pass_fn()
            except Exception as e:
                failures.append((pass_fn.__name__, e))
        if failures:
            summary = "; ".join(f"{name}: {err}" for name, err in failures)
            logger.error(f"=== Graph Resolution FAILED for {len(failures)} pass(es): {summary} ===")
            raise RuntimeError(f"Graph resolution failed for pass(es): {summary}")
        logger.info("=== Graph Resolution Complete ===")
