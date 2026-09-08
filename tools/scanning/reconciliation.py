"""Reconcile model findings with authoritative graph evidence."""

import json
import logging
from typing import Any

from tools.scanning.contracts import EvidenceReference

logger = logging.getLogger(__name__)

RACE_KEYWORDS = ("race", "concurrency")
VALIDATION_KEYWORDS = ("validation", "injection", "access_control")
UNREACHABLE_EVIDENCE_KEYWORDS = (
    "unreachable",
    "never called",
    "dead code",
    "no caller",
    "internal-only",
    "internal only",
)


def reconcile_finding(finding: dict[str, Any], graph_json: str) -> dict[str, Any]:
    """Normalize a finding and flag disagreements with graph ground truth."""
    if not isinstance(finding, dict):
        return finding

    try:
        graph_data = json.loads(graph_json)
        graph_function = graph_data.get("function", {}) or {}
        graph_uds_sources = graph_data.get("sources", {}).get("uds", []) or []
    except (ValueError, json.JSONDecodeError, AttributeError):
        graph_data, graph_function, graph_uds_sources = {}, {}, []

    graph_has_data_race_risk = bool(graph_function.get("has_data_race_risk", False))
    graph_is_dead_code = bool(graph_function.get("is_dead_code", False))
    graph_has_authoritative_uds_trigger = any(
        isinstance(trigger, dict) and trigger.get("source") == "dcm_did_table"
        for trigger in graph_uds_sources
    )
    graph_is_reachable = not graph_is_dead_code or graph_has_authoritative_uds_trigger

    references = finding.setdefault("evidence_references", [])
    if isinstance(references, list) and not references:
        provenance = graph_data.get("provenance", {})
        references.append(EvidenceReference(
            source="graph_json",
            location=provenance.get("retrieval_pointer"),
            provenance=provenance.get("query"),
            resolution="serialized_neighborhood",
        ).model_dump(mode="json"))
        for path in graph_data.get("graph", {}).get("paths", []):
            if path.get("status") == "verified":
                references.append(EvidenceReference(
                    source="graph_path",
                    location=path.get("path"),
                    provenance=path.get("provenance"),
                    resolution=path.get("resolution"),
                ).model_dump(mode="json"))
                break

    finding["vulnerability_found"] = finding.get("status") == "supported"
    if not finding["vulnerability_found"]:
        return finding

    vulnerability_type = str(finding.get("vulnerability_type", "")).lower()
    contradiction = None

    if any(keyword in vulnerability_type for keyword in RACE_KEYWORDS):
        claimed_agreement = finding.get("graph_flag_agreement")
        if claimed_agreement not in (True, False):
            finding["graph_flag_agreement"] = graph_has_data_race_risk
            contradiction = (
                f"{finding.get('vulnerability_type')}: graph_flag_agreement missing "
                f"(graph has_data_race_risk={graph_has_data_race_risk})"
            )
        elif bool(claimed_agreement) != graph_has_data_race_risk:
            contradiction = (
                f"{finding.get('vulnerability_type')}: model claimed "
                f"graph_flag_agreement={claimed_agreement} but "
                f"graph has_data_race_risk={graph_has_data_race_risk}"
            )

    elif any(keyword in vulnerability_type for keyword in VALIDATION_KEYWORDS):
        evidence = str(finding.get("evidence", "")).lower()
        premised_on_unreachability = any(
            keyword in evidence for keyword in UNREACHABLE_EVIDENCE_KEYWORDS
        )
        if premised_on_unreachability:
            claimed_agreement = finding.get("graph_flag_agreement")
            actual_agreement = not graph_is_reachable
            if claimed_agreement not in (True, False):
                finding["graph_flag_agreement"] = actual_agreement
                contradiction = (
                    f"{finding.get('vulnerability_type')}: graph_flag_agreement missing "
                    f"(graph is_dead_code={graph_is_dead_code}, "
                    f"authoritative_uds_trigger={graph_has_authoritative_uds_trigger})"
                )
            elif bool(claimed_agreement) != actual_agreement:
                contradiction = (
                    f"{finding.get('vulnerability_type')}: model claimed unreachability "
                    f"(graph_flag_agreement={claimed_agreement}) but "
                    f"graph is_dead_code={graph_is_dead_code} with "
                    f"authoritative_uds_trigger={graph_has_authoritative_uds_trigger}"
                )

    if contradiction:
        finding["needs_human_review"] = True
        finding["graph_contradictions"] = [contradiction]
        logger.warning("Deep-scan/graph disagreement: %s", contradiction)

    return finding