"""Compatibility projection for current and legacy scan report findings."""

from typing import Any


def stringify(value: Any, default: str = "No details provided.") -> str:
    if value is None or value == "":
        return default
    if isinstance(value, list):
        items = [str(item) for item in value if item not in (None, "")]
        return "\n".join(f"- {item}" for item in items) if items else default
    return str(value)


def supported_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    findings = report.get("findings")
    if isinstance(findings, list):
        supported = [
            finding for finding in findings
            if isinstance(finding, dict) and finding.get("status") == "supported"
        ]
        if supported:
            return supported
    return [{
        "vulnerability_type": "unspecified",
        "severity": report.get("severity", "Unknown"),
        "confidence": report.get("confidence", "unknown"),
        "evidence": report.get("details", "No details provided."),
        "mitigation": None,
    }]
