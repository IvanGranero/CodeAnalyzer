import logging
from collections.abc import Callable
from typing import Any

from tools.scanning.reporter import ScanReporter

logger = logging.getLogger(__name__)


def generate_final_report(
    all_reports: dict[str, dict[str, Any]],
    reporter: ScanReporter,
    output: Callable[[str], None] | None = print,
) -> None:
    """Generate reports and optionally send terminal summary text to a sink."""
    if not all_reports:
        return

    if output is not None:
        output("\n" + "=" * 60)
    logger.info("FINAL SCAN SUMMARY:")
    if output is not None:
        output("=" * 60)

    vuln_count = 0
    for func, report in all_reports.items():
        if report.get("vulnerability_found"):
            vuln_count += 1
            logger.warning(f"🚨 [{report.get('severity', 'HIGH').upper()}] {func}")
            reporter.generate_individual_report(func, report)

    if vuln_count > 0:
        logger.info(f"✅ Generated {vuln_count} individual Markdown reports in the 'reports/' directory.")
    else:
        logger.info("✅ No vulnerabilities were found in the scanned targets.")
    if output is not None:
        output("=" * 60 + "\n")

    if hasattr(reporter, 'generate_consolidated_reports'):
        reporter.generate_consolidated_reports(all_reports)
