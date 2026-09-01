import logging
from typing import Dict

from scan.reporter import ScanReporter

logger = logging.getLogger(__name__)


def generate_final_report(all_reports: Dict[str, dict], reporter: ScanReporter) -> None:
    if not all_reports:
        return

    print("\n" + "=" * 60)
    logger.info("FINAL SCAN SUMMARY:")
    print("=" * 60)

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
    print("=" * 60 + "\n")

    if hasattr(reporter, 'generate_consolidated_reports'):
        reporter.generate_consolidated_reports(all_reports)
