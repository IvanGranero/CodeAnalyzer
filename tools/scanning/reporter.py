import os
import json
import logging
import re
from datetime import datetime
from tools.reporting.location import SourceLocationResolver
from tools.reporting.finding_projection import stringify, supported_findings

logger = logging.getLogger(__name__)

class ScanReporter:
    """Generates a single, consolidated Markdown, SARIF, and raw JSON report."""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.locations = SourceLocationResolver()

    def _byte_to_line_number(self, file_path: str, byte_offset: int) -> int:
        return self.locations.line_from_span(file_path, str(byte_offset))

    def _parse_file_path(self, uri: str) -> str:
        return self.locations.parse_path(uri)

    @staticmethod
    def _stringify(value, default: str = "No details provided.") -> str:
        return stringify(value, default)

    @staticmethod
    def _supported_findings(report: dict) -> list:
        return supported_findings(report)

    def generate_consolidated_reports(self, all_scan_results: dict):
        """
        Generates one master Markdown and SARIF report containing all
        vulnerabilities found during the scan.
        """
        # Filter for only the reports that found vulnerabilities
        vulnerabilities = {
            func: report for func, report in all_scan_results.items()
            if report.get("vulnerability_found")
        }
        
        if not vulnerabilities:
            logger.info("No vulnerabilities found. Skipping report generation.")
            return
            
        logger.info(f"Consolidating {len(vulnerabilities)} vulnerabilities into master reports...")

        # Generate each consolidated report type
        self.save_raw_json(vulnerabilities)
        self.save_markdown_report(vulnerabilities)
        self.save_sarif_report(vulnerabilities)

    def save_raw_json(self, vulnerabilities: dict):
        """Saves one master raw JSON file."""
        filepath = os.path.join(self.output_dir, f"raw_findings_{self.timestamp}.json")
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(vulnerabilities, f, indent=2)
            logger.info(f"Raw findings saved to '{filepath}'")
        except Exception as e:
            logger.error(f"Failed to save JSON findings: {e}")

    def save_markdown_report(self, vulnerabilities: dict):
        """Saves one master human-readable Markdown report."""
        filepath = os.path.join(self.output_dir, f"Vulnerability_Report_{self.timestamp}.md")
        
        md = [f"# Security Vulnerability Report ({self.timestamp})\n"]
        
        for func, report in vulnerabilities.items():
            metadata = report.get("metadata", {})
            file_path = self._parse_file_path(metadata.get("FilePath"))
            
            # --- FIX: Safely handle None for ByteSpan ---
            location = self.locations.resolve(metadata.get("FilePath"), metadata.get("ByteSpan"))

            md.append("---")
            md.append(f"## 🚨 {report.get('severity', 'Unknown')}: Vulnerability in `{func}`")
            md.append(f"**File:** `{location.path}` (Line {location.line})")

            for finding in self._supported_findings(report):
                md.append(f"\n### [{finding.get('vulnerability_type', 'unspecified')}] {finding.get('severity', report.get('severity', 'Unknown'))} (confidence: {finding.get('confidence', 'unknown')})")
                md.append(f"> {self._stringify(finding.get('evidence'))}")
                if finding.get("mitigation"):
                    md.append(f"\n**Mitigation:** {finding['mitigation']}")
                if finding.get("graph_flag_agreement") is False:
                    md.append(f"\n**⚠️ Needs human review:** this finding's claim disagreed with the graph's own ground-truth flag.")

            exploit_data = report.get("exploit_validation")
            if exploit_data:
                status = exploit_data.get("status", "unknown")
                icon = "💀" if status == "success" else "🛡️"
                md.append(f"\n### {icon} Exploit Validation: {status.upper()}")
                md.append(f"**Rationale:** {exploit_data.get('rationale', 'N/A')}")
                if status == "success" and "final_payload" in exploit_data:
                    md.append(f"**Verified Payload:** `{exploit_data.get('final_payload')}`\n")
                md.append(f"**Deterministic Oracle Confirmed:** `{exploit_data.get('oracle_confirmed', False)}`")
                if exploit_data.get("exploit_chain"):
                    findings = [step.get("oracle_finding") for step in exploit_data["exploit_chain"] if step.get("oracle_finding")]
                    if findings:
                        md.append(f"**Oracle Findings:** {', '.join(findings)}")
              
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("\n".join(md))
            logger.info(f"Consolidated Markdown report saved to '{filepath}'")
        except Exception as e:
            logger.error(f"Failed to save Markdown report: {e}")

    def save_sarif_report(self, vulnerabilities: dict):
        """Saves one master industry-standard SARIF v2.1.0 file."""
        filepath = os.path.join(self.output_dir, f"results_{self.timestamp}.sarif")
        
        sarif_results = []
        for func, report in vulnerabilities.items():
            metadata = report.get("metadata", {})
            # --- FIX: Safely handle None for ByteSpan in SARIF generation ---
            location = self.locations.resolve(metadata.get("FilePath"), metadata.get("ByteSpan"))

            exploit_data = report.get("exploit_validation")
            exploit_suffix = ""
            if exploit_data:
                status = exploit_data.get("status", "unknown").upper()
                exploit_suffix = f"\n\n[Exploit Validation: {status}]\nRationale: {exploit_data.get('rationale', 'N/A')}"
                if status == "SUCCESS" and "final_payload" in exploit_data:
                    exploit_suffix += f"\nVerified Payload: {exploit_data.get('final_payload')}"
                exploit_suffix += f"\nDeterministic Oracle Confirmed: {exploit_data.get('oracle_confirmed', False)}"

            # One SARIF result PER FINDING, not per function -- a function with multiple
            # independently-real vulnerability classes (e.g. buffer overflow AND a data
            # race) previously collapsed into a single result and every class but one was
            # invisible to any SARIF-consuming tool (GitHub Security, SonarQube, etc.).
            for finding in self._supported_findings(report):
                sev = str(finding.get("severity", report.get("severity", ""))).lower()
                severity_level = "note"
                if sev in ("critical", "high"):
                    severity_level = "error"
                elif sev == "medium":
                    severity_level = "warning"

                vuln_type = finding.get("vulnerability_type", "unspecified")
                message_text = f"[{vuln_type}] Vulnerability in {func}: {self._stringify(finding.get('evidence'), default='')}"
                if finding.get("mitigation"):
                    message_text += f"\nMitigation: {finding['mitigation']}"
                message_text += exploit_suffix

                # Defense in depth: vulnerability_type is supposed to be a short
                # canonical slug (see llm/prompts.json), but a SARIF ruleId must stay a
                # stable, punctuation-free identifier even if a model drifts and emits
                # a prose phrase -- sanitize instead of embedding raw spaces/punctuation.
                rule_slug = re.sub(r"[^A-Za-z0-9_]+", "_", str(vuln_type)).strip("_").upper()
                sarif_results.append({
                    "ruleId": f"AUTOSAR-SEC-{rule_slug}" if rule_slug and vuln_type != "unspecified" else "AUTOSAR-SEC-01",
                    "level": severity_level,
                    "message": {"text": message_text},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": location.file_uri}, "region": {"startLine": location.line}}}]
                })

        rule_ids = sorted({r["ruleId"] for r in sarif_results}) or ["AUTOSAR-SEC-01"]
        sarif = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "AutoSAR-Multi-Agent-Scanner", "rules": [{"id": rid} for rid in rule_ids]}}, "results": sarif_results}]
        }
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(sarif, f, indent=2)
            logger.info(f"Consolidated SARIF report saved to '{filepath}'")
        except Exception as e:
            logger.error(f"Failed to save SARIF report: {e}")

    def generate_individual_report(self, func_name: str, report: dict):
        """Generates a dedicated Markdown report tracing the full Tri-Agent chain for a single vulnerability."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(self.output_dir, f"VULN_{func_name}_{timestamp}.md")
        
        md = [f"# Vulnerability Report: `{func_name}`\n"]
        md.append(f"**Severity:** {report.get('severity', 'UNKNOWN').upper()} | **Confidence:** {report.get('confidence', 'UNKNOWN').upper()}\n")
        
        metadata = report.get("metadata", {})
        md.append("### 📍 Location & Context")
        md.append(f"- **File:** `{metadata.get('FilePath', 'Unknown')}`")
        md.append(f"- **Byte Span:** `{metadata.get('ByteSpan', 'Unknown')}`")
        if metadata.get('DIDs'):
            md.append(f"- **Target DIDs:** `{', '.join(metadata.get('DIDs', []))}`")
        md.append("\n---\n")
        
        md.append("## 1️⃣ Triage Agent (Threat Model Generator)")
        triage_dir = report.get("triage_directive", "No triage directive recorded.")
        md.append(f"> {triage_dir}\n")
        
        md.append("## 2️⃣ Deep Scan Agent (Static Analysis Prover)")
        for finding in self._supported_findings(report):
            md.append(f"\n### [{finding.get('vulnerability_type', 'unspecified')}] {finding.get('severity', report.get('severity', 'Unknown'))} (confidence: {finding.get('confidence', 'unknown')})")
            md.append(self._stringify(finding.get("evidence")))
            if finding.get("mitigation"):
                md.append(f"\n**Mitigation:** {finding['mitigation']}")
            if finding.get("graph_flag_agreement") is False:
                md.append("\n**⚠️ Needs human review:** this finding's claim disagreed with the graph's own ground-truth flag.")
        if report.get("graph_contradictions"):
            md.append("\n**Graph/LLM contradictions flagged during this scan:**")
            for c in report["graph_contradictions"]:
                md.append(f"- {c}")
        md.append("\n---\n")
        
        exploit_val = report.get("exploit_validation")
        md.append("## 3️⃣ Exploit Orchestrator (Dynamic Validation)")
        if not exploit_val:
            md.append("*No dynamic exploit validation was run for this target.*")
        else:
            status = exploit_val.get('status', 'Unknown').upper()
            status_icon = "💀" if status == "SUCCESS" else "🛡️"
            md.append(f"**Final Status:** {status_icon} **{status}**")
            md.append(f"**Strategist Rationale:** {exploit_val.get('rationale', 'None')}\n")
            
            chain = exploit_val.get("exploit_chain", [])
            if chain:
                md.append("### Execution Chain Log")
                for step in chain:
                    md.append(f"#### Attempt {step.get('attempt')}")
                    
                    if 'tx_payload' in step:
                        md.append(f"- **Crafted Payload:** `{step.get('tx_payload')}` (Delivery: *{step.get('delivery_method', 'sequential')}*)")
                    
                    if 'oracle_finding' in step:
                        md.append(f"- **Oracle Finding:** `{step.get('oracle_finding')}`")
                        
                    if 'analysis' in step:
                        md.append(f"- **Analyzer Observation:** {step['analysis'].get('observation', 'None')}")
                        
                    if 'error' in step:
                        md.append(f"- **Error:** `{step.get('error')}`")
                    md.append("")
                    
        # Render before opening the file: open(..., "w") truncates immediately, so if
        # rendering failed partway through and we opened first, a pre-existing report
        # (or a fresh empty file) would be left silently blank instead of surfacing the
        # error. _stringify above should make this join always succeed on well-formed
        # findings, but a malformed one should still fail loud rather than truncate.
        try:
            content = "\n".join(md)
        except Exception as e:
            logger.error(f"Failed to render individual report for {func_name}: {e}")
            return

        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(content)
        except Exception as e:
            logger.error(f"Failed to write individual report for {func_name}: {e}")