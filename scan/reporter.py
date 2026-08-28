import os
import json
import logging
from datetime import datetime
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class ScanReporter:
    """Generates a single, consolidated Markdown, SARIF, and raw JSON report."""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def _byte_to_line_number(self, file_path: str, byte_offset: int) -> int:
        if not os.path.exists(file_path): return 1
        try:
            with open(file_path, 'rb') as f:
                return f.read(byte_offset).count(b'\n') + 1
        except Exception: return 1

    def _parse_file_path(self, uri: str) -> str:
        """Robustly cleans file:// URIs into valid local filesystem paths."""
        if not uri or uri == "Unknown": 
            return "Unknown"
            
        file_path = uri
        
        # Strip the file:// protocol
        if file_path.startswith("file://"):
            file_path = file_path[7:]
            
        # Fix Windows drive letter formatting (e.g., /C:/Users/... -> C:/Users/...)
        if os.name == 'nt' and file_path.startswith('/') and ':' in file_path:
            file_path = file_path[1:]
            
        return os.path.normpath(file_path)

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
            byte_span_str = metadata.get("ByteSpan")
            if isinstance(byte_span_str, str) and '-' in byte_span_str:
                start_byte = int(byte_span_str.split('-')[0])
            else:
                start_byte = 0 # Default to 0 if ByteSpan is None or malformed
            
            line = self._byte_to_line_number(file_path, start_byte)
            
            md.append("---")
            md.append(f"## 🚨 {report.get('severity', 'Unknown')}: Vulnerability in `{func}`")
            md.append(f"**File:** `{file_path}` (Line {line})")
            md.append("\n**Details:**")
            md.append(f"> {report.get('details', 'No details provided.')}\n")

            exploit_data = report.get("exploit_validation")
            if exploit_data:
                status = exploit_data.get("status", "unknown")
                icon = "💀" if status == "success" else "🛡️"
                md.append(f"\n### {icon} Exploit Validation: {status.upper()}")
                md.append(f"**Rationale:** {exploit_data.get('rationale', 'N/A')}")
                if status == "success" and "final_payload" in exploit_data:
                    md.append(f"**Verified Payload:** `{exploit_data.get('final_payload')}`\n")
              
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
            file_path = self._parse_file_path(metadata.get("FilePath"))
            
            # --- FIX: Safely handle None for ByteSpan in SARIF generation ---
            byte_span_str = metadata.get("ByteSpan")
            if isinstance(byte_span_str, str) and '-' in byte_span_str:
                start_byte = int(byte_span_str.split('-')[0])
            else:
                start_byte = 0 # Default to 0 if ByteSpan is None or malformed
                
            line = self._byte_to_line_number(file_path, start_byte)

            relative_path = os.path.relpath(file_path, os.getcwd()).replace("\\", "/")
            file_uri = f"file:///{relative_path}" if os.name == 'nt' else f"file://{relative_path}"

            severity_level = "note"
            sev = report.get("severity", "").lower()
            if sev in ["critical", "high"]: 
                severity_level = "error"
            elif sev == "medium": 
                severity_level = "warning"

            message_text = f"Vulnerability in {func}: {report.get('details', '')}"
            exploit_data = report.get("exploit_validation")
            if exploit_data:
                status = exploit_data.get("status", "unknown").upper()
                message_text += f"\n\n[Exploit Validation: {status}]\nRationale: {exploit_data.get('rationale', 'N/A')}"
                if status == "SUCCESS" and "final_payload" in exploit_data:
                    message_text += f"\nVerified Payload: {exploit_data.get('final_payload')}"

            sarif_results.append({
                "ruleId": "AUTOSAR-SEC-01",
                "level": severity_level,
                "message": {"text": f"Vulnerability in {func}: {report.get('details', '')}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": file_uri}, "region": {"startLine": line}}}]
            })

        sarif = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "AutoSAR-Multi-Agent-Scanner", "rules": [{"id": "AUTOSAR-SEC-01"}]}}, "results": sarif_results}]
        }
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(sarif, f, indent=2)
            logger.info(f"Consolidated SARIF report saved to '{filepath}'")
        except Exception as e:
            logger.error(f"Failed to save SARIF report: {e}")
