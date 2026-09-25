import os
import sys
import logging
from threading import Event
from pathlib import Path
from typing import Any
from tools.graph.manager import GraphManager
from tools.ingestion.builder import GraphPayloadBuilder
from tools.ingestion.parser import ASTParser
from tools.ingestion.arxml_parser import ARXMLParser

from tools.ingestion.rte_json_parser import RteJsonParser 
from tools.ingestion.dispatch import ConfigParserDispatcher
from tools.ingestion.source_discovery import discover_source_files, is_vendor_file

logger = logging.getLogger(__name__)

class IngestionPipeline:
    def __init__(self, target_dir: str, graph_manager: GraphManager):
        self.target_dir = os.path.abspath(target_dir)
        self.graph_manager = graph_manager
        self.builder = GraphPayloadBuilder(batch_size=5000)
        self.parser = ASTParser(self.builder)
        self.arxml_parser = ARXMLParser(self.builder)
        
        self.rte_json_parser = RteJsonParser(self.builder)
        self.config_dispatcher = ConfigParserDispatcher({
            ".arxml": self.arxml_parser,
            ".xml": self.arxml_parser,
            ".json": self.rte_json_parser,
        })

    def run(
        self,
        vendor_folders: list = None,
        config_files: list = None,
        vendor_parse_mode: str = "full",
        discovery_context: dict[str, Any] | None = None,
        cancel_event: Event | None = None,
    ) -> dict[str, Any]:
        if vendor_folders is None:
            vendor_folders = []
        if config_files is None:
            config_files = []
            
        vendor_folders_normalized = [vf.strip().strip('/\\').lower() for vf in vendor_folders]
        if vendor_parse_mode not in {"full", "structure", "application_only"}:
            raise ValueError(
                "vendor_parse_mode must be one of: full, structure, application_only"
            )
        
        logger.info(f"Starting pipeline. Tagging Vendor/Generated folders: {vendor_folders_normalized}")
        report: dict[str, Any] = {
            "config_files_seen": 0,
            "config_files_parsed": 0,
            "config_files_missing": [],
            "config_files_outside_target": [],
            "config_files_unsupported": [],
            "source_files_seen": 0,
            "source_files_parsed": 0,
            "source_files_failed": [],
            "vendor_files": 0,
            "application_files": 0,
            "parser_edges_emitted": 0,
            "vendor_parse_mode": vendor_parse_mode,
            "discovery_context": discovery_context or {},
        }
        self._active_report = report
        report["parser_coverage"] = {
            "by_extension": {},
            "by_parser": {},
            "by_status": {},
            "unsupported_extensions": [],
            "discovery_modules": list((discovery_context or {}).get("modules", [])),
            "discovery_config_structures": list(
                (discovery_context or {}).get("config_structures", [])
            ),
            "discovery_domains": list((discovery_context or {}).get("domains", [])),
            "domain_coverage": {},
        }
        
        
        if config_files:
            logger.info(f"Parsing {len(config_files)} OS/System configuration files...")
            report["config_files_seen"] = len(config_files)
            
            for config_file in config_files:
                normalized_config_path = os.path.normpath(config_file)
                target_root = Path(self.target_dir).resolve()
                full_path = (target_root / normalized_config_path).resolve()
                try:
                    full_path.relative_to(target_root)
                except ValueError:
                    logger.warning("Config file is outside target directory: %s", config_file)
                    report["config_files_outside_target"].append(config_file)
                    continue
                
                if full_path.exists():
                    logger.debug(f"Parsing config: {config_file}")
                    config_path = Path(full_path)
                    if self.config_dispatcher.parse(config_path):
                        report["config_files_parsed"] += 1
                        extension = config_path.suffix.lower()
                        coverage = report["parser_coverage"]["by_extension"]
                        coverage[extension] = coverage.get(extension, 0) + 1
                        parser_kind = self.config_dispatcher.classify(config_path)
                        by_parser = report["parser_coverage"]["by_parser"]
                        by_parser[parser_kind] = by_parser.get(parser_kind, 0) + 1
                        parse_result = self.config_dispatcher.result(config_path)
                        status = parse_result.get("status", "parsed")
                        by_status = report["parser_coverage"]["by_status"]
                        by_status[status] = by_status.get(status, 0) + 1
                        self._check_and_flush()
                    else:
                        report["config_files_unsupported"].append(config_file)
                        extension = config_path.suffix.lower()
                        if extension not in report["parser_coverage"]["unsupported_extensions"]:
                            report["parser_coverage"]["unsupported_extensions"].append(extension)
                        logger.warning("No parser registered for config file: %s", config_file)
                else:
                    logger.warning(f"Config file not found on disk: {full_path}")
                    report["config_files_missing"].append(config_file)

        
        all_files = discover_source_files(self.target_dir)
                    
        total_files = len(all_files)
        report["source_files_seen"] = total_files
        logger.info(f"Discovered {total_files} C/C++ files to parse.")

        print("")
        for idx, filepath in enumerate(all_files, 1):
            if cancel_event is not None and cancel_event.is_set():
                raise KeyboardInterrupt
            percent = (idx / total_files) * 100 if total_files else 100
            
            is_vendor_code = is_vendor_file(
                filepath,
                set(vendor_folders_normalized),
                root=self.target_dir,
            )
            if is_vendor_code:
                report["vendor_files"] += 1
            else:
                report["application_files"] += 1
                domains = report["parser_coverage"]["discovery_domains"]
                roots = report["discovery_context"].get("application_roots", [])
                relative_parts = Path(filepath).relative_to(Path(self.target_dir)).parts
                if domains and relative_parts:
                    for domain in domains:
                        domain_path = str(domain).strip().strip('/\\')
                        if "/" not in domain_path and roots:
                            domain_path = f"{str(roots[0]).strip().strip('/\\')}/{domain_path}"
                        domain_parts = Path(domain_path).parts
                        if tuple(relative_parts[:len(domain_parts)]) == domain_parts:
                            coverage = report["parser_coverage"]["domain_coverage"]
                            coverage[domain] = coverage.get(domain, 0) + 1
                            break
            parse_vendor_internals = vendor_parse_mode == "full"
            
            indicator = "📦" if is_vendor_code else "🚀"
            short_path = os.path.join(*Path(filepath).parts[-2:])
            display_path = f"{short_path:<40}"
            sys.stdout.write(f"\r{indicator} Parsing [{idx}/{total_files}] ({percent:3.0f}%) -> {display_path}")
            sys.stdout.flush()
                
            try:
                self.parser.parse_file(
                    str(filepath),
                    is_vendor_code,
                    parse_vendor_internals=parse_vendor_internals,
                    cancel_event=cancel_event,
                )
                report["source_files_parsed"] += 1
            except KeyboardInterrupt:
                print(f"\n⏹ Parsing interrupted at {short_path}")
                self._flush_pending_batch()
                raise
            except Exception as e:
                print(f"\n❌ Crash while parsing {short_path}: {e}")
                report["source_files_failed"].append({"file": str(filepath), "error": str(e)})
            
            self._check_and_flush()

        print("\n")
        logger.info("Flushing final graph data to Neo4j...")
        final_batch = self.builder.flush_all()
        if final_batch.nodes or final_batch.edges:
            report["parser_edges_emitted"] += len(final_batch.edges)
            self.graph_manager.ingest_batch(final_batch)
            
        logger.info("Ingestion pipeline finished.")
        logger.debug(
            "Ingestion metrics: vendor_files=%d application_files=%d parser_edges_emitted=%d vendor_parse_mode=%s",
            report["vendor_files"],
            report["application_files"],
            report["parser_edges_emitted"],
            report["vendor_parse_mode"],
        )
        if (
            report["config_files_missing"]
            or report["config_files_outside_target"]
            or report["config_files_unsupported"]
            or report["source_files_failed"]
        ):
            logger.warning(
                "Ingestion completed with partial coverage: %d missing configs, %d outside-target configs, %d unsupported configs, %d source parse failures",
                len(report["config_files_missing"]),
                len(report["config_files_outside_target"]),
                len(report["config_files_unsupported"]),
                len(report["source_files_failed"]),
            )
        else:
            logger.info(
                "Ingestion coverage complete: %d config files and %d source files processed",
                report["config_files_parsed"],
                report["source_files_parsed"],
            )
        return report

    def _check_and_flush(self):
        if self.builder.is_ready_to_flush():
            logger.debug("Batch threshold reached. Flushing to Neo4j...")
            batch = self.builder.flush_batch()
            self._active_report["parser_edges_emitted"] += len(batch.edges)
            self.graph_manager.ingest_batch(batch)

    def _flush_pending_batch(self):
        batch = self.builder.flush_all()
        if batch.nodes or batch.edges:
            self._active_report["parser_edges_emitted"] += len(batch.edges)
            self.graph_manager.ingest_batch(batch)
