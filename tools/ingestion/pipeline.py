import os
import sys
import logging
from pathlib import Path
from tools.graph.manager import GraphManager
from tools.ingestion.builder import GraphPayloadBuilder
from tools.ingestion.parser import ASTParser
from tools.ingestion.arxml_parser import ARXMLParser
# Assume we will create a new parser for these specific JSON files
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
        # --- NEW: Initialize the JSON parser with the same builder ---
        self.rte_json_parser = RteJsonParser(self.builder)
        self.config_dispatcher = ConfigParserDispatcher({
            ".arxml": self.arxml_parser,
            ".xml": self.arxml_parser,
            ".json": self.rte_json_parser,
        })

    def run(self, vendor_folders: list = None, config_files: list = None):
        if vendor_folders is None:
            vendor_folders = []
        if config_files is None:
            config_files = []
            
        vendor_folders_normalized = [vf.strip().strip('/\\').lower() for vf in vendor_folders]
        
        logger.info(f"Starting pipeline. Tagging Vendor/Generated folders: {vendor_folders_normalized}")
        
        # --- 1. PARSE CONFIG FILES (ARXML, JSON, etc.) FIRST ---
        if config_files:
            logger.info(f"Parsing {len(config_files)} OS/System configuration files...")
            
            for config_file in config_files:
                normalized_config_path = os.path.normpath(config_file)
                full_path = os.path.join(self.target_dir, normalized_config_path)
                
                if os.path.exists(full_path):
                    logger.debug(f"Parsing config: {config_file}")
                    self.config_dispatcher.parse(Path(full_path))
                    self._check_and_flush()
                else:
                    logger.warning(f"Config file not found on disk: {full_path}")

        # --- 2. PARSE C/C++ SOURCE CODE ---
        all_files = discover_source_files(self.target_dir)
                    
        total_files = len(all_files)
        logger.info(f"Discovered {total_files} C/C++ files to parse.")

        print("")
        for idx, filepath in enumerate(all_files, 1):
            percent = (idx / total_files) * 100
            
            is_vendor_code = is_vendor_file(filepath, set(vendor_folders_normalized))
            
            indicator = "📦" if is_vendor_code else "🚀"
            short_path = os.path.join(*Path(filepath).parts[-2:])
            display_path = f"{short_path:<40}"
            sys.stdout.write(f"\r{indicator} Parsing [{idx}/{total_files}] ({percent:3.0f}%) -> {display_path}")
            sys.stdout.flush()
                
            try:
                self.parser.parse_file(str(filepath), is_vendor_code)
            except Exception as e:
                print(f"\n❌ Crash while parsing {short_path}: {e}")
            
            self._check_and_flush()

        print("\n")
        logger.info("Flushing final graph data to Neo4j...")
        final_batch = self.builder.flush_all()
        if final_batch.nodes or final_batch.edges:
            self.graph_manager.ingest_batch(final_batch)
            
        logger.info("Ingestion pipeline finished.")

    def _check_and_flush(self):
        if self.builder.is_ready_to_flush():
            logger.debug("Batch threshold reached. Flushing to Neo4j...")
            batch = self.builder.flush_batch()
            self.graph_manager.ingest_batch(batch)
