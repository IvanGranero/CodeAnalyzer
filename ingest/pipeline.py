import os
import sys
import logging
from pathlib import Path
from graph.manager import GraphManager
from ingest.builder import GraphPayloadBuilder
from ingest.parser import ASTParser

logger = logging.getLogger(__name__)

class IngestionPipeline:
    def __init__(self, target_dir: str, graph_manager: GraphManager):
        self.target_dir = os.path.abspath(target_dir)
        self.graph_manager = graph_manager
        self.builder = GraphPayloadBuilder(batch_size=5000)
        self.parser = ASTParser(self.builder)

    def run(self, vendor_folders: list = None):
        if vendor_folders is None:
            vendor_folders = []
            
        # Normalize the vendor folder strings so we can match them safely
        vendor_folders_normalized = [vf.strip().strip('/\\').lower() for vf in vendor_folders]
        
        logger.info(f"Starting pipeline. Tagging Vendor/Generated folders: {vendor_folders_normalized}")
        
        all_files = []
        for root, _, files in os.walk(self.target_dir):
            for file in files:
                if file.endswith(('.c', '.cpp', '.h', '.hpp')):
                    all_files.append(os.path.join(root, file))
                    
        total_files = len(all_files)
        logger.info(f"Discovered {total_files} C/C++ files to parse.")

        print("")
        for idx, filepath in enumerate(all_files, 1):
            percent = (idx / total_files) * 100
            
            # --- CROSS-PLATFORM NORMALIZATION ---
            # Path(filepath).parts gives a list like ('C:', 'Users', 'project', 'bsw', 'file.c')
            path_parts = [p.lower() for p in Path(filepath).parts]
            
            # Check if any part of the path matches our vendor folders
            is_vendor_code = any(vf in path_parts for vf in vendor_folders_normalized)
            
            indicator = "📦" if is_vendor_code else "🚀"
            short_path = os.path.join(*Path(filepath).parts[-2:])
            display_path = f"{short_path:<40}"
            sys.stdout.write(f"\r{indicator} Parsing [{idx}/{total_files}] ({percent:3.0f}%) -> {display_path}")
            sys.stdout.flush()
                
            try:
                self.parser.parse_file(filepath, is_vendor_code)
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
