import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class RepoDiscoverer:
    @staticmethod
    def generate_directory_tree(target_dir: str, max_depth: int = 4) -> str:
        """Generates a lightweight text representation of the folder structure."""
        tree = []
        base_depth = target_dir.rstrip(os.sep).count(os.sep)
        
        for root, dirs, files in os.walk(target_dir):
            current_depth = root.count(os.sep) - base_depth
            if current_depth > max_depth:
                del dirs[:]
                continue
                
            indent = "  " * current_depth
            folder_name = os.path.basename(root)
            tree.append(f"{indent}[DIR] {folder_name}/")
            
            important_exts = ('.arxml', '.oil', '.xml', 'CMakeLists.txt', '.mk')
            important_files = [
                f for f in files 
                if f.endswith(important_exts) 
                or f.startswith('Makefile')
                or ('rte' in f.lower() and f.endswith('.json'))
            ]
            other_files = [f for f in files if f not in important_files]
            display_files = (important_files + other_files)[:5] 
            
            for f in display_files: 
                # Create a relative path from the root and normalize separators
                relative_path = os.path.relpath(os.path.join(root, f), target_dir)
                normalized_path = Path(relative_path).as_posix() # <-- POSIX uses '/'
                tree.append(f"{indent}  - {normalized_path}")
            
            if len(files) > 5:
                tree.append(f"{indent}  - ... ({len(files) - 5} more files)")
                
        return "\n".join(tree)
