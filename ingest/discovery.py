import os
import logging

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
                del dirs[:]  # Stop going deeper
                continue
                
            indent = "  " * current_depth
            folder_name = os.path.basename(root)
            tree.append(f"{indent}[DIR] {folder_name}/")
            
            # Optionally list just a few files to give the LLM hints
            for f in files[:3]: 
                tree.append(f"{indent}  - {f}")
            if len(files) > 3:
                tree.append(f"{indent}  - ... ({len(files) - 3} more files)")
                
        return "\n".join(tree)
