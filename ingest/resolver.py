import os
import difflib
from typing import Dict, Optional
import logging

logger = logging.getLogger(__name__)

class IncludeResolver:
    """Maps #include directives to absolute file paths efficiently."""
    
    def __init__(self, search_paths: list[str]):
        self.search_paths = search_paths
        self._exact_map: Dict[str, str] = {}
        self._fuzzy_cache: Dict[str, Optional[str]] = {}
        self._build_index()

    def _build_index(self):
        """Builds an exact-match index of all available headers."""
        for path in self.search_paths:
            for root, _, files in os.walk(path):
                for file in files:
                    if file.endswith(('.h', '.hpp')):
                        # Keep the first found if duplicates exist
                        if file not in self._exact_map:
                            self._exact_map[file] = os.path.join(root, file)

    def resolve(self, header_name: str) -> Optional[str]:
        """Resolves a header name, using exact match first, then cached fuzzy match."""
        # 1. Exact Match (O(1))
        if header_name in self._exact_map:
            return self._exact_map[header_name]
            
        # 2. Check Fuzzy Cache (O(1))
        if header_name in self._fuzzy_cache:
            return self._fuzzy_cache[header_name]
            
        # 3. Fallback: Fuzzy matching (Strip prefixes like Rte_, Bsw_)
        logger.debug(f"Fuzzy resolving {header_name}...")
        stripped_name = header_name.replace("Rte_", "").replace("Bsw_", "")
        
        matches = difflib.get_close_matches(stripped_name, self._exact_map.keys(), n=1, cutoff=0.8)
        
        result_path = self._exact_map[matches[0]] if matches else None
        
        # Save to cache so we never do this expensive calculation for this header again
        self._fuzzy_cache[header_name] = result_path 
        return result_path
