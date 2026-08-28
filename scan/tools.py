import os
import logging
from urllib.parse import urlparse
from graph.manager import GraphManager

logger = logging.getLogger(__name__)

class AnalyzerTools:
    """Deterministic tools exposed to the AnalyzerAgent for exploring the codebase."""
    
    def __init__(self, graph_manager: GraphManager):
        self.db = graph_manager.db
        # --- NEW: Agent Memory Cache ---
        self._cache = set()

    def _check_cache(self, tool_name: str, cache_key: str) -> bool:
        """Checks if the agent already ran this exact tool with these exact arguments."""
        full_key = f"{tool_name}::{cache_key}"
        if full_key in self._cache:
            return True
        self._cache.add(full_key)
        return False

    def get_function_metadata(self, func_name: str) -> str:
        """Returns the file path, byte span, and UDS entry point status of a function."""
        if self._check_cache("get_function_metadata", func_name):
            return f"System Note: Metadata for '{func_name}' is already in your conversation history. Do not request it again."

        query = """
        MATCH (f:Function {name: $func_name})
        RETURN f.storage_uri AS FilePath, 
               f.byte_span AS ByteSpan, 
               f.tainted_by_uds AS TaintedByUDS, 
               f.reachable_from_dids AS DIDs,
               coalesce(f.is_vendor_code, false) AS IsVendorLibrary,
               f:Stub AS IsStubNode
        """
        try:
            with self.db.driver.session() as session:
                result = session.run(query, func_name=func_name).data()
                if not result:
                    return f"Function {func_name} not found in graph."
                
                # Format the results for the LLM
                for r in result:
                    # 1. Truncate massive DID arrays
                    dids = r.get("DIDs")
                    if dids and len(dids) > 10:
                        r["DIDs"] = dids[:10] + [f"... and {len(dids) - 10} more"]
                        
                    # 2. If it's a stub, append a warning for the LLM
                    if r.get("IsStubNode"):
                        r["WARNING"] = "This is a Stub node (external library or macro). It has no source code available to read."
                
                return str(result)
        except Exception as e:
            return f"Error executing tool: {e}"

    def get_callees(self, func_name: str) -> str:
        """Retrieves everything this function calls (downstream), indicating dangerous sinks."""
        if self._check_cache("get_callees", func_name):
            return f"System Note: Callees for '{func_name}' are already in your conversation history."

        query = """
        MATCH (f:Function {name: $func_name})-[:CALLS]->(callee:Function)
        RETURN callee.name AS CalledFunction, 
               callee.is_vendor_code AS IsVendorLibrary, 
               callee.is_dangerous_sink AS IsDangerousSink,
               callee:Stub AS IsStubNode
        """
        try:
            with self.db.driver.session() as session:
                result = session.run(query, func_name=func_name).data()
                if not result:
                    return "No callees found."
                    
                # Format the results for the LLM
                for r in result:
                    if r.get("IsStubNode"):
                        r["WARNING"] = "Stub node. No source code available."
                        
                return str(result)
        except Exception as e:
            return f"Error executing tool: {e}"

    def read_file_span(self, storage_uri: str, byte_span: str) -> str:
        """Reads exactly the requested bytes from a C/C++ source file."""
        if not storage_uri or not byte_span:
            return "Error: Must provide both storage_uri and byte_span."
            
        # Check Agent Memory
        if self._check_cache("read_file_span", f"{storage_uri}_{byte_span}"):
            return "System Note: You have already read this exact file span. It is in your conversation history. Do not request it again."
            
        # Robust Windows/Linux URI parsing
        file_path = storage_uri
        if file_path.startswith("file://"):
            file_path = file_path[7:]
            
        if os.name == 'nt' and file_path.startswith('/') and ':' in file_path:
            file_path = file_path[1:] 
            
        try:
            start_byte, end_byte = map(int, byte_span.split('-'))
            with open(file_path, 'rb') as f:
                f.seek(start_byte)
                snippet = f.read(end_byte - start_byte)
                return snippet.decode('utf-8', errors='ignore')
        except FileNotFoundError:
            return f"Error: The file {file_path} was not found on disk."
        except Exception as e:
            return f"Error reading file from disk: {e}"

    def get_callers_and_entry_points(self, func_name: str) -> str:
        """Retrieves upstream callers, or direct Hardware/UDS triggers."""
        if self._check_cache("get_callers", func_name):
            return f"System Note: Callers for '{func_name}' are already in your conversation history."

        query = """
        MATCH (f:Function {name: $func_name})
        OPTIONAL MATCH (f)-[:HANDLES_UDS]->(uds:UdsService)
        OPTIONAL MATCH (f)-[:RECEIVES_SIGNAL]->(net:NetworkSignal)
        OPTIONAL MATCH (caller:Function)-[:CALLS]->(f)
        RETURN 
            collect(DISTINCT uds.did) AS UdsTriggers,
            collect(DISTINCT net.name) AS NetworkTriggers,
            collect(DISTINCT caller.name) AS StandardCallers,
            f.is_hardware_entry AS IsHardwareTask
        """
        try:
            with self.db.driver.session() as session:
                result = session.run(query, func_name=func_name).single()
                return str(result.data()) if result else "No upstream context found."
        except Exception as e:
            return f"Error executing tool: {e}"

    def get_variable_access(self, func_name: str) -> str:
        """Retrieves the global variables this function reads or writes."""
        if self._check_cache("get_vars", func_name):
            return f"System Note: Variable access for '{func_name}' is already in your conversation history."

        query = """
        MATCH (f:Function {name: $func_name})-[r:READS_VAR|WRITES_VAR]->(v:GlobalVariable)
        RETURN v.name AS VariableName, 
               type(r) AS AccessType
        """
        try:
            with self.db.driver.session() as session:
                result = session.run(query, func_name=func_name).data()
                return str(result) if result else "No global variable access found."
        except Exception as e:
            return f"Error executing tool: {e}"
