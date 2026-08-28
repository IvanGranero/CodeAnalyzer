import logging
import re
from tree_sitter import Language, Parser
import tree_sitter_c  
from ingest.builder import GraphPayloadBuilder

logger = logging.getLogger(__name__)

class ASTParser:
    def __init__(self, builder: GraphPayloadBuilder):
        self.builder = builder
        self.lang = Language(tree_sitter_c.language())
        self.parser = Parser(self.lang) 
        
        # Matches AutoSAR FUNC(ReturnType, MemClass) FunctionName(Args...)
        self.autosar_func_re = re.compile(br'FUNC\s*\([^)]+\)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(')
        
        # Matches AutoSAR TASK(TaskName) or ISR(IsrName)
        self.autosar_task_re = re.compile(br'(?:TASK|ISR)\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)')

    def parse_file(self, filepath: str, is_vendor_code: bool = False):
        try:
            with open(filepath, 'rb') as f:
                raw_code = f.read()
        except Exception as e:
            logger.error(f"Failed to read {filepath}: {e}")
            return

        file_size = len(raw_code)
        uri = f"file://{filepath}"
        found_function_names = set()
        
        if file_size > 50 * 1024 * 1024: 
            return

        is_config_file = any(filepath.endswith(ext) for ext in ['_Cfg.c', '_PBcfg.c', '_Lcfg.c', '_LCfg.c'])

        # --- Fast AutoSAR Macro Stripping ---
        # We replace the macros with spaces so we don't mess up the byte_span offsets!
        source_code = self._clean_autosar_macros(raw_code)

        # 1. Standard AST Traversal
        if file_size <= 2 * 1024 * 1024 and not is_config_file:
            try:
                tree = self.parser.parse(source_code)
                
                # A. Extract Global Variables
                for child in tree.root_node.children:
                    if child.type == 'declaration':
                        var_name = self._extract_first_identifier(child, source_code)
                        if var_name:
                            self.builder.add_global_variable(var_name, uri, f"{child.start_byte}-{child.end_byte}")

                # B. Extract Functions and Internals
                func_nodes = self._find_nodes_of_type(tree.root_node, 'function_definition')
                for func_node in func_nodes:
                    func_name = self._extract_function_name(func_node, source_code)
                    if func_name:
                        byte_span = f"{func_node.start_byte}-{func_node.end_byte}"
                        func_id = self.builder.add_function_node(func_name, uri, byte_span, is_vendor_code)
                        found_function_names.add(func_name)
                        
                        # Now Tree-sitter can successfully read the internals!
                        self._process_function_internals(func_node, source_code, func_id, func_name)
            except Exception as e:
                logger.error(f"AST Parsing failed on {filepath}: {e}")

        # 2. AutoSAR Macro & Attack Surface Fallback
        # --- FIX: We MUST pass raw_code here so the Regex can see the unmodified macros! ---
        self._regex_autosar_fallback(raw_code, uri, found_function_names, is_vendor_code)

    def _clean_autosar_macros(self, code: bytes) -> bytes:
        """
        Replaces AutoSAR compiler abstraction macros with spaces 
        to preserve byte offsets while allowing Tree-sitter to parse standard C.
        """
        text = code.decode('utf-8', errors='ignore')
        
        # 1. Clean FUNC(type, memclass) -> type                 
        text = re.sub(r'FUNC\s*\(\s*([a-zA-Z0-9_]+)\s*,\s*[a-zA-Z0-9_]+\s*\)', lambda m: m.group(1).ljust(len(m.group(0))), text)
        
        # 2. Clean P2VAR, P2CONST, CONSTP2VAR -> type*
        text = re.sub(r'(?:P2VAR|P2CONST|CONSTP2VAR|CONSTP2CONST)\s*\(\s*([a-zA-Z0-9_]+)\s*,\s*[a-zA-Z0-9_]+\s*,\s*[a-zA-Z0-9_]+\s*\)', lambda m: (m.group(1) + "*").ljust(len(m.group(0))), text)
        
        # 3. Clean VAR, CONST -> type
        text = re.sub(r'(?:VAR|CONST)\s*\(\s*([a-zA-Z0-9_]+)\s*,\s*[a-zA-Z0-9_]+\s*\)', lambda m: m.group(1).ljust(len(m.group(0))), text)
        
        # 4. Clean TASK(name) -> void name()
        text = re.sub(r'TASK\s*\(\s*([a-zA-Z0-9_]+)\s*\)', lambda m: f"void {m.group(1)}()".ljust(len(m.group(0))), text)
        
        return text.encode('utf-8')

    def _regex_autosar_fallback(self, raw_code: bytes, uri: str, found_function_names: set, is_vendor_code: bool):
        def process_discovered_func(func_name, byte_span, is_isr_task=False):
            if func_name not in found_function_names:
                func_id = self.builder.add_function_node(func_name, uri, byte_span, is_vendor_code, is_isr_task)
                found_function_names.add(func_name)
            else:
                func_id = self.builder.generate_node_id("Function", func_name, uri)
                # --- FIX: Ensure the hardware entry flag is set even if AST found it first! ---
                if is_isr_task and func_id in self.builder._nodes:
                    self.builder._nodes[func_id].properties["is_hardware_entry"] = True

            # UDS Mapping
            if "_DID_" in func_name or "_RID_" in func_name:
                parts = func_name.split("_DID_") if "_DID_" in func_name else func_name.split("_RID_")
                if len(parts) > 1:
                    did_hex = parts[1][:4] 
                    operation = "Unknown"
                    if "Read" in func_name: operation = "Read"
                    elif "Write" in func_name: operation = "Write"
                    self.builder.add_uds_handler(func_id, did_hex, operation)
                
            # Network Mapping (Com/PduR)
            if "RxIndication" in func_name or "TxConfirmation" in func_name:
                direction = "RX" if "RxIndication" in func_name else "TX"
                sig_name = func_name.replace("Com_", "").replace("PduR_", "")
                self.builder.add_network_signal(func_id, sig_name, direction)

        # Catch FUNC macros
        for match in self.autosar_func_re.finditer(raw_code):
            process_discovered_func(match.group(1).decode('utf8', errors='ignore'), f"{match.start()}-{match.end()}")
                
        # Catch TASK / ISR macros (Hardware entry points!)
        for match in self.autosar_task_re.finditer(raw_code):
            process_discovered_func(match.group(1).decode('utf8', errors='ignore'), f"{match.start()}-{match.end()}", is_isr_task=True)

    def _process_function_internals(self, func_node, source_code: bytes, caller_id: str, func_name: str):
        # 1. Extract Calls
        for call_node in self._find_nodes_of_type(func_node, 'call_expression'):
            callee_name = self._extract_call_name(call_node, source_code)
            if callee_name:
                self.builder.add_call_edge(caller_id, callee_name)
        
        # 2. Advanced Vulnerability Context: Extract Written Variables vs Read Variables
        written_vars = set()
        
        for assign_node in self._find_nodes_of_type(func_node, 'assignment_expression'):
            left_side = assign_node.child_by_field_name('left')
            if left_side:
                var_name = self._extract_first_identifier(left_side, source_code)
                if var_name: written_vars.add(var_name)
                
        for update_node in self._find_nodes_of_type(func_node, 'update_expression'):
            var_name = self._extract_first_identifier(update_node, source_code)
            if var_name: written_vars.add(var_name)

        # 3. Extract all identifiers (fallback for generic Reads)
        for ident in self._find_nodes_of_type(func_node, 'identifier'):
            var_name = source_code[ident.start_byte:ident.end_byte].decode('utf8', errors='ignore')
            if var_name and var_name != func_name:
                is_write = var_name in written_vars
                self.builder.add_var_access_edge(caller_id, var_name, is_write)

    # --- Utility Methods ---
    def _find_nodes_of_type(self, node, target_type):
        results = []
        stack = [node]
        while stack:
            current = stack.pop()
            if current.type == target_type:
                results.append(current)
            for child in current.children:
                stack.append(child)
        return results

    def _extract_function_name(self, func_node, source_code: bytes):
        decl = func_node.child_by_field_name('declarator')
        if not decl:
            decls = self._find_nodes_of_type(func_node, 'function_declarator')
            if decls: decl = decls[0]
        if decl:
            return self._extract_first_identifier(decl, source_code)
        return None
        
    def _extract_call_name(self, call_node, source_code: bytes):
        func = call_node.child_by_field_name('function')
        if func:
            return self._extract_first_identifier(func, source_code)
        return None

    def _extract_first_identifier(self, node, source_code: bytes):
        stack = [node]
        while stack:
            current = stack.pop()
            if current.type in ('identifier', 'field_identifier'):
                return source_code[current.start_byte:current.end_byte].decode('utf8', errors='ignore')
            for child in reversed(current.children):
                stack.append(child)
        return None
