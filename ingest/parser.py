import logging
import re
from tree_sitter import Language, Parser
import tree_sitter_c  
from ingest.builder import GraphPayloadBuilder

logger = logging.getLogger(__name__)

# --- NEW: Blacklist of common C and AUTOSAR primitive types ---
# This prevents creating millions of useless DEPENDS_ON_TYPE edges to 'uint8', etc.
PRIMITIVE_TYPES = {
    'void', 'char', 'int', 'short', 'long', 'float', 'double',
    'uint8', 'uint16', 'uint32', 'uint64', 'sint8', 'sint16', 'sint32', 'sint64',
    'uint8_least', 'uint16_least', 'uint32_least', 'boolean', 'bool',
    'Std_ReturnType', 'StatusType', 'NotifResultType', 'BufReq_ReturnType',
    'PduIdType', 'PduLengthType', 'PduInfoType', 'Com_SignalIdType'
}

class ASTParser:
    def __init__(self, builder: GraphPayloadBuilder):
        self.builder = builder
        self.lang = Language(tree_sitter_c.language())
        self.parser = Parser(self.lang) 
        
        self.autosar_func_re = re.compile(br'FUNC\s*\([^)]+\)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(')
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
        source_code = self._clean_autosar_macros(raw_code)

        if file_size <= 2 * 1024 * 1024 and not is_config_file:
            try:
                tree = self.parser.parse(source_code)
                
                # --- This block now skips internal parsing for vendor code ---
                if not is_vendor_code:
                    for child in tree.root_node.children:
                        if child.type == 'preproc_def':
                            name_node = child.child_by_field_name('name')
                            val_node = child.child_by_field_name('value')
                            if name_node:
                                m_name = source_code[name_node.start_byte:name_node.end_byte].decode('utf8', errors='ignore')
                                m_val = source_code[val_node.start_byte:val_node.end_byte].decode('utf8', errors='ignore') if val_node else ""
                                self.builder.add_macro_definition(m_name, m_val, uri, f"{child.start_byte}-{child.end_byte}")

                        elif child.type == 'declaration':
                            var_name = self._extract_first_identifier(child, source_code)
                            if var_name:
                                var_id = self.builder.add_global_variable(var_name, uri, f"{child.start_byte}-{child.end_byte}")
                                type_node = child.child_by_field_name('type')
                                if type_node:
                                    type_name = source_code[type_node.start_byte:type_node.end_byte].decode('utf8', errors='ignore').strip()
                                    if type_name not in PRIMITIVE_TYPES:
                                        self.builder.add_type_dependency_edge(var_id, type_name, "GLOBAL_VAR_TYPE")

                        elif child.type in ('type_definition', 'struct_specifier', 'enum_specifier'):
                            type_name = self._extract_first_identifier(child, source_code)
                            if type_name and type_name not in PRIMITIVE_TYPES:
                                self.builder.add_type_definition(type_name, uri, f"{child.start_byte}-{child.end_byte}")
                                field_list = self._find_nodes_of_type(child, 'field_declaration_list')
                                if field_list:
                                    for field in self._find_nodes_of_type(field_list[0], 'field_declaration'):
                                        f_type = field.child_by_field_name('type')
                                        if f_type:
                                            f_type_name = source_code[f_type.start_byte:f_type.end_byte].decode('utf8', errors='ignore').strip()
                                            if f_type_name not in PRIMITIVE_TYPES:
                                                parent_stub_id = f"stub::{type_name}"
                                                self.builder.add_type_dependency_edge(parent_stub_id, f_type_name, "NESTED_FIELD")

                # --- Function definitions are ALWAYS parsed, even for vendor code, to build the call graph ---
                func_nodes = self._find_nodes_of_type(tree.root_node, 'function_definition')
                for func_node in func_nodes:
                    func_name = self._extract_function_name(func_node, source_code)
                    if func_name:
                        byte_span = f"{func_node.start_byte}-{func_node.end_byte}"
                        func_id = self.builder.add_function_node(func_name, uri, byte_span, is_vendor_code)
                        found_function_names.add(func_name)
                        
                        # --- OPTIMIZATION: Only process internals for non-vendor code ---
                        if not is_vendor_code:
                            type_node = func_node.child_by_field_name('type')
                            if type_node:
                                type_name = source_code[type_node.start_byte:type_node.end_byte].decode('utf8', errors='ignore').strip()
                                if type_name not in PRIMITIVE_TYPES:
                                    self.builder.add_type_dependency_edge(func_id, type_name, "RETURN_TYPE")
                                
                            param_lists = self._find_nodes_of_type(func_node, 'parameter_list')
                            if param_lists:
                                for param in self._find_nodes_of_type(param_lists[0], 'parameter_declaration'):
                                    p_type = param.child_by_field_name('type')
                                    if p_type:
                                        p_type_name = source_code[p_type.start_byte:p_type.end_byte].decode('utf8', errors='ignore').strip()
                                        if p_type_name not in PRIMITIVE_TYPES:
                                            self.builder.add_type_dependency_edge(func_id, p_type_name, "PARAM_TYPE")

                            self._process_function_internals(func_node, source_code, func_id, func_name)
            except Exception as e:
                logger.error(f"AST Parsing failed on {filepath}: {e}")

        self._regex_autosar_fallback(raw_code, uri, found_function_names, is_vendor_code)

    def _clean_autosar_macros(self, code: bytes) -> bytes:
        text = code.decode('utf-8', errors='ignore')
        text = re.sub(r'FUNC\s*\(\s*([a-zA-Z0-9_]+)\s*,\s*[a-zA-Z0-9_]+\s*\)', lambda m: m.group(1).ljust(len(m.group(0))), text)
        text = re.sub(r'(?:P2VAR|P2CONST|CONSTP2VAR|CONSTP2CONST)\s*\(\s*([a-zA-Z0-9_]+)\s*,\s*[a-zA-Z0-9_]+\s*,\s*[a-zA-Z0-9_]+\s*\)', lambda m: (m.group(1) + "*").ljust(len(m.group(0))), text)
        text = re.sub(r'(?:VAR|CONST)\s*\(\s*([a-zA-Z0-9_]+)\s*,\s*[a-zA-Z0-9_]+\s*\)', lambda m: m.group(1).ljust(len(m.group(0))), text)
        text = re.sub(r'TASK\s*\(\s*([a-zA-Z0-9_]+)\s*\)', lambda m: f"void {m.group(1)}()".ljust(len(m.group(0))), text)
        return text.encode('utf-8')

    def _regex_autosar_fallback(self, raw_code: bytes, uri: str, found_function_names: set, is_vendor_code: bool):
        def process_discovered_func(func_name, byte_span, is_isr_task=False):
            if func_name not in found_function_names:
                func_id = self.builder.add_function_node(func_name, uri, byte_span, is_vendor_code, is_isr_task)
                found_function_names.add(func_name)
            else:
                func_id = self.builder.generate_node_id("Function", func_name, uri)
                if is_isr_task and func_id in self.builder._nodes:
                    self.builder._nodes[func_id].properties["is_hardware_entry"] = True

            if "_DID_" in func_name or "_RID_" in func_name:
                parts = func_name.split("_DID_") if "_DID_" in func_name else func_name.split("_RID_")
                if len(parts) > 1:
                    did_hex = parts[1][:4] 
                    operation = "Read" if "Read" in func_name else ("Write" if "Write" in func_name else "Unknown")
                    self.builder.add_uds_handler(func_id, did_hex, operation)
                
            if "RxIndication" in func_name or "TxConfirmation" in func_name:
                direction = "RX" if "RxIndication" in func_name else "TX"
                sig_name = func_name.replace("Com_", "").replace("PduR_", "")
                self.builder.add_network_signal(func_id, sig_name, direction)

        for match in self.autosar_func_re.finditer(raw_code):
            process_discovered_func(match.group(1).decode('utf8', errors='ignore'), f"{match.start()}-{match.end()}")
                
        for match in self.autosar_task_re.finditer(raw_code):
            process_discovered_func(match.group(1).decode('utf8', errors='ignore'), f"{match.start()}-{match.end()}", is_isr_task=True)

    def _process_function_internals(self, func_node, source_code: bytes, caller_id: str, func_name: str):
        # This function is now only called for non-vendor code, drastically reducing relationship count.
        for call_node in self._find_nodes_of_type(func_node, 'call_expression'):
            args = []
            args_node = call_node.child_by_field_name('arguments')
            if args_node:
                for arg_node in args_node.children:
                    if arg_node.is_named:
                        args.append(source_code[arg_node.start_byte:arg_node.end_byte].decode('utf8', errors='ignore'))
            
            func_target = call_node.child_by_field_name('function')
            if func_target:
                if func_target.type in ('identifier', 'type_identifier'):
                    callee_name = source_code[func_target.start_byte:func_target.end_byte].decode('utf8', errors='ignore')
                    self.builder.add_call_edge(caller_id, callee_name, arguments=args, is_pointer=False)
                elif func_target.type == 'field_expression':
                    pointer_expr = source_code[func_target.start_byte:func_target.end_byte].decode('utf8', errors='ignore')
                    self.builder.add_call_edge(caller_id, pointer_expr, arguments=args, is_pointer=True)

        local_vars = set()
        for decl_node in self._find_nodes_of_type(func_node, 'declaration'):
            l_var = self._extract_first_identifier(decl_node, source_code)
            if l_var: local_vars.add(l_var)
            
        written_vars = set()
        for assign_node in self._find_nodes_of_type(func_node, 'assignment_expression'):
            left_side = assign_node.child_by_field_name('left')
            if left_side:
                var_name = self._extract_first_identifier(left_side, source_code)
                if var_name and var_name not in local_vars:
                    written_vars.add(var_name)
                
        for update_node in self._find_nodes_of_type(func_node, 'update_expression'):
            var_name = self._extract_first_identifier(update_node, source_code)
            if var_name and var_name not in local_vars:
                written_vars.add(var_name)

        for ident in self._find_nodes_of_type(func_node, 'identifier'):
            var_name = source_code[ident.start_byte:ident.end_byte].decode('utf8', errors='ignore')
            if var_name and var_name != func_name and var_name not in local_vars:
                is_write = var_name in written_vars
                self.builder.add_var_access_edge(caller_id, var_name, is_write)

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

    def _extract_first_identifier(self, node, source_code: bytes):
        stack = [node]
        # Ignore common C modifiers that Tree-sitter sometimes misclassifies
        ignored_keywords = {'STATIC', 'CONST', 'VOLATILE', 'EXTERN', 'INLINE', 'static', 'const', 'extern'}
        
        while stack:
            current = stack.pop()
            
            if current.type in ('identifier', 'field_identifier'):
                name = source_code[current.start_byte:current.end_byte].decode('utf8', errors='ignore')
                if name and name not in ignored_keywords:
                    return name
                    
            for child in reversed(current.children):
                stack.append(child)
        return None

