import logging
import re
from tree_sitter import Language, Parser
import tree_sitter_c  
from tools.ingestion.builder import GraphPayloadBuilder

logger = logging.getLogger(__name__)



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
        
        
        
        
        self.macro_alias_target_re = re.compile(r'^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(')
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        self.accessor_macro_body_re = re.compile(r'^\s*\((?:[\s&*(]*)[A-Za-z_]')
        
        
        
        
        
        
        
        
        
        self.dcm_did_table_entry_re = re.compile(
            br'\(\(Dcm_DidMgrOpFuncType\)\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\)'
            br'[^{}]*?0x([0-9A-Fa-f]+)u\}\s*/\*\s*DID:\s*0x([0-9A-Fa-f]+)\s*\*/'
        )

    def parse_file(
        self,
        filepath: str,
        is_vendor_code: bool = False,
        parse_vendor_internals: bool = True,
    ):
        self._node_cache = {}
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
        file_global_ids: dict = {}

        if file_size <= 10 * 1024 * 1024 and not is_config_file:
            try:
                
                
                def source_reader(byte_offset, _point):
                    return source_code[byte_offset:byte_offset + 64 * 1024]

                tree = self.parser.parse(source_reader)

                
                if not is_vendor_code or parse_vendor_internals:
                    for child in tree.root_node.children:
                        if child.type == 'declaration':
                            for var_name in self._extract_all_declared_identifiers(child, source_code):
                                var_id = self.builder.add_global_variable(var_name, uri, f"{child.start_byte}-{child.end_byte}")
                                file_global_ids[var_name] = var_id

                        elif child.type in ('type_definition', 'struct_specifier', 'enum_specifier'):
                            type_name = self._extract_first_identifier(child, source_code)
                            if type_name and type_name not in PRIMITIVE_TYPES:
                                self.builder.add_type_definition(type_name, uri, f"{child.start_byte}-{child.end_byte}")

                for macro_def_node in self._find_nodes_of_type(tree.root_node, 'preproc_function_def'):
                    self._process_macro_alias(macro_def_node, source_code)

                for preproc_def_node in self._find_nodes_of_type(tree.root_node, 'preproc_def'):
                    name_node = preproc_def_node.child_by_field_name('name')
                    val_node = preproc_def_node.child_by_field_name('value')
                    if not name_node:
                        continue
                    m_name = source_code[name_node.start_byte:name_node.end_byte].decode('utf8', errors='ignore')
                    m_val = source_code[val_node.start_byte:val_node.end_byte].decode('utf8', errors='ignore').strip() if val_node else ""
                    self.builder.add_macro_definition(m_name, m_val, uri, f"{preproc_def_node.start_byte}-{preproc_def_node.end_byte}")
                    if m_val and m_val != m_name and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', m_val):
                        self.builder.add_macro_alias(m_name, m_val)

                
                func_nodes = self._find_nodes_of_type(tree.root_node, 'function_definition')
                for func_node in func_nodes:
                    func_name = self._extract_function_name(func_node, source_code)
                    if func_name:
                        byte_span = f"{func_node.start_byte}-{func_node.end_byte}"
                        func_id = self.builder.add_function_node(func_name, uri, byte_span, is_vendor_code)
                        found_function_names.add(func_name)
                        
                        
                        if not is_vendor_code or parse_vendor_internals:
                            self._process_function_internals(func_node, source_code, func_id, func_name, file_global_ids)
            except Exception as e:
                logger.error(f"AST Parsing failed on {filepath}: {e}")

        self._regex_autosar_fallback(raw_code, uri, found_function_names, is_vendor_code)
        self._extract_dcm_did_table_entries(raw_code)

    def _extract_dcm_did_table_entries(self, raw_code: bytes):
        """Scrapes (function, DID) pairs directly from a generated Dcm DID dispatch table, if this file has one."""
        for func_name, func_class_hex, did_hex in self.dcm_did_table_entry_re.findall(raw_code):
            self.builder.add_dcm_did_table_entry(
                func_name.decode('utf8', errors='ignore'),
                did_hex.decode('utf8', errors='ignore'),
                func_class_hex.decode('utf8', errors='ignore'),
            )

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
                    raw_identifier = parts[1].split("_", 1)[0]
                    
                    
                    
                    did_hex = raw_identifier[-4:]
                    operation = (
                        "Read" if "Read" in func_name else
                        "Write" if "Write" in func_name else
                        next((name for name in ("Start", "Stop", "RequestResults") if name in func_name), "Unknown")
                    )
                    kind = "rid" if "_RID_" in func_name else "did"
                    self.builder.add_uds_handler(func_id, did_hex, operation, kind)
                
            if "RxIndication" in func_name or "TxConfirmation" in func_name:
                direction = "RX" if "RxIndication" in func_name else "TX"
                sig_name = func_name.replace("Com_", "").replace("PduR_", "")
                self.builder.add_network_signal(func_id, sig_name, direction)

        for match in self.autosar_func_re.finditer(raw_code):
            process_discovered_func(match.group(1).decode('utf8', errors='ignore'), f"{match.start()}-{match.end()}")
                
        for match in self.autosar_task_re.finditer(raw_code):
            process_discovered_func(match.group(1).decode('utf8', errors='ignore'), f"{match.start()}-{match.end()}", is_isr_task=True)

    def _process_function_internals(self, func_node, source_code: bytes, caller_id: str, func_name: str, file_global_ids: dict = None):
        
        file_global_ids = file_global_ids or {}

        
        
        
        
        call_target_spans = set()

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
                    call_target_spans.add((func_target.start_byte, func_target.end_byte))
                    self.builder.add_call_edge(caller_id, callee_name, arguments=args, is_pointer=False)
                elif func_target.type == 'field_expression':
                    pointer_expr = source_code[func_target.start_byte:func_target.end_byte].decode('utf8', errors='ignore')
                    self.builder.add_call_edge(caller_id, pointer_expr, arguments=args, is_pointer=True)

        
        
        
        local_vars = set()
        for param_node in self._find_nodes_of_type(func_node, 'parameter_declaration'):
            p_var = self._extract_first_identifier(param_node, source_code)
            if p_var: local_vars.add(p_var)
        for decl_node in self._find_nodes_of_type(func_node, 'declaration'):
            local_vars.update(self._extract_all_declared_identifiers(decl_node, source_code))

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
            if (ident.start_byte, ident.end_byte) in call_target_spans:
                continue
            var_name = source_code[ident.start_byte:ident.end_byte].decode('utf8', errors='ignore')
            if var_name and var_name != func_name and var_name not in local_vars:
                is_write = var_name in written_vars
                
                
                
                target_id = file_global_ids.get(var_name)
                self.builder.add_var_access_edge(caller_id, var_name, is_write, target_id=target_id)

    def _find_nodes_of_type(self, node, target_type):
        cache_key = (id(node), target_type)
        cached = self._node_cache.get(cache_key)
        if cached is not None:
            return cached
        results = []
        stack = [node]
        while stack:
            current = stack.pop()
            if current.type == target_type:
                results.append(current)
            for child in current.children:
                stack.append(child)
        self._node_cache[cache_key] = results
        return results

    def _extract_function_name(self, func_node, source_code: bytes):
        decl = func_node.child_by_field_name('declarator')
        if not decl:
            decls = self._find_nodes_of_type(func_node, 'function_declarator')
            if decls: decl = decls[0]
        if decl:
            return self._extract_first_identifier(decl, source_code)
        return None

    def _process_macro_alias(self, preproc_function_def_node, source_code: bytes):
        """
        Handles a function-like macro `#define SHORT(...) LONG(...)`. tree-sitter-c
        doesn't parse the replacement body into a sub-AST -- it's an opaque
        `preproc_arg` text blob -- so the target is extracted with a regex looking for
        a leading identifier immediately followed by '('.
        """
        name_node = preproc_function_def_node.child_by_field_name('name')
        if not name_node:
            return
        short_name = source_code[name_node.start_byte:name_node.end_byte].decode('utf8', errors='ignore')

        arg_nodes = self._find_nodes_of_type(preproc_function_def_node, 'preproc_arg')
        if not arg_nodes:
            return
        replacement_text = source_code[arg_nodes[0].start_byte:arg_nodes[0].end_byte].decode('utf8', errors='ignore')

        match = self.macro_alias_target_re.match(replacement_text)
        if not match:
            
            
            
            
            
            
            
            
            
            
            
            
            if short_name.startswith('Rte_') and self.accessor_macro_body_re.match(replacement_text):
                self.builder.mark_late_bound_accessor(short_name)
            return
        long_name = match.group(1)
        if long_name and long_name != short_name:
            self.builder.add_macro_alias(short_name, long_name)

    def _extract_all_declared_identifiers(self, node, source_code: bytes) -> list:
        """
        Returns every identifier declared by a (possibly comma-separated) `declaration`
        node, e.g. all of a/b/c in `uint32 a, b, c;` or p/q in `uint8 *p, *q;`.
        _extract_first_identifier only ever returns the first hit from a depth-first
        walk, so every variable after the first in a multi-declarator statement was
        previously dropped from the graph entirely.
        """
        names = []
        declarator_types = ('identifier', 'init_declarator', 'pointer_declarator', 'array_declarator')
        found_any = False
        for child in node.children:
            if child.type in declarator_types:
                found_any = True
                name = self._extract_first_identifier(child, source_code)
                if name:
                    names.append(name)
        if not found_any:
            
            
            single = self._extract_first_identifier(node, source_code)
            if single:
                names.append(single)
        return names

    def _extract_first_identifier(self, node, source_code: bytes):
        stack = [node]
        
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

