import hashlib
from typing import List, Dict, Optional
import logging

from graph.models import GraphNode, GraphEdge, NodeLabel, EdgeType, IngestBatch

logger = logging.getLogger(__name__)

class GraphPayloadBuilder:
    def __init__(self, batch_size: int = 5000):
        self.batch_size = batch_size
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[GraphEdge] = []
    
    @staticmethod
    def generate_node_id(label: str, name: str, uri: str = "") -> str:
        unique_string = f"{label}::{name}::{uri}"
        return hashlib.sha256(unique_string.encode('utf-8')).hexdigest()

    def add_function_node(self, name: str, uri: str, byte_span: str, is_vendor_code: bool = False, is_isr_task: bool = False) -> str:
        node_id = self.generate_node_id(NodeLabel.FUNCTION, name, uri)
        self._nodes[node_id] = GraphNode(
            id=node_id,
            labels=[NodeLabel.FUNCTION],
            properties={"name": name, "storage_uri": uri, "byte_span": byte_span, "is_vendor_code": is_vendor_code, "is_hardware_entry": is_isr_task}
        )
        return node_id

    def add_global_variable(self, name: str, uri: str, byte_span: str):
        var_id = self.generate_node_id(NodeLabel.GLOBAL_VARIABLE, name, uri)
        self._nodes[var_id] = GraphNode(
            id=var_id, 
            labels=[NodeLabel.GLOBAL_VARIABLE],
            properties={"name": name, "storage_uri": uri, "byte_span": byte_span}
        )
        return var_id

    def add_type_definition(self, name: str, uri: str, byte_span: str):
        type_id = self.generate_node_id(NodeLabel.TYPE_DEFINITION, name, uri)
        self._nodes[type_id] = GraphNode(
            id=type_id,
            labels=[NodeLabel.TYPE_DEFINITION], 
            properties={"name": name, "storage_uri": uri, "byte_span": byte_span}
        )
        return type_id

    def add_macro_definition(self, name: str, value: str, uri: str, byte_span: str):
        macro_id = self.generate_node_id(NodeLabel.MACRO_DEFINITION, name, uri)
        self._nodes[macro_id] = GraphNode(
            id=macro_id,
            labels=[NodeLabel.MACRO_DEFINITION], 
            properties={"name": name, "value": value, "storage_uri": uri, "byte_span": byte_span}
        )
        return macro_id

    def add_os_entity(self, entity_type: str, name: str, uri: str, properties: dict):
        """Creates OsTask, OsIsr, or OsResource nodes from ARXML configuration."""
        # Convert string entity_type to NodeLabel enum safely
        label = NodeLabel(entity_type) 
        
        node_id = self.generate_node_id(label, name, uri)
        
        # Merge base properties with specific properties (like priority)
        final_props = {"name": name, "storage_uri": uri}
        final_props.update(properties)
        
        self._nodes[node_id] = GraphNode(
            id=node_id,
            labels=[label], 
            properties=final_props
        )
        return node_id

    def add_uds_handler(self, func_id: str, did_hex: str, operation: str):
        uds_id = self.generate_node_id(NodeLabel.UDS_SERVICE, did_hex)
        self._nodes[uds_id] = GraphNode(
            id=uds_id, labels=[NodeLabel.UDS_SERVICE], properties={"did": did_hex, "name": f"DID_{did_hex}"}
        )
        self._edges.append(GraphEdge(source_id=func_id, target_id=uds_id, type=EdgeType.HANDLES_UDS, properties={"operation": operation}))

    def add_network_signal(self, func_id: str, signal_name: str, direction: str):
        sig_id = self.generate_node_id(NodeLabel.NETWORK_SIGNAL, signal_name)
        self._nodes[sig_id] = GraphNode(
            id=sig_id, labels=[NodeLabel.NETWORK_SIGNAL], properties={"name": signal_name, "direction": direction}
        )
        edge_type = EdgeType.RECEIVES_SIGNAL if direction == "RX" else EdgeType.SENDS_SIGNAL
        self._edges.append(GraphEdge(source_id=func_id, target_id=sig_id, type=edge_type, properties={}))

    def add_call_edge(self, caller_id: str, target_name: str, arguments: Optional[List[str]] = None, is_pointer: bool = False) -> None:
        props = {"arguments": arguments} if arguments else {}
        props["call_type"] = "pointer" if is_pointer else "direct"
        self._edges.append(GraphEdge(
            source_id=caller_id, target_name=target_name, type=EdgeType.CALLS, properties=props
        ))

    def add_dcm_did_table_entry(self, function_name: str, did_hex: str, func_class_hex: str = ""):
        """
        Records one (function, DID) pair scraped directly from a generated Dcm DID
        dispatch table (e.g. Dcm_CfgDidMgrSignalOpClassInfo[] in Dcm_Lcfg.c/Dcm_PBcfg.c).
        This is the module's own authoritative, generator-produced source of truth for
        which function handles which DID -- independent of whatever naming convention
        the callback function happens to use. graph/resolver.py's
        _resolve_dcm_did_table_entries later resolves function_name to the real
        Function node and creates the HANDLES_UDS edge from it.
        """
        entry_id = self.generate_node_id(NodeLabel.DCM_DID_TABLE_ENTRY, f"{function_name}::{did_hex}")
        self._nodes[entry_id] = GraphNode(
            id=entry_id,
            labels=[NodeLabel.DCM_DID_TABLE_ENTRY],
            properties={"function_name": function_name, "did_hex": did_hex, "func_class_hex": func_class_hex}
        )

    def add_macro_alias(self, short_name: str, long_name: str):
        """
        Records a function-like preprocessor macro that is a pure pass-through alias
        for another function (the extremely common Vector MICROSAR RTE pattern
        `#define Rte_IrvRead_SHORT(...) Rte_IrvRead_LONG(...)` used for essentially all
        Rte_Read_/Rte_Write_/Rte_Call_/Rte_IrvRead_/Rte_IrvWrite_ port accessors).

        Call sites always use the SHORT name textually, but the actual Function node
        (from the FUNC declaration/definition) is only ever registered under the LONG
        name -- so without this, every such call resolves to a dead-end stub instead of
        the real function, and the real function looks like it's never called at all.

        Writes directly to the deterministic id "stub::<short_name>" -- the exact same
        id graph/manager.py's fuzzy CALLS-edge resolution falls back to for an
        unresolved call target. This makes the mapping order-independent: it doesn't
        matter whether the macro's defining header or a caller's .c file is parsed
        first, because Neo4j MERGE-by-id converges onto the same node either way.
        graph/resolver.py's _resolve_macro_call_aliases then redirects any CALLS edge
        landing on that stub onto the real target and removes the stub.
        """
        alias_stub_id = f"stub::{short_name}"
        self._nodes[alias_stub_id] = GraphNode(
            id=alias_stub_id,
            labels=[NodeLabel.GRAPH_NODE],
            properties={"name": short_name, "alias_target": long_name}
        )

    def mark_late_bound_accessor(self, short_name: str):
        """
        Records that `short_name` is a late-bound AUTOSAR RTE accessor macro (e.g.
        Rte_Pim_*/Rte_CData_*) whose replacement body is a pointer/address-of
        expression, not a call to another function -- confirmed against real Vector
        MICROSAR headers:
            #define Rte_Pim_..._17() (&((*RtePim_..._17())[0]))
            #define Rte_CData_RomData_VIN() (&(Rte_..._RomData_VIN[0]))
        Call sites using this name are NOT unresolved/missing calls; they are
        placeholders that bind to real memory/config at build time (the source tree
        is parsed as-is, never built) and must never be reported as dead ends.

        Written to the same deterministic "stub::<name>" id that an unresolved CALLS
        edge falls back to (see graph/manager.py's fuzzy-edge ingestion) via a plain
        property SET -- so this is order-independent exactly like add_macro_alias:
        it doesn't matter whether the accessor's defining header or a caller's .c
        file is parsed/flushed first. If the fuzzy-CALLS ingestion's MERGE happens to
        run first and creates the node as a :Stub, this property is still applied on
        top of it; consumers should check `is_late_bound_accessor`, not the absence
        of the :Stub label, to tell late-bound accessors apart from genuinely
        unresolved targets.
        """
        stub_id = f"stub::{short_name}"
        self._nodes[stub_id] = GraphNode(
            id=stub_id,
            labels=[NodeLabel.GRAPH_NODE],
            properties={"name": short_name, "is_late_bound_accessor": True}
        )

    def add_var_access_edge(self, func_id: str, var_name: str, is_write: bool, target_id: Optional[str] = None):
        edge_type = EdgeType.WRITES_VAR if is_write else EdgeType.READS_VAR
        if target_id:
            # Exact match: this variable is a global declared in the same file as the
            # accessing function, so we already know its real node id — no fuzzy
            # name-based resolution needed at ingestion time.
            self._edges.append(GraphEdge(source_id=func_id, target_id=target_id, type=edge_type, properties={}))
        else:
            self._edges.append(GraphEdge(source_id=func_id, target_name=var_name, type=edge_type, properties={}))

    def is_ready_to_flush(self) -> bool:
        return (len(self._nodes) + len(self._edges)) >= self.batch_size

    def flush_batch(self) -> IngestBatch:
        batch = IngestBatch(nodes=list(self._nodes.values()), edges=self._edges)
        self._nodes = {}
        self._edges = []
        return batch

    def flush_all(self) -> IngestBatch:
        return self.flush_batch()
