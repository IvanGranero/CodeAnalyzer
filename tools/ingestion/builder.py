import hashlib
from typing import List, Dict, Optional
import logging

from tools.graph.models import GraphNode, GraphEdge, NodeLabel, EdgeType, IngestBatch

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
        
        label = NodeLabel(entity_type) 
        
        node_id = self.generate_node_id(label, name, uri)
        
        
        final_props = {"name": name, "storage_uri": uri}
        final_props.update(properties)
        
        self._nodes[node_id] = GraphNode(
            id=node_id,
            labels=[label], 
            properties=final_props
        )
        return node_id

    def add_uds_handler(self, func_id: str, did_hex: str, operation: str, kind: str = "did"):
        uds_id = self.generate_node_id(NodeLabel.UDS_SERVICE, did_hex)
        normalized_id = str(did_hex).upper().removeprefix("0X")
        is_routine = kind == "rid"
        contract = {
            "kind": kind,
            "identifier": f"0x{normalized_id}",
            "operation": operation,
            "request_layout": None,
            "source": "name_heuristic",
            "confidence": "partial",
            "missing_facts": ["request layout", "request length"],
        }
        if is_routine:
            subfunction = {
                "Start": "0x01",
                "Stop": "0x02",
                "RequestResults": "0x03",
            }.get(operation)
            if subfunction is not None:
                contract["subfunction"] = subfunction
            contract["missing_facts"].append("control option record layout")
        self._nodes[uds_id] = GraphNode(
            id=uds_id,
            labels=[NodeLabel.UDS_SERVICE],
            properties={
                "did": did_hex,
                "name": f"DID_{did_hex}",
                "protocol_contract": contract,
            },
        )
        self._edges.append(GraphEdge(
            source_id=func_id,
            target_id=uds_id,
            type=EdgeType.HANDLES_UDS,
            properties={"operation": operation, "kind": kind, "source": "name_heuristic"},
        ))

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
        entry_id = self.generate_node_id(NodeLabel.DCM_DID_TABLE_ENTRY, f"{function_name}::{did_hex}")
        self._nodes[entry_id] = GraphNode(
            id=entry_id,
            labels=[NodeLabel.DCM_DID_TABLE_ENTRY],
            properties={"function_name": function_name, "did_hex": did_hex, "func_class_hex": func_class_hex}
        )

    def add_dcm_requirement(
        self,
        identifier_hex: str,
        kind: str,
        *,
        session_bitmask: int = 0,
        security_bitmask: int = 0,
        sessions: list | None = None,
        security_levels: list | None = None,
        operations: int | None = None,
    ):
        identifier = str(identifier_hex).upper().replace("0X", "")
        entry_id = self.generate_node_id(
            NodeLabel.DCM_SECURITY_REQUIREMENT,
            f"{kind}::{identifier}",
        )
        sessions = sessions or []
        security_levels = security_levels or []
        self._nodes[entry_id] = GraphNode(
            id=entry_id,
            labels=[NodeLabel.DCM_SECURITY_REQUIREMENT],
            properties={
                "identifier_hex": identifier,
                "kind": kind,
                "session_bitmask": int(session_bitmask or 0),
                "security_bitmask": int(security_bitmask or 0),
                # Neo4j-native primitive arrays (zero JSON decode needed downstream).
                "required_session_subfunctions": [
                    int(session.get("session_subfunction", 0)) for session in sessions if session.get("session_subfunction") is not None
                ],
                "required_seed_subfunctions": [
                    int(level.get("seed_subfunction", 0)) for level in security_levels if level.get("seed_subfunction") is not None
                ],
                "required_key_subfunctions": [
                    int(level.get("key_subfunction", 0)) for level in security_levels if level.get("key_subfunction") is not None
                ],
                **({"operations": int(operations)} if operations is not None else {}),
            },
        )
        return entry_id

    def add_macro_alias(self, short_name: str, long_name: str):
        alias_stub_id = f"stub::{short_name}"
        self._nodes[alias_stub_id] = GraphNode(
            id=alias_stub_id,
            labels=[NodeLabel.GRAPH_NODE],
            properties={"name": short_name, "alias_target": long_name}
        )

    def mark_late_bound_accessor(self, short_name: str):
        stub_id = f"stub::{short_name}"
        self._nodes[stub_id] = GraphNode(
            id=stub_id,
            labels=[NodeLabel.GRAPH_NODE],
            properties={"name": short_name, "is_late_bound_accessor": True}
        )

    def add_var_access_edge(self, func_id: str, var_name: str, is_write: bool, target_id: Optional[str] = None):
        edge_type = EdgeType.WRITES_VAR if is_write else EdgeType.READS_VAR
        if target_id:
            
            
            
            self._edges.append(GraphEdge(
                source_id=func_id,
                target_id=target_id,
                type=edge_type,
                properties={"resolution": "exact"},
            ))
        else:
            self._edges.append(GraphEdge(
                source_id=func_id,
                target_name=var_name,
                type=edge_type,
                properties={"resolution": "fuzzy"},
            ))

    def is_ready_to_flush(self) -> bool:
        return (len(self._nodes) + len(self._edges)) >= self.batch_size

    def flush_batch(self) -> IngestBatch:
        batch = IngestBatch(nodes=list(self._nodes.values()), edges=self._edges)
        self._nodes = {}
        self._edges = []
        return batch

    def flush_all(self) -> IngestBatch:
        return self.flush_batch()
