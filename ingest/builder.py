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
            properties={
                "name": name, 
                "storage_uri": uri, 
                "byte_span": byte_span,
                "is_vendor_code": is_vendor_code,
                "is_hardware_entry": is_isr_task
            }
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

    def add_uds_handler(self, func_id: str, did_hex: str, operation: str):
        uds_id = self.generate_node_id(NodeLabel.UDS_SERVICE, did_hex)
        self._nodes[uds_id] = GraphNode(
            id=uds_id, 
            labels=[NodeLabel.UDS_SERVICE], 
            properties={"did": did_hex, "name": f"DID_{did_hex}"}
        )
        self._edges.append(GraphEdge(
            source_id=func_id, target_id=uds_id,
            type=EdgeType.HANDLES_UDS, properties={"operation": operation}
        ))

    def add_network_signal(self, func_id: str, signal_name: str, direction: str):
        sig_id = self.generate_node_id(NodeLabel.NETWORK_SIGNAL, signal_name)
        self._nodes[sig_id] = GraphNode(
            id=sig_id, 
            labels=[NodeLabel.NETWORK_SIGNAL], 
            properties={"name": signal_name, "direction": direction}
        )
        edge_type = EdgeType.RECEIVES_SIGNAL if direction == "RX" else EdgeType.SENDS_SIGNAL
        self._edges.append(GraphEdge(source_id=func_id, target_id=sig_id, type=edge_type, properties={}))

    def add_call_edge(self, caller_id: str, callee_name: str) -> None:
        self._edges.append(GraphEdge(
            source_id=caller_id, target_name=callee_name, type=EdgeType.CALLS, properties={}
        ))

    # --- UPGRADED: Differentiate between Reads and Writes for Vulnerability Detection ---
    def add_var_access_edge(self, func_id: str, var_name: str, is_write: bool):
        edge_type = EdgeType.WRITES_VAR if is_write else EdgeType.READS_VAR
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
