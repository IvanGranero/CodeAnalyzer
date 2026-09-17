import json

from pydantic import BaseModel, Field, ConfigDict
from typing import List, Dict, Any, Optional
from enum import Enum

class EdgeType(str, Enum):
    CALLS = "CALLS"
    READS_VAR = "READS_VAR"    
    WRITES_VAR = "WRITES_VAR"  
    HANDLES_UDS = "HANDLES_UDS"
    RECEIVES_SIGNAL = "RECEIVES_SIGNAL"
    SENDS_SIGNAL = "SENDS_SIGNAL"
    IMPLEMENTS_TASK = "IMPLEMENTS_TASK" 
    DEPENDS_ON_TYPE = "DEPENDS_ON_TYPE"  
    USES_MACRO = "USES_MACRO"          
    OS_LOCK_ACTION = "OS_LOCK_ACTION"
    RTE_DATA_FLOW = "RTE_DATA_FLOW"
    RELATED_TO = "RELATED_TO"
    LOCATED_IN = "LOCATED_IN"

class NodeLabel(str, Enum):
    GRAPH_NODE = "GraphNode" 
    FUNCTION = "Function"
    GLOBAL_VARIABLE = "GlobalVariable"
    VULNERABILITY = "Vulnerability"
    UDS_SERVICE = "UdsService"
    NETWORK_SIGNAL = "NetworkSignal"
    TYPE_DEFINITION = "TypeDefinition" 
    MACRO_DEFINITION = "MacroDefinition"
    OS_TASK = "OsTask"
    OS_ISR = "OsIsr"
    OS_RESOURCE = "OsResource"
    STUB = "Stub"
    
    
    
    
    
    
    
    DCM_DID_TABLE_ENTRY = "DcmDidTableEntry"

class GraphNode(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(...)
    labels: List[NodeLabel] = Field(...)
    properties: Dict[str, Any] = Field(default_factory=dict)

class GraphEdge(BaseModel):
    source_id: str = Field(...)
    target_id: Optional[str] = Field(None)
    target_name: Optional[str] = Field(None)
    type: EdgeType = Field(...)
    properties: Dict[str, Any] = Field(default_factory=dict)

class IngestBatch(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]

    def to_neo4j_dicts(self) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        nodes_dict = [self._neo4j_record(n.model_dump(mode='json')) for n in self.nodes]
        edges_dict = [self._neo4j_record(e.model_dump(mode='json')) for e in self.edges]
        return nodes_dict, edges_dict

    @staticmethod
    def _neo4j_record(record: Dict[str, Any]) -> Dict[str, Any]:
        """Flatten nested Python maps at the Neo4j property boundary.

        The in-memory graph remains richly modeled for late binding. Neo4j node and
        relationship properties, however, accept only primitives or primitive arrays.
        Nested evidence maps are therefore retained as compact JSON strings.
        """
        result = dict(record)
        properties = result.get("properties")
        if isinstance(properties, dict):
            result["properties"] = {
                key: json.dumps(value, separators=(",", ":"), ensure_ascii=False)
                if isinstance(value, dict)
                else value
                for key, value in properties.items()
            }
        return result
