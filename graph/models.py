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
        nodes_dict = [n.model_dump(mode='json') for n in self.nodes]
        edges_dict = [e.model_dump(mode='json') for e in self.edges]
        return nodes_dict, edges_dict
