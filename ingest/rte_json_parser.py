import json
import logging
from typing import Any, Dict, List, Optional
from ingest.builder import GraphPayloadBuilder
from graph.models import GraphEdge, EdgeType, NodeLabel, GraphNode

logger = logging.getLogger(__name__)

class RteJsonParser:
    """
    Parses Vector / DaVinci RTE Analyzer configurations (e.g., RteAnalyzerConfiguration.json).
    Extracts ground-truth Runnable-to-Task mappings, Exclusive Areas, and Sender-Receiver data flows.
    """
    def __init__(self, builder: GraphPayloadBuilder):
        self.builder = builder

    def parse(self, filepath: str) -> None:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
        except Exception as e:
            logger.error(f"Failed to read/parse RTE JSON config {filepath}: {e}")
            return

        uri = f"file://{filepath}"
        logger.info(f"Extracting RTE Ground Truth from {filepath}...")

        self._extract_tasks_and_runnables(data, uri)
        self._extract_exclusive_areas(data, uri)
        self._extract_sender_receiver_flows(data, uri)
        logger.info(f"Successfully processed RTE ground truth from {filepath}")

    def _extract_tasks_and_runnables(self, data: Dict[str, Any], uri: str) -> None:
        """Maps Runnable entities to their hosting OsTasks with exact execution order/timing."""
        # 1. Inspect Tasks collection
        tasks = data.get("Tasks") or data.get("tasks") or data.get("OsTasks") or []
        for task in tasks:
            task_name = task.get("Name") or task.get("name") or task.get("ShortName")
            if not task_name:
                continue

            priority = task.get("Priority") or task.get("priority") or 0
            task_id = self.builder.generate_node_id(NodeLabel.OS_TASK, task_name, uri)
            
            # Register or update the Task Node
            self.builder._nodes[task_id] = GraphNode(
                id=task_id,
                labels=[NodeLabel.OS_TASK],
                properties={
                    "name": task_name,
                    "priority": int(priority),
                    "storage_uri": uri
                }
            )

            # Map Runnables under this Task
            runnables = task.get("MappedRunnables") or task.get("Runnables") or task.get("runnables") or []
            for r in runnables:
                r_symbol = r.get("Symbol") or r.get("symbol") or r.get("Name") or r.get("name")
                if not r_symbol:
                    continue

                # Add IMPLEMENTS_TASK edge from the function/runnable to the OsTask
                self.builder._edges.append(GraphEdge(
                    source_id=f"stub::{r_symbol}",
                    target_name=task_name,
                    type=EdgeType.IMPLEMENTS_TASK,
                    properties={
                        "execution_order": r.get("Order", 0),
                        "period_ms": r.get("Period", 0)
                    }
                ))

        # 2. Inspect standalone Runnables collection if formatted separately
        runnable_list = data.get("Runnables") or data.get("runnables") or []
        for r in runnable_list:
            symbol = r.get("Symbol") or r.get("symbol") or r.get("Name")
            mapped_task = r.get("Task") or r.get("task") or r.get("MappedTask")
            if symbol and mapped_task:
                self.builder._edges.append(GraphEdge(
                    source_id=f"stub::{symbol}",
                    target_name=mapped_task,
                    type=EdgeType.IMPLEMENTS_TASK,
                    properties={"period_ms": r.get("Period", 0)}
                ))

    def _extract_exclusive_areas(self, data: Dict[str, Any], uri: str) -> None:
        """Extracts configured lock mechanisms (None, AllInterrupts, OsResource)."""
        exclusive_areas = data.get("ExclusiveAreas") or data.get("exclusive_areas") or []
        for ea in exclusive_areas:
            ea_name = ea.get("Name") or ea.get("name")
            if not ea_name:
                continue

            mechanism = ea.get("Mechanism") or ea.get("LockingMechanism") or "ALL_INTERRUPTS"
            resource_id = self.builder.generate_node_id(NodeLabel.OS_RESOURCE, ea_name, uri)

            self.builder._nodes[resource_id] = GraphNode(
                id=resource_id,
                labels=[NodeLabel.OS_RESOURCE],
                properties={
                    "name": ea_name,
                    "mechanism": mechanism,
                    "is_exclusive_area": True,
                    "storage_uri": uri
                }
            )

            # Link accessing runnables to the Exclusive Area Resource
            accessing_runnables = ea.get("AccessingRunnables") or ea.get("Runnables") or []
            for r in accessing_runnables:
                r_symbol = r if isinstance(r, str) else (r.get("Symbol") or r.get("name"))
                if r_symbol:
                    self.builder._edges.append(GraphEdge(
                        source_id=f"stub::{r_symbol}",
                        target_name=ea_name,
                        type=EdgeType.CALLS,
                        properties={"call_type": "exclusive_area", "mechanism": mechanism}
                    ))

    def _extract_sender_receiver_flows(self, data: Dict[str, Any], uri: str) -> None:
        """Extracts deterministic S/R data channels between software components."""
        flows = data.get("DataFlows") or data.get("PortConnections") or data.get("SenderReceiverConnections") or []
        for flow in flows:
            sender = flow.get("SenderRunnable") or flow.get("Source")
            receiver = flow.get("ReceiverRunnable") or flow.get("Target")
            port_name = flow.get("Port") or flow.get("PortName") or "Rte_Port"
            data_type = flow.get("DataType") or flow.get("Type") or "Unknown"

            if sender and receiver:
                self.builder._edges.append(GraphEdge(
                    source_id=f"stub::{sender}",
                    target_name=receiver,
                    type=EdgeType.DEPENDS_ON_TYPE,
                    properties={
                        "context": "RTE_DATA_FLOW",
                        "port": port_name,
                        "data_type": data_type
                    }
                ))
