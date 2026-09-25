import json
import logging
from typing import Any, Dict, List, Optional
from tools.ingestion.builder import GraphPayloadBuilder
from tools.graph.models import GraphEdge, EdgeType, NodeLabel, GraphNode

logger = logging.getLogger(__name__)

class RteJsonParser:
    def __init__(self, builder: GraphPayloadBuilder):
        self.builder = builder
        self.last_result = {"status": "not_run", "flow_count": 0}

    def parse(self, filepath: str) -> None:
        self.last_result = {"status": "read_failed", "flow_count": 0}
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
        flow_count = self._extract_sender_receiver_flows(data, uri)
        self.last_result = {
            "status": "parsed_with_flows" if flow_count else "parsed_empty_flows",
            "flow_count": flow_count,
        }
        if flow_count:
            logger.info(f"Successfully processed RTE ground truth from {filepath}; extracted {flow_count} sender/receiver flows")
        else:
            logger.warning(
                "Processed RTE ground truth from %s, but it contains no sender/receiver flow records; "
                "RTE_DATA_FLOW resolution will rely on source-level accessor evidence",
                filepath,
            )

    def _extract_tasks_and_runnables(self, data: Dict[str, Any], uri: str) -> None:
        tasks = (
            data.get("Tasks")
            or data.get("tasks")
            or data.get("OsTasks")
            or data.get("TaskList")
            or []
        )
        for task in tasks:
            task_name = (
                task.get("Name")
                or task.get("name")
                or task.get("ShortName")
                or task.get("TaskName")
            )
            if not task_name:
                continue

            priority = task.get("Priority") or task.get("priority") or 0
            try:
                priority = int(priority)
            except (TypeError, ValueError):
                priority = 0
            task_id = self.builder.generate_node_id(NodeLabel.OS_TASK, task_name, uri)
            
            
            self.builder._nodes[task_id] = GraphNode(
                id=task_id,
                labels=[NodeLabel.OS_TASK],
                properties={
                    "name": task_name,
                    "priority": int(priority),
                    "storage_uri": uri
                }
            )

            runnables = task.get("MappedRunnables") or task.get("Runnables") or task.get("runnables") or []
            for r in runnables:
                r_symbol = r.get("Symbol") or r.get("symbol") or r.get("Name") or r.get("name")
                if not r_symbol:
                    continue

                self.builder._edges.append(GraphEdge(
                    source_id=f"stub::{r_symbol}",
                    target_name=task_name,
                    type=EdgeType.IMPLEMENTS_TASK,
                    properties={
                        "execution_order": r.get("Order", 0),
                        "period_ms": r.get("Period", 0)
                    }
                ))

            if not runnables and task.get("TaskName"):
                self.builder._edges.append(GraphEdge(
                    source_id=f"stub::{task_name}",
                    target_name=task_name,
                    type=EdgeType.IMPLEMENTS_TASK,
                    properties={"binding_source": "rte_task_list"},
                ))

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

    def _extract_sender_receiver_flows(self, data: Dict[str, Any], uri: str) -> int:
        """Extracts deterministic S/R data channels between software components."""
        flow_keys = {
            "dataflows", "rte_data_flows", "rtedataflows", "rtedataflowlist",
            "dataflowlist", "portconnections", "portconnectionlist",
            "senderreceiverconnections", "senderreceiverconnectionlist",
        }

        def collect_flow_records(value: Any, depth: int = 0) -> list[dict[str, Any]]:
            if depth > 4:
                return []
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
            if not isinstance(value, dict):
                return []
            records = []
            for key, child in value.items():
                normalized_key = "".join(char for char in str(key).lower() if char.isalnum() or char == "_")
                if normalized_key.replace("_", "") in {item.replace("_", "") for item in flow_keys}:
                    records.extend(collect_flow_records(child, depth + 1))
                elif isinstance(child, (dict, list)):
                    records.extend(collect_flow_records(child, depth + 1))
            return records

        flows = collect_flow_records(data)
        extracted = 0
        for flow in flows:
            if not isinstance(flow, dict):
                continue
            sender = (
                flow.get("SenderRunnable") or flow.get("SourceRunnable")
                or flow.get("Sender") or flow.get("Source")
            )
            receiver = (
                flow.get("ReceiverRunnable") or flow.get("TargetRunnable")
                or flow.get("Receiver") or flow.get("Target")
            )
            sender = flow.get("SenderFunction") or flow.get("SourceFunction") or sender
            receiver = flow.get("ReceiverFunction") or flow.get("TargetFunction") or receiver
            sender = flow.get("ProviderRunnable") or flow.get("Provider") or sender
            receiver = flow.get("RequesterRunnable") or flow.get("Requester") or receiver
            sender = self._endpoint_name(sender)
            receiver = self._endpoint_name(receiver)
            port_name = (
                flow.get("Port") or flow.get("PortName") or flow.get("PortPrototype")
                or flow.get("DataElement") or flow.get("DataElementName") or "Rte_Port"
            )
            data_type = flow.get("DataType") or flow.get("DataElementType") or flow.get("Type") or "Unknown"

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
                extracted += 1
        return extracted

    @staticmethod
    def _endpoint_name(endpoint: Any) -> Any:
        if not isinstance(endpoint, dict):
            return endpoint
        return (
            endpoint.get("Symbol") or endpoint.get("symbol")
            or endpoint.get("Name") or endpoint.get("name")
            or endpoint.get("Function") or endpoint.get("function")
            or endpoint.get("Runnable") or endpoint.get("runnable")
            or endpoint.get("Implementation") or endpoint.get("implementation")
        )
