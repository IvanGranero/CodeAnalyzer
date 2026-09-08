"""Pure formatting helpers for serialized graph neighborhoods."""

from typing import Any


def node_record(name: str, kind: str, node_id: Any = None, **properties) -> dict[str, Any]:
    record = {"id": node_id, "type": kind, "name": name}
    record.update(properties)
    return record


def path_excerpt(function_name: str, source_name: str | None, sink_name: str | None) -> str:
    if source_name and sink_name:
        return f"{source_name} -> {function_name} -> {sink_name}"
    if source_name:
        return f"{source_name} -> {function_name}"
    if sink_name:
        return f"{function_name} -> {sink_name}"
    return function_name


def empty_function_payload(function_name: str) -> dict[str, Any]:
    return {
        "id": None,
        "name": function_name,
        "file": None,
        "tainted_by_uds": False,
        "reachable_dids": [],
        "is_vendor_library": False,
        "is_hardware_entry": False,
        "has_data_race_risk": False,
        "is_dead_code": False,
        "is_stub_node": False,
    }
