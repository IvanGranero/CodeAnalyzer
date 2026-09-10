"""Allow-listed read-only retrieval tools for analyzer agents."""

import json
import ast
from typing import Callable


TOOL_DEFINITIONS = [
    {
        "type": "function",
        "name": "get_function_metadata",
        "description": "Get graph metadata and UDS entry-point provenance for a function.",
        "parameters": {"type": "object", "properties": {"function_name": {"type": "string"}}, "required": ["function_name"]},
    },
    {
        "type": "function",
        "name": "get_uds_contract",
        "description": "Get the deterministic UDS/DID/RID protocol contract and explicit missing facts for a function.",
        "parameters": {"type": "object", "properties": {"function_name": {"type": "string"}}, "required": ["function_name"]},
    },
    {
        "type": "function",
        "name": "get_callers_and_entry_points",
        "description": "Get callers, UDS triggers, network triggers, and hardware-entry status.",
        "parameters": {"type": "object", "properties": {"function_name": {"type": "string"}}, "required": ["function_name"]},
    },
    {
        "type": "function",
        "name": "get_callees",
        "description": "Get direct callees and dangerous-sink metadata.",
        "parameters": {"type": "object", "properties": {"function_name": {"type": "string"}}, "required": ["function_name"]},
    },
    {
        "type": "function",
        "name": "get_variable_access",
        "description": "Get global variable reads and writes for a function.",
        "parameters": {"type": "object", "properties": {"function_name": {"type": "string"}}, "required": ["function_name"]},
    },
    {
        "type": "function",
        "name": "get_related_global_accesses",
        "description": "Get every resolved read/write of globals used by a function, including accessor functions and source spans.",
        "parameters": {"type": "object", "properties": {"function_name": {"type": "string"}, "symbol": {"type": "string"}}, "required": ["function_name"]},
    },
    {
        "type": "function",
        "name": "get_concurrency_metadata",
        "description": "Get task, ISR, lock, exclusive-area, and graph data-race metadata for a function.",
        "parameters": {"type": "object", "properties": {"function_name": {"type": "string"}}, "required": ["function_name"]},
    },
    {
        "type": "function",
        "name": "get_preprocessed_source",
        "description": "Get the indexed implementation source for a requested build variant and report whether a preprocessed variant exists.",
        "parameters": {"type": "object", "properties": {"function_name": {"type": "string"}, "build_variant": {"type": "string"}}, "required": ["function_name"]},
    },
    {
        "type": "function",
        "name": "get_related_taint_paths",
        "description": "Get verified UDS-to-function graph paths for a function.",
        "parameters": {"type": "object", "properties": {"function_name": {"type": "string"}, "max_hops": {"type": "integer", "minimum": 0, "maximum": 12}}, "required": ["function_name"]},
    },
    {
        "type": "function",
        "name": "get_type_layout",
        "description": "Get an indexed type definition and layout-related properties; report when compiler layout data is unavailable.",
        "parameters": {"type": "object", "properties": {"type_name": {"type": "string"}}, "required": ["type_name"]},
    },
    {
        "type": "function",
        "name": "get_type_definition",
        "description": "Get a bounded source span for a type definition.",
        "parameters": {"type": "object", "properties": {"type_name": {"type": "string"}}, "required": ["type_name"]},
    },
    {
        "type": "function",
        "name": "get_macro_definition",
        "description": "Get a preprocessor macro definition.",
        "parameters": {"type": "object", "properties": {"macro_name": {"type": "string"}}, "required": ["macro_name"]},
    },
]


class ReadOnlyToolRegistry:
    def __init__(self, analyzer_tools, allowed_tools=None, audit_callback=None):
        self.tools = analyzer_tools
        self.activity_callback = None
        self.audit_callback = audit_callback
        self.allowed_tools = frozenset(allowed_tools) if allowed_tools is not None else None
        self.handlers = {
            "get_function_metadata": lambda function_name: self.tools.get_function_metadata(function_name),
            "get_uds_contract": lambda function_name: self.tools.get_uds_contract(function_name),
            "get_callers_and_entry_points": lambda function_name: self.tools.get_callers_and_entry_points(function_name),
            "get_callees": lambda function_name: self.tools.get_callees(function_name),
            "get_variable_access": lambda function_name: self.tools.get_variable_access(function_name),
            "get_related_global_accesses": lambda function_name, symbol=None: self.tools.get_related_global_accesses(function_name, symbol),
            "get_concurrency_metadata": lambda function_name: self.tools.get_concurrency_metadata(function_name),
            "get_preprocessed_source": lambda function_name, build_variant="default": self.tools.get_preprocessed_source(function_name, build_variant),
            "get_related_taint_paths": lambda function_name, max_hops=8: self.tools.get_related_taint_paths(function_name, max_hops),
            "get_type_definition": self.tools.get_type_definition,
            "get_type_layout": self.tools.get_type_layout,
            "get_macro_definition": self.tools.get_macro_definition,
        }

    def definitions(self):
        if self.allowed_tools is None:
            return TOOL_DEFINITIONS
        return [definition for definition in TOOL_DEFINITIONS if definition["name"] in self.allowed_tools]

    def scoped(self, allowed_tools, audit_callback=None):
        scoped_registry = ReadOnlyToolRegistry(
            self.tools,
            allowed_tools=allowed_tools,
            audit_callback=audit_callback,
        )
        scoped_registry.activity_callback = self.activity_callback
        return scoped_registry

    def set_activity_callback(self, callback) -> None:
        self.activity_callback = callback

    def call(self, name: str, arguments: dict) -> str:
        if self.allowed_tools is not None and name not in self.allowed_tools:
            return json.dumps({"error": f"Tool '{name}' is not allowed for this agent."})
        if self.activity_callback is not None:
            callback = getattr(self.activity_callback, "tool", None)
            if callback is not None:
                import asyncio
                result = callback(name)
                if asyncio.iscoroutine(result):
                    asyncio.create_task(result)
        handler: Callable | None = self.handlers.get(name)
        if handler is None:
            return json.dumps({"error": f"Tool '{name}' is not allow-listed."})
        try:
            result = handler(**arguments)
            if isinstance(result, str):
                try:
                    output = json.dumps(ast.literal_eval(result), ensure_ascii=False)
                except (ValueError, SyntaxError):
                    output = result
            else:
                output = json.dumps(result, ensure_ascii=False)
            if self.audit_callback is not None:
                self.audit_callback(name, arguments, output)
            return output
        except Exception as exc:
            output = json.dumps({"error": f"Tool '{name}' failed: {exc}"})
            if self.audit_callback is not None:
                self.audit_callback(name, arguments, output)
            return output
