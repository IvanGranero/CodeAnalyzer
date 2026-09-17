from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from tools.graph.db import GraphDB
from tools.graph.graph_projection import GraphProjection, project_records


@dataclass(frozen=True)
class GraphQueryResult:
    question: str
    cypher: str
    parameters: dict[str, Any]
    rows: list[dict[str, Any]]
    projection: GraphProjection
    answer: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": "success",
            "question": self.question,
            "cypher": self.cypher,
            "parameters": self.parameters,
            "answer": self.answer,
            "rows": self.rows,
            "graph": self.projection.to_dict(),
        }


@dataclass(frozen=True)
class QueryPlan:
    cypher: str
    parameters: dict[str, Any]
    answer: Callable[[list[dict[str, Any]]], str]


class GraphQueryService:
    """Read-only natural-language graph exploration service."""

    _FUNCTION = r"([A-Za-z_][A-Za-z0-9_]*)"

    def __init__(self, db: GraphDB, nl_engine: Any = None, max_rows: int = 200) -> None:
        self.db = db
        self.nl_engine = nl_engine
        self.max_rows = max_rows

    def ask(self, question: str) -> dict[str, Any]:
        question = question.strip()
        if not question:
            return {"status": "error", "message": "Question cannot be empty."}
        plan = self._plan(question)
        if plan is None:
            return self._ask_with_nl_engine(question)
        try:
            records = self._execute(plan.cypher, plan.parameters)
            projection = project_records(records)
            return GraphQueryResult(
                question=question,
                cypher=plan.cypher,
                parameters=plan.parameters,
                rows=records,
                projection=projection,
                answer=plan.answer(records),
            ).to_dict()
        except Exception as exc:
            return {
                "status": "error",
                "question": question,
                "cypher": plan.cypher,
                "message": f"Graph query failed: {exc}",
            }

    def _execute(self, cypher: str, parameters: Mapping[str, Any]) -> list[dict[str, Any]]:
        with self.db.driver.session() as session:
            result = session.execute_read(
                lambda tx: list(tx.run(cypher, **dict(parameters)))
            )
        return [record.data() for record in result]

    def _ask_with_nl_engine(self, question: str) -> dict[str, Any]:
        if self.nl_engine is None:
            return {
                "status": "error",
                "question": question,
                "message": "No deterministic query matched and no NL-to-Cypher engine is configured.",
            }
        result = self.nl_engine.query_and_execute(question, allow_write=False)
        if result.get("status") != "success":
            return result
        rows = result.get("data", [])[: self.max_rows]
        projection = project_records(rows)
        return {
            **result,
            "answer": self._generic_answer(rows),
            "rows": rows,
            "graph": projection.to_dict(),
        }

    def _plan(self, question: str) -> QueryPlan | None:
        normalized = re.sub(r"\s+", " ", question.strip().lower())
        if re.search(
            r"(?:what|which) functions? (?:are )?(?:uds[- ]related|related to uds)"
            r"|what is (?:uds[- ]related|related to uds)",
            normalized,
        ):
            return QueryPlan(
                cypher=(
                    "MATCH (function:Function) "
                    "WHERE coalesce(function.tainted_by_uds, false) = true "
                    "OR size(coalesce(function.reachable_from_dids, [])) > 0 "
                    "OR EXISTS { MATCH (function)-[:HANDLES_UDS]->() } "
                    "RETURN function LIMIT $limit"
                ),
                parameters={"limit": self.max_rows},
                answer=lambda rows: self._name_answer(
                    rows,
                    "function",
                    "No UDS-related functions were found.",
                    "UDS-related functions:",
                ),
            )
        match = re.search(rf"(?:who|which functions) calls?\s+(?:function\s+)?['\"]?{self._FUNCTION}['\"]?", normalized)
        if match:
            name = match.group(1)
            return QueryPlan(
                cypher=(
                    "MATCH (caller:Function)-[r:CALLS]->(target:Function {name: $function_name}) "
                    "RETURN caller, r, target LIMIT $limit"
                ),
                parameters={"function_name": name, "limit": self.max_rows},
                answer=lambda rows: self._name_answer(rows, "caller", f"No functions call {name}.", f"Functions calling {name}:"),
            )

        match = re.search(rf"(?:what does|which functions does) (?:function\s+)?['\"]?{self._FUNCTION}['\"]?\s+call", normalized)
        if match:
            name = match.group(1)
            return QueryPlan(
                cypher=(
                    "MATCH (source:Function {name: $function_name})-[r:CALLS]->(callee:Function) "
                    "RETURN source, r, callee LIMIT $limit"
                ),
                parameters={"function_name": name, "limit": self.max_rows},
                answer=lambda rows: self._name_answer(rows, "callee", f"{name} does not call any indexed functions.", f"Functions called by {name}:"),
            )

        match = re.search(rf"(?:who|which functions) handles?\s+(?:uds\s+)?(?:did|rid)\s+['\"]?(0x)?([0-9a-f]{{4}})['\"]?", normalized)
        if match:
            identifier = match.group(2).upper()
            return QueryPlan(
                cypher=(
                    "MATCH (function:Function)-[r:HANDLES_UDS]->(service:UdsService) "
                    "WHERE toUpper(coalesce(service.did, service.rid, '')) = $identifier "
                    "RETURN function, r, service LIMIT $limit"
                ),
                parameters={"identifier": identifier, "limit": self.max_rows},
                answer=lambda rows: self._name_answer(rows, "function", f"No functions handle UDS identifier {identifier}.", f"Functions handling UDS identifier {identifier}:"),
            )
        return None

    @staticmethod
    def _name_answer(rows: list[dict[str, Any]], key: str, empty: str, prefix: str) -> str:
        names = []
        for row in rows:
            value = row.get(key)
            if value is not None and hasattr(value, "get") and value.get("name"):
                names.append(str(value["name"]))
        names = list(dict.fromkeys(names))
        return empty if not names else f"{prefix} " + ", ".join(names) + "."

    @staticmethod
    def _generic_answer(rows: list[dict[str, Any]]) -> str:
        if not rows:
            return "The graph returned no matching records."
        return f"The graph returned {len(rows)} matching record(s)."
