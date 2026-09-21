from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

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


class GraphQueryService:
    """Natural-language graph exploration backed by the read-only NL engine."""

    def __init__(self, db: GraphDB, nl_engine: Any = None, max_rows: int = 200) -> None:
        self.db = db
        self.nl_engine = nl_engine
        self.max_rows = max_rows

    def ask(
        self,
        question: str,
        function_names: list[str] | None = None,
    ) -> dict[str, Any]:
        question = question.strip()
        if not question:
            return {"status": "error", "message": "Question cannot be empty."}
        if self.nl_engine is None:
            return {
                "status": "error",
                "question": question,
                "message": "No NL-to-Cypher engine is configured.",
            }
        original_question = question
        if function_names:
            question = question + (
                "\n\nPREVIOUS_RESULT_SCOPE (mandatory): The user is asking about the immediately "
                "previous result. Restrict the query to Function.name values in this "
                "exact JSON list. Do not search functions outside this list, and do not "
                "treat these names as a new unconstrained search:\n"
                + json.dumps(function_names, ensure_ascii=False)
            )
        try:
            result = self.nl_engine.query_and_execute(question, allow_write=False)
        except Exception as exc:
            return {
                "status": "error",
                "question": original_question,
                "message": f"Graph query failed: {exc}",
            }
        if result.get("status") != "success":
            return {**result, "question": original_question}
        rows = result.get("data", [])[: self.max_rows]
        return GraphQueryResult(
            question=original_question,
            cypher=str(result.get("cypher", "")),
            parameters={},
            rows=rows,
            projection=project_records(rows),
            answer=self._generic_answer(rows),
        ).to_dict()

    @staticmethod
    def _generic_answer(rows: list[dict[str, Any]]) -> str:
        if not rows:
            return "The graph returned no matching records."
        rendered = []
        for row in rows[:50]:
            values = []
            non_empty = [(key, value) for key, value in row.items() if value is not None]
            for key, value in row.items():
                entity_name = GraphQueryService._entity_name(value)
                if entity_name is not None:
                    value = entity_name
                if value is None:
                    continue
                if len(non_empty) == 1 and len(str(key)) <= 2:
                    values.append(str(value))
                    continue
                values.append(f"{key}={value}")
            rendered.append(", ".join(values))
        suffix = f" ... ({len(rows)} total)" if len(rows) > 50 else ""
        return "Matching records: " + "; ".join(rendered) + suffix + "."

    @staticmethod
    def _entity_name(value: Any) -> str | None:
        if isinstance(value, dict) and value.get("name"):
            return str(value["name"])
        if hasattr(value, "get"):
            try:
                name = value.get("name")
            except (AttributeError, TypeError):
                return None
            if name:
                return str(name)
        return None
