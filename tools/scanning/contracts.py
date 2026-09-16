"""Typed contracts for LLM-backed vulnerability scanning."""

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator


class VulnerabilityClass(str, Enum):
    BUFFER_OVERFLOW = "buffer_overflow"
    INTEGER_OVERFLOW = "integer_overflow"
    OUT_OF_BOUNDS_ACCESS = "out_of_bounds_access"
    USE_AFTER_FREE = "use_after_free"
    NULL_DEREF = "null_deref"
    FORMAT_STRING = "format_string"
    DATA_RACE = "data_race"
    INJECTION = "injection"
    MISSING_VALIDATION = "missing_validation"
    ACCESS_CONTROL = "access_control"
    STATE_MANAGEMENT = "state_management"
    ERROR_HANDLING = "error_handling"
    OTHER = "other"


class ScanDecision(str, Enum):
    IGNORE = "ignore"
    ESCALATE = "escalate"
    REQUEST_MORE = "request_more"


class FindingStatus(str, Enum):
    SUPPORTED = "supported"
    DISPROVEN = "disproven"
    UNKNOWN = "unknown"


class EvidenceStatus(str, Enum):
    FOUND = "found"
    NOT_FOUND = "not_found"
    UNSUPPORTED = "unsupported"
    ERROR = "error"


class ArtifactRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    kind: str = "unknown"
    function: Optional[str] = None
    file: Optional[str] = None
    symbol: Optional[str] = None
    macro: Optional[str] = None
    span: Dict[str, Any] = Field(default_factory=dict)
    reason: Optional[str] = None

    @field_validator("span", mode="before")
    @classmethod
    def normalize_span(cls, value: Any) -> Dict[str, Any]:
        return value if isinstance(value, dict) else {}


class Candidate(BaseModel):
    model_config = ConfigDict(extra="ignore")

    vulnerability_class: VulnerabilityClass
    priority: int = Field(default=1, ge=1)
    rationale: str = ""
    effort_estimate: str = "medium"

    @field_validator("effort_estimate")
    @classmethod
    def validate_effort(cls, value: str) -> str:
        return value if value in {"low", "medium", "high"} else "medium"


class Coverage(BaseModel):
    model_config = ConfigDict(extra="allow")

    memory_safety: str = "insufficient_evidence"
    integer_arithmetic: str = "insufficient_evidence"
    taint_validation: str = "insufficient_evidence"
    concurrency: str = "insufficient_evidence"
    state_management: str = "insufficient_evidence"

    @field_validator("memory_safety", "integer_arithmetic", "taint_validation", "concurrency", "state_management")
    @classmethod
    def validate_coverage_state(cls, value: str) -> str:
        allowed = {"checked", "not_applicable", "insufficient_evidence"}
        return value if value in allowed else "insufficient_evidence"

    def incomplete(self) -> bool:
        return any(value == "insufficient_evidence" for value in self.model_dump().values())


class TriageResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    decision: ScanDecision
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reason: str = ""
    investigation_directive: str = ""
    vulnerability_candidates: List[Candidate] = Field(default_factory=list)
    coverage: Coverage = Field(default_factory=Coverage)

    @model_validator(mode="after")
    def validate_decision_payload(self):
        if self.decision == ScanDecision.ESCALATE:
            if not self.investigation_directive.strip():
                raise ValueError("escalate requires investigation_directive")
            if not self.vulnerability_candidates:
                raise ValueError("escalate requires at least one vulnerability candidate")
        return self


class EvidenceReference(BaseModel):
    model_config = ConfigDict(extra="ignore")

    source: str
    location: Optional[str] = None
    provenance: Optional[str] = None
    resolution: Optional[str] = None
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)


class ArtifactResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    status: EvidenceStatus
    kind: str
    content: str = ""
    references: List[EvidenceReference] = Field(default_factory=list)
    error: Optional[str] = None


class Finding(BaseModel):
    model_config = ConfigDict(extra="allow")

    vulnerability_type: VulnerabilityClass
    status: FindingStatus
    vulnerability_found: bool = False
    severity: str = "Informational"
    confidence: str = "low"
    evidence: str = ""
    details: str = ""
    mitigation: Optional[str] = None
    decision: str = "final"
    needs_human_review: bool = False
    evidence_references: List[EvidenceReference] = Field(default_factory=list)

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_missing_severity(cls, value: Any) -> str:
        return "Informational" if value is None else value

    def as_report_dict(self) -> Dict[str, Any]:
        result = self.model_dump(mode="json", exclude_none=True)
        result["vulnerability_found"] = self.status == FindingStatus.SUPPORTED
        return result


class ScanMetadata(BaseModel):
    """Stable metadata shared by scan, exploit routing, and report renderers."""

    model_config = ConfigDict(extra="allow")

    file_path: Optional[str] = Field(default=None, alias="FilePath")
    byte_span: Optional[str] = Field(default=None, alias="ByteSpan")
    tainted_by_uds: bool = Field(default=False, alias="TaintedByUDS")
    dids: List[str] = Field(default_factory=list, alias="DIDs")
    taint_depth: Optional[int] = Field(default=None, alias="TaintDepth")
    memory_region: Optional[str] = Field(default=None, alias="MemoryRegion")
    location: Dict[str, Any] = Field(default_factory=dict, alias="Location")


class ExploitFinding(BaseModel):
    """Bounded finding data that is safe and useful for dynamic validation."""

    model_config = ConfigDict(extra="ignore")

    vulnerability_type: Optional[str] = None
    status: Optional[str] = None
    vulnerability_found: bool = False
    severity: str = "Informational"
    confidence: str = "low"
    evidence: str = ""
    details: str = ""
    mitigation: Optional[str] = None
    evidence_references: List[EvidenceReference] = Field(default_factory=list)
    graph_flag_agreement: Optional[bool] = None
    needs_human_review: bool = False
    decision: Optional[str] = None
    candidate_rationale: Optional[str] = None
    effort_estimate: Optional[str] = None


class EvidenceBundle(BaseModel):
    """Stable, single-source evidence handoff for deep scan and exploitation."""

    schema_version: str = "1.0"
    retrieval_pointer: Optional[str] = None
    scan_metadata: Dict[str, Any] = Field(default_factory=dict)
    graph_json: str = ""
    graph_summary: str = ""
    source_code: str = ""
    variable_access: List[Dict[str, Any]] = Field(default_factory=list)
    concurrency: Dict[str, Any] = Field(default_factory=dict)
    deep_scan_findings: List[Dict[str, Any]] = Field(default_factory=list)
    protocol_contract: Dict[str, Any] = Field(default_factory=dict)
    graph_flags: Dict[str, Any] = Field(default_factory=dict)
    rte_data_flows: List[Dict[str, Any]] = Field(default_factory=list)
    memory_sink_paths: List[Dict[str, Any]] = Field(default_factory=list)


class ExploitContext(BaseModel):
    """Versioned scan-to-exploit handoff persisted for resume and exploit-only."""

    model_config = ConfigDict(extra="ignore")

    schema_version: str = "1.0"
    target_function: Optional[str] = None
    entry_point: Dict[str, Any] = Field(default_factory=dict)
    findings: List[ExploitFinding] = Field(default_factory=list)
    primary_finding: Dict[str, Any] = Field(default_factory=dict)
    triage: Dict[str, Any] = Field(default_factory=dict)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    evidence_bundle: Optional[EvidenceBundle] = None
    limitations: List[str] = Field(default_factory=list)


class ScanReport(BaseModel):
    """Persisted scan envelope with legacy fields retained for compatibility."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    vulnerability_found: bool = False
    severity: str = "Informational"
    confidence: str = "low"
    details: str = ""
    metadata: ScanMetadata = Field(default_factory=ScanMetadata)
    findings: List[Finding] = Field(default_factory=list)
    exploit_context: Optional[ExploitContext] = None

    def as_report_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def parse_object(value: Any, model: type[BaseModel]) -> BaseModel:
    """Validate a decoded LLM object and reject arrays/scalars at the boundary."""
    if not isinstance(value, dict):
        raise ValueError(f"response_contract_invalid: expected JSON object, got {type(value).__name__}")
    try:
        return model.model_validate(value)
    except ValidationError as exc:
        fields = []
        for error in exc.errors():
            location = ".".join(str(part) for part in error.get("loc", ())) or "response"
            if location not in fields:
                fields.append(location)
        field_text = ", ".join(fields[:6])
        if len(fields) > 6:
            field_text += ", ..."
        raise ValueError(f"response_contract_invalid: missing or invalid fields: {field_text}") from None