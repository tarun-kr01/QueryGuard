"""Public API and internal data models."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["info", "low", "medium", "high", "critical"]


class Finding(BaseModel):
    code: str
    severity: Severity
    message: str
    risk_points: int = Field(ge=0)
    evidence: str | None = None
    suggestion: str | None = None


class SchemaColumn(BaseModel):
    name: str
    data_type: str = "TEXT"
    nullable: bool = True
    description: str | None = None


class SchemaTable(BaseModel):
    name: str
    columns: list[SchemaColumn] = Field(default_factory=list)
    row_count: int | None = None
    bytes_per_row: int = 256


class QuerySchema(BaseModel):
    tables: list[SchemaTable] = Field(default_factory=list)


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    sql: str = Field(min_length=1, max_length=1_000_000)
    user_id: str = Field(default="anonymous", min_length=1, max_length=128)
    schema_: QuerySchema | None = Field(default=None, alias="schema")
    explain_plan: Any | None = None
    dialect: Literal["generic", "postgres", "bigquery", "sqlite"] = "generic"
    limit: int | None = Field(default=None, ge=1, le=100_000)
    sample_percent: float | None = Field(default=None, gt=0, le=100)

    @property
    def schema(self) -> QuerySchema | None:
        return self.schema_


class AnalyzeResponse(BaseModel):
    statement_type: str
    normalized_sql: str
    findings: list[Finding]
    risk_score: int = Field(ge=0, le=100)
    estimated_bytes: int = Field(ge=0)
    estimated_cost_usd: float = Field(ge=0)
    rewritten_sql: str | None = None
    sample_sql: str | None = None
    pii_columns: list[str] = Field(default_factory=list)
    allowed: bool


class ExecuteRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    sql: str = Field(min_length=1, max_length=1_000_000)
    user_id: str = Field(default="anonymous", min_length=1, max_length=128)
    read_only: bool = True
    timeout_ms: int = Field(default=2_000, ge=1, le=60_000)
    max_rows: int = Field(default=100, ge=1, le=10_000)
    schema_: QuerySchema | None = Field(default=None, alias="schema")

    @property
    def schema(self) -> QuerySchema | None:
        return self.schema_


class ExecuteResponse(BaseModel):
    columns: list[str]
    rows: list[dict[str, Any]]
    row_count: int
    truncated: bool
    masked_columns: list[str] = Field(default_factory=list)
    risk_score: int = 0


class QuotaResponse(BaseModel):
    user_id: str
    requests_used: int
    requests_limit: int
    bytes_used: int
    bytes_limit: int
    remaining_requests: int
    remaining_bytes: int


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    version: str
