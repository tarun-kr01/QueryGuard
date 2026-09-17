"""Application orchestration."""
from __future__ import annotations

from .explain import analyze_explain
from .models import AnalyzeRequest, AnalyzeResponse, ExecuteRequest, ExecuteResponse
from .pii import output_pii_columns, pii_columns, redact_rows
from .quota import QuotaStore
from .sql import add_sampling, analyze_sql, inject_limit, normalize_sql
from .executor import ExecutionError, SQLiteDemoExecutor


class QueryGuardService:
    def __init__(self, quota: QuotaStore | None = None, executor: SQLiteDemoExecutor | None = None):
        self.quota = quota or QuotaStore()
        self.executor = executor or SQLiteDemoExecutor()

    def analyze(self, request: AnalyzeRequest) -> AnalyzeResponse:
        analysis = analyze_sql(request.sql, request.schema)
        findings = list(analysis.findings)
        if request.explain_plan is not None:
            findings.extend(analyze_explain(request.explain_plan))
        score = min(100, sum(f.risk_points for f in findings))
        rewritten = inject_limit(request.sql, request.limit or 1000) if analysis.statement_type in {"SELECT", "WITH"} else None
        sampled = add_sampling(request.sql, request.sample_percent, request.dialect) if request.sample_percent else None
        return AnalyzeResponse(
            statement_type=analysis.statement_type, normalized_sql=normalize_sql(request.sql),
            findings=findings, risk_score=score, estimated_bytes=analysis.estimated_bytes,
            estimated_cost_usd=analysis.estimated_cost_usd, rewritten_sql=rewritten, sample_sql=sampled,
            pii_columns=sorted(pii_columns(request.schema)), allowed=score < 40,
        )

    def execute(self, request: ExecuteRequest) -> ExecuteResponse:
        analysis = analyze_sql(request.sql, request.schema)
        if analysis.risk_score >= 40:
            raise ExecutionError("query blocked by QueryGuard risk policy; analyze and rewrite it first")
        self.quota.consume(request.user_id, analysis.estimated_bytes)
        result = self.executor.execute(request.sql, read_only=request.read_only,
                                       timeout_ms=request.timeout_ms, max_rows=request.max_rows)
        columns = output_pii_columns(request.sql, request.schema)
        rows = redact_rows(result.rows, columns)
        return ExecuteResponse(columns=result.columns, rows=rows, row_count=len(rows),
                               truncated=result.truncated, masked_columns=sorted(columns),
                               risk_score=analysis.risk_score)
