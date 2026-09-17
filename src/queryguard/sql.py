"""Small deterministic SQL lexer/heuristics.

This intentionally is not a SQL parser. The guard must fail closed for unsupported
statements while remaining predictable across supported dialects.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from .models import Finding, QuerySchema, Severity

_KEYWORDS = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|WITH|MERGE|CREATE|DROP|ALTER)\b", re.I)
_TABLE = re.compile(r"\b(?:FROM|JOIN|UPDATE|INTO|DELETE\s+FROM)\s+([`\"\[\]\w.$-]+)", re.I)
_EXPENSIVE = re.compile(
    r"\b(REGEXP_(?:CONTAINS|EXTRACT|REPLACE)|ST_DISTANCE|ML\.|"
    r"JSON_EXTRACT|PARSE_JSON|TO_JSON|APPROX_QUANTILES|COUNT\s*\(\s*DISTINCT)\b", re.I
)
_LIMIT = re.compile(r"\bLIMIT\s+\d+\b", re.I)
_WHERE = re.compile(r"\bWHERE\b", re.I)


def strip_comments(sql: str) -> str:
    """Remove comments without changing quoted strings."""
    return re.sub(r"/\*.*?\*/|--[^\r\n]*", " ", sql, flags=re.S)


def statement_type(sql: str) -> str:
    match = _KEYWORDS.search(strip_comments(sql))
    return (match.group(1).upper() if match else "UNKNOWN")


def normalize_sql(sql: str) -> str:
    return re.sub(r"\s+", " ", strip_comments(sql)).strip()


def _severity(points: int) -> Severity:
    if points >= 35:
        return "critical"
    if points >= 22:
        return "high"
    if points >= 10:
        return "medium"
    if points:
        return "low"
    return "info"


@dataclass(frozen=True)
class Analysis:
    statement_type: str
    findings: list[Finding]
    risk_score: int
    estimated_bytes: int
    estimated_cost_usd: float


def _finding(code: str, points: int, message: str, evidence: str, suggestion: str) -> Finding:
    return Finding(
        code=code,
        severity=_severity(points),
        message=message,
        risk_points=points,
        evidence=evidence[:500],
        suggestion=suggestion,
    )


def _tables(sql: str) -> list[str]:
    return [m.group(1).strip("`\"[]") for m in _TABLE.finditer(strip_comments(sql))]


def analyze_sql(sql: str, schema: QuerySchema | None = None) -> Analysis:
    clean = strip_comments(sql)
    typ = statement_type(sql)
    findings: list[Finding] = []
    upper = clean.upper()
    tables = _tables(sql)
    is_read_or_write = typ in {"SELECT", "WITH", "INSERT", "UPDATE", "DELETE"}

    if typ == "UNKNOWN":
        findings.append(_finding("unsupported_statement", 40, "Statement type is not supported.", typ,
                                 "Allow only SELECT, INSERT, UPDATE, or DELETE."))
    if re.search(r"\bSELECT\s+\*", upper):
        findings.append(_finding("select_star", 10, "SELECT * can read unreviewed sensitive and excess columns.",
                                 "SELECT *", "Project an explicit allowlisted column list."))
    insert_select = typ == "INSERT" and bool(re.search(r"\bSELECT\b", upper))
    if typ in {"SELECT", "WITH", "UPDATE", "DELETE"} or insert_select:
        predicate_missing = tables and not _WHERE.search(clean)
    else:
        predicate_missing = False
    if predicate_missing:
        code = "missing_predicate" if typ in {"UPDATE", "DELETE"} else "full_table_scan"
        points = 30 if typ in {"UPDATE", "DELETE"} else 18
        msg = "Write statement has no WHERE predicate." if typ in {"UPDATE", "DELETE"} else \
            "No WHERE predicate was found; every row may be scanned."
        findings.append(_finding(code, points, msg, typ, "Add a selective, partition-friendly WHERE predicate."))
    if typ in {"SELECT", "WITH"} and tables and not _LIMIT.search(clean):
        findings.append(_finding("unbounded_query", 12, "Query has no LIMIT.", "missing LIMIT",
                                 "Add a bounded LIMIT appropriate for the caller."))
    from_match = re.search(r"\bFROM\b(.*)", clean, re.I | re.S)
    from_tail = from_match.group(1) if from_match else ""
    # Only inspect the source-list portion; commas in IN(), function calls, or
    # later SELECT expressions are not cartesian joins.
    source_list = re.split(r"\b(?:WHERE|GROUP\s+BY|ORDER\s+BY|LIMIT|HAVING|QUALIFY)\b",
                           from_tail, maxsplit=1, flags=re.I)[0]
    if re.search(r",\s*[`\"\w]", source_list):
        findings.append(_finding("cartesian_join", 25, "Comma-separated FROM sources can create a cartesian join.",
                                 "FROM a, b", "Use an explicit JOIN with a validated ON predicate."))
    joins = list(re.finditer(r"\bJOIN\b", clean, re.I))
    for join in joins:
        tail = clean[join.end(): join.end() + 300]
        if not re.search(r"\bON\b|\bUSING\b", tail, re.I):
            findings.append(_finding("cartesian_join", 25, "JOIN has no ON/USING predicate.",
                                     tail.strip(), "Add a key-based ON predicate or remove the join."))
            break
    for match in _EXPENSIVE.finditer(clean):
        findings.append(_finding("expensive_function", 8, "Expensive function may amplify scan cost.",
                                 match.group(0), "Filter/partition first and precompute expensive transformations."))

    schema_by_name = {t.name.lower(): t for t in (schema.tables if schema else [])}
    estimated = 0
    for table_name in tables:
        table = schema_by_name.get(table_name.lower().split(".")[-1])
        if table and table.row_count is not None:
            estimated += max(0, table.row_count) * max(1, table.bytes_per_row)
        else:
            estimated += 10 * 1024 * 1024  # conservative unknown-table estimate
    if estimated == 0 and is_read_or_write:
        estimated = 1024
    if estimated > 1_000_000_000:
        findings.append(_finding("large_scan", 25, "Estimated scan exceeds 1 GB.", str(estimated),
                                 "Partition, filter, sample, or obtain an explicit cost override."))
    score = min(100, sum(f.risk_points for f in findings))
    # Cost is a transparent approximation, not a billing promise.
    return Analysis(typ, findings, score, estimated, round(estimated / (1024**4) * 5.0, 6))


def _suffix_start(sql: str) -> int:
    """Return where trailing comments/whitespace begin."""
    match = re.search(r"(?is)(?:\s*(?:--[^\r\n]*(?:\r?\n|$)|/\*.*?\*/))*\s*$", sql)
    return match.start() if match else len(sql)


def _last_unquoted_semicolon(sql: str) -> int:
    quote: str | None = None
    last = -1
    index = 0
    while index < len(sql):
        char = sql[index]
        if quote:
            if char == quote:
                if index + 1 < len(sql) and sql[index + 1] == quote:
                    index += 2
                    continue
                quote = None
            index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
        elif char == ";":
            last = index
        index += 1
    return last


def inject_limit(sql: str, limit: int = 1000) -> str:
    """Inject LIMIT before a statement terminator and trailing comments."""
    if limit < 1:
        raise ValueError("limit must be positive")
    if _LIMIT.search(strip_comments(sql)):
        return sql
    boundary = _suffix_start(sql)
    body = sql[:boundary]
    suffix = sql[boundary:]
    semi = _last_unquoted_semicolon(body)
    if semi >= 0 and not body[semi + 1:].strip():
        insertion = semi
        return body[:insertion].rstrip() + f" LIMIT {limit}" + body[insertion:] + suffix
    return body.rstrip() + f" LIMIT {limit}" + suffix


def add_sampling(sql: str, percent: float, dialect: str = "generic") -> str:
    """Add sampling to simple table references; never rewrites subqueries."""
    if not 0 < percent <= 100:
        raise ValueError("percent must be between 0 and 100")
    if dialect == "bigquery":
        clause = f" TABLESAMPLE SYSTEM ({percent:g} PERCENT)"
    else:
        clause = f" TABLESAMPLE SYSTEM ({percent:g})"
    pattern = re.compile(r"(\b(?:FROM|JOIN)\s+)([`\"\w.$-]+)(?!\s+TABLESAMPLE)", re.I)
    return pattern.sub(lambda m: m.group(1) + m.group(2) + clause, sql)
