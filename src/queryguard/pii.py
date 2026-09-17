"""Schema-driven PII classification and deterministic result masking."""
from __future__ import annotations

import re
from typing import Any, Iterable

from .models import QuerySchema, SchemaColumn

_PII_NAME = re.compile(r"(email|e_mail|phone|mobile|ssn|social.?security|"
                       r"credit.?card|card_number|password|secret|token|"
                       r"address|dob|birth|ip_address|national.?id)", re.I)
_PII_TYPES = re.compile(r"(email|phone|inet|uuid|json|secret|password)", re.I)


def is_pii_column(column: SchemaColumn) -> bool:
    return bool(_PII_NAME.search(column.name) or _PII_TYPES.search(column.data_type)
                or (column.description and _PII_NAME.search(column.description)))


def pii_columns(schema: QuerySchema | None) -> set[str]:
    if not schema:
        return set()
    return {column.name for table in schema.tables for column in table.columns if is_pii_column(column)}


def output_pii_columns(sql: str, schema: QuerySchema | None) -> set[str]:
    """Map source PII columns to result names, including simple SQL aliases."""
    source_columns = pii_columns(schema)
    if not source_columns:
        return set()
    match = re.search(r"\bSELECT\s+(.*?)\s+\bFROM\b", sql, re.I | re.S)
    if not match:
        return source_columns
    projection = match.group(1)
    if "*" in projection:
        return source_columns
    result: set[str] = set()
    # Splitting on commas outside parentheses handles common function expressions.
    fields: list[str] = []
    start = depth = 0
    quote: str | None = None
    for index, char in enumerate(projection):
        if quote:
            if char == quote:
                quote = None
        elif char in {"'", '"'}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            fields.append(projection[start:index])
            start = index + 1
    fields.append(projection[start:])
    lowered = {name.lower(): name for name in source_columns}
    for field in fields:
        tokens = re.findall(r"[A-Za-z_][\w$]*", field)
        if not tokens:
            continue
        alias_match = re.search(r"\bAS\s+([A-Za-z_][\w$]*)\b", field, re.I)
        output_name = alias_match.group(1) if alias_match else tokens[-1]
        if any(token.lower() in lowered for token in tokens):
            result.add(output_name)
    return result


def mask_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        if len(value) <= 4:
            return "****"
        return value[:2] + "…" + value[-2:]
    return "[REDACTED]"


def redact_rows(rows: Iterable[dict[str, Any]], columns: set[str]) -> list[dict[str, Any]]:
    lowered = {c.lower() for c in columns}
    return [{key: mask_value(value) if key.lower() in lowered else value for key, value in row.items()}
            for row in rows]
