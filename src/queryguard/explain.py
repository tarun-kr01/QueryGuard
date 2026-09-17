"""EXPLAIN plan ingestion for common JSON and text formats."""
from __future__ import annotations

import re
from typing import Any

from .models import Finding
from .sql import _finding


def _walk(node: Any):
    if isinstance(node, dict):
        if "Plan" in node:
            yield from _walk(node["Plan"])
        if "Plans" in node:
            for child in node["Plans"]:
                yield from _walk(child)
        yield node
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item)


def analyze_explain(plan: Any) -> list[Finding]:
    findings: list[Finding] = []
    if isinstance(plan, str):
        text = plan
        if re.search(r"\bSeq Scan\b|\bTable Scan\b", text, re.I):
            findings.append(_finding("plan_sequential_scan", 15, "Plan contains a sequential/table scan.",
                                     "Seq Scan/Table Scan", "Add a selective predicate and an appropriate index/partition."))
        if re.search(r"\bNested Loop\b", text, re.I):
            findings.append(_finding("plan_nested_loop", 10, "Plan contains a nested-loop join.",
                                     "Nested Loop", "Verify join cardinality and indexes on the inner side."))
        costs = re.findall(r"(?:cost|Total Cost)[= ]+([0-9.]+(?:\.\.[0-9.]+)?)", text, re.I)
        numeric_costs = [float(token.split("..")[-1]) for token in costs]
        if numeric_costs and numeric_costs[-1] > 100000:
            findings.append(_finding("plan_high_cost", 20, "Plan cost is unusually high.", str(numeric_costs[-1]),
                                     "Reduce scanned data before executing."))
        return findings
    try:
        nodes = list(_walk(plan))
    except (TypeError, AttributeError):
        return [_finding("invalid_plan", 12, "EXPLAIN plan shape is invalid.", repr(plan),
                         "Provide a Postgres/BigQuery JSON plan or text plan.")]
    if not nodes:
        return [_finding("invalid_plan", 12, "EXPLAIN plan is empty.", "", "Provide a non-empty plan.")]
    for node in nodes:
        kind = str(node.get("Node Type") or node.get("node_type") or node.get("name") or "")
        kind_lower = kind.lower()
        if "seq scan" in kind_lower or "table scan" in kind_lower or "scan" == kind_lower or kind_lower == "read":
            findings.append(_finding("plan_sequential_scan", 15, "Plan contains a sequential/table scan.",
                                     kind, "Add a selective predicate and index/partition."))
        if "nested loop" in kind_lower or "cross join" in kind_lower:
            findings.append(_finding("plan_cartesian_or_nested", 18, "Plan may multiply rows through a join.",
                                     kind, "Validate join keys and cardinality."))
        rows = node.get("Plan Rows", node.get("rows", node.get("estimated_rows", node.get("recordsRead"))))
        if isinstance(rows, str):
            try:
                rows = float(rows.replace(",", ""))
            except ValueError:
                rows = None
        if isinstance(rows, (int, float)) and rows > 10_000_000:
            findings.append(_finding("plan_large_rows", 20, "Plan estimates more than ten million rows.",
                                     str(rows), "Filter earlier or require an explicit approval."))
        total_cost = node.get("Total Cost", node.get("total_cost", node.get("cost")))
        shuffle = node.get("shuffleOutputBytes", node.get("shuffle_output_bytes"))
        if isinstance(shuffle, str):
            try:
                shuffle = float(shuffle.replace(",", ""))
            except ValueError:
                shuffle = None
        if isinstance(shuffle, (int, float)) and shuffle > 1_000_000_000:
            findings.append(_finding("plan_large_shuffle", 20, "Plan shuffles more than one GB.",
                                     str(shuffle), "Filter earlier and reduce join/grouping cardinality."))
        if isinstance(total_cost, (int, float)) and total_cost > 100_000:
            findings.append(_finding("plan_high_cost", 20, "Plan cost is unusually high.", str(total_cost),
                                     "Reduce scanned data before executing."))
    # De-duplicate repeated child-node findings.
    return list({(f.code, f.evidence): f for f in findings}.values())
