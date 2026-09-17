from queryguard.models import QuerySchema, SchemaTable
from queryguard.sql import add_sampling, analyze_sql, inject_limit


def test_analyzer_detects_high_risk_patterns():
    result = analyze_sql("SELECT * FROM events e JOIN users u")
    codes = {finding.code for finding in result.findings}
    assert {"select_star", "unbounded_query", "cartesian_join"} <= codes
    assert result.risk_score >= 40


def test_write_without_predicate_and_estimate():
    schema = QuerySchema(tables=[SchemaTable(name="users", row_count=100, bytes_per_row=50)])
    result = analyze_sql("UPDATE users SET name='x'", schema)
    assert "missing_predicate" in {f.code for f in result.findings}
    assert result.estimated_bytes == 5000


def test_insert_select_is_checked_as_a_scan():
    result = analyze_sql("INSERT INTO archive SELECT * FROM events")
    codes = {finding.code for finding in result.findings}
    assert {"select_star", "full_table_scan"} <= codes


def test_limit_preserves_terminator_and_comments():
    sql = "SELECT id FROM users; -- caller note"
    rewritten = inject_limit(sql, 10)
    assert rewritten == "SELECT id FROM users LIMIT 10; -- caller note"
    assert inject_limit("SELECT id FROM users;--caller note", 10) == \
        "SELECT id FROM users LIMIT 10;--caller note"
    assert inject_limit("SELECT ';' FROM users -- caller note", 10) == \
        "SELECT ';' FROM users LIMIT 10 -- caller note"
    assert inject_limit("SELECT 1 LIMIT 2", 10) == "SELECT 1 LIMIT 2"


def test_sampling():
    assert "TABLESAMPLE SYSTEM (5 PERCENT)" in add_sampling(
        "SELECT * FROM users", 5, "bigquery"
    )
