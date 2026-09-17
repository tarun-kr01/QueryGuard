"""Sandboxed SQLite demo execution abstraction."""
from __future__ import annotations

import re
import sqlite3
import time
from dataclasses import dataclass
from typing import Any


class ExecutionError(RuntimeError):
    """A safe, user-facing execution failure."""


@dataclass
class ExecutionResult:
    columns: list[str]
    rows: list[dict[str, Any]]
    truncated: bool


class SQLiteDemoExecutor:
    def __init__(self, database: str = ":memory:") -> None:
        self.connection = sqlite3.connect(database, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(
            "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, age INTEGER);"
            "INSERT OR IGNORE INTO users(id,name,email,age) VALUES "
            "(1,'Ada','ada@example.com',37),(2,'Linus','linus@example.com',55);"
        )

    def execute(self, sql: str, *, read_only: bool = True, timeout_ms: int = 2_000,
                max_rows: int = 100) -> ExecutionResult:
        if not sql.strip() or "\x00" in sql:
            raise ExecutionError("SQL is empty or contains a NUL byte")
        if len(sql) > 1_000_000:
            raise ExecutionError("SQL is too long")
        statement = _one_statement(sql)
        keyword = re.match(r"([A-Za-z]+)", statement)
        if not keyword:
            raise ExecutionError("Unable to identify SQL statement")
        kind = keyword.group(1).upper()
        with_write = kind == "WITH" and re.search(r"\b(INSERT|UPDATE|DELETE|MERGE)\b", statement, re.I)
        if read_only and (kind not in {"SELECT", "WITH", "EXPLAIN"} or with_write):
            raise ExecutionError("Read-only execution permits SELECT/WITH/EXPLAIN only")
        deadline = time.monotonic() + timeout_ms / 1000
        def progress() -> int:
            return 1 if time.monotonic() >= deadline else 0
        self.connection.set_progress_handler(progress, 1_000)
        try:
            cursor = self.connection.execute(statement)
            if cursor.description is None:
                self.connection.commit()
                return ExecutionResult([], [], False)
            columns = [str(item[0]) for item in cursor.description]
            rows = [dict(row) for row in cursor.fetchmany(max_rows + 1)]
            truncated = len(rows) > max_rows
            return ExecutionResult(columns, rows[:max_rows], truncated)
        except sqlite3.Error as exc:
            raise ExecutionError(f"SQL execution failed: {exc}") from exc
        finally:
            self.connection.set_progress_handler(None, 0)


def _one_statement(sql: str) -> str:
    """Extract one statement while allowing a terminator and SQL comments."""
    quote: str | None = None
    semicolon = -1
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
            semicolon = index
            break
        index += 1
    if semicolon >= 0:
        remainder = sql[semicolon + 1:]
        if re.sub(r"/\*.*?\*/|--[^\r\n]*", "", remainder, flags=re.S).strip():
            raise ExecutionError("Exactly one SQL statement is allowed")
        return sql[:semicolon].strip()
    if re.sub(r"/\*.*?\*/|--[^\r\n]*", "", sql, flags=re.S).strip() == "":
        raise ExecutionError("SQL is empty")
    return sql.strip()
