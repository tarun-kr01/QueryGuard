import threading

import pytest

from queryguard.models import QuerySchema, SchemaColumn, SchemaTable
from queryguard.pii import output_pii_columns, pii_columns, redact_rows
from queryguard.quota import QuotaExceeded, QuotaLimits, QuotaStore


def test_pii_classification_and_masking():
    schema = QuerySchema(tables=[SchemaTable(name="users", columns=[
        SchemaColumn(name="email", data_type="TEXT"), SchemaColumn(name="id", data_type="INTEGER")
    ])])
    assert pii_columns(schema) == {"email"}
    assert redact_rows([{"email": "ada@example.com", "id": 1}], {"email"})[0]["email"] == "ad…om"
    assert output_pii_columns("SELECT email AS contact, id FROM users", schema) == {"contact"}


def test_quota_is_thread_safe_and_enforced():
    store = QuotaStore(QuotaLimits(requests=2, bytes=100))
    store.consume("u", 20)
    store.consume("u", 20)
    with pytest.raises(QuotaExceeded):
        store.consume("u", 1)
    assert store.snapshot("u")["remaining_requests"] == 0
