# QueryGuard

QueryGuard is a small, deterministic safety boundary for natural-language-to-SQL
systems. It analyzes generated SQL before execution, explains cost and risk, and
offers bounded rewrites. It is deliberately an enforcement layer, not an LLM or
a database proxy.

## Architecture

`api.py` exposes FastAPI endpoints. `service.py` composes the SQL heuristics,
EXPLAIN analyzer, PII classifier, quota store, and execution abstraction.
`SQLiteDemoExecutor` is a local demonstration backend; production deployments
should provide an isolated executor implementation. All policy decisions are
deterministic and observable through structured `Finding` objects.

## Threat model

The boundary assumes SQL and prompts are untrusted: prompt injection, generated
DDL, accidental full scans, cartesian joins, unbounded results, expensive
functions, destructive writes, and PII exfiltration are in scope. It does not
claim to detect every SQL dialect feature. Unsupported statements fail closed.
Use database credentials, network isolation, auditing, and a separate tenant
database in production.

## Quickstart

```sh
python -m venv .venv
. .venv/bin/activate                 # Windows: .venv\Scripts\activate
pip install -e '.[dev]'
uvicorn queryguard.api:app --reload
pytest
```

## API

```sh
curl -X POST http://localhost:8000/v1/analyze \
  -H 'content-type: application/json' \
  -d '{"sql":"SELECT * FROM users"}'
curl -X POST http://localhost:8000/v1/execute \
  -H 'content-type: application/json' \
  -d '{"sql":"SELECT id,email FROM users","schema":{"tables":[{"name":"users","columns":[{"name":"id","data_type":"INTEGER"},{"name":"email","data_type":"TEXT"}]}]}}'
curl http://localhost:8000/v1/quota?user_id=anonymous
```

`/v1/analyze` returns statement type, findings, 0–100 risk score, estimated
bytes/cost, PII columns, and optional LIMIT/sampling rewrites. `/v1/execute`
defaults to read-only mode, caps rows, applies a progress-handler timeout, and
masks schema-classified PII; high-risk statements are rejected before execution.
`/v1/health` is suitable for probes.

## Design decisions

* Regex/token heuristics are intentionally conservative and deterministic.
* Estimates use supplied row metadata and a transparent $5/TiB approximation.
* Rewrites insert LIMIT before semicolons and trailing comments.
* Quotas are per UTC day and protected by a lock; replace with a durable store
  for multi-process deployments.
* The evaluation corpus contains 100 generated/static adversarial cases.

## Production hardening

Use a read-only database role, a process/container per tenant, database-native
statement timeouts and byte limits, TLS/authentication, durable quota accounting,
structured audit logs, a reviewed SQL parser for each dialect, and a secrets
manager. Never treat masking as an authorization control.

## Evaluation

```sh
python -c "from queryguard.evaluation import evaluate; print(evaluate())"
```

The corpus covers prompt injection, unsafe writes, resource amplification,
cartesian joins, and sensitive-data access. Add organization-specific cases
before enabling automatic execution.
