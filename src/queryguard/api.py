"""FastAPI HTTP surface."""
from __future__ import annotations

from fastapi import FastAPI, HTTPException, Query

from . import __version__
from .executor import ExecutionError
from .models import (AnalyzeRequest, AnalyzeResponse, ExecuteRequest, ExecuteResponse,
                     HealthResponse, QuotaResponse)
from .quota import QuotaExceeded
from .service import QueryGuardService


def create_app(service: QueryGuardService | None = None) -> FastAPI:
    guard = service or QueryGuardService()
    app = FastAPI(title="QueryGuard", version=__version__,
                  description="Cost-aware safety layer for generated SQL.")

    @app.get("/v1/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(version=__version__)

    @app.post("/v1/analyze", response_model=AnalyzeResponse)
    def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
        return guard.analyze(request)

    @app.post("/v1/execute", response_model=ExecuteResponse)
    def execute(request: ExecuteRequest) -> ExecuteResponse:
        try:
            return guard.execute(request)
        except QuotaExceeded as exc:
            raise HTTPException(status_code=429, detail=str(exc)) from exc
        except ExecutionError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/v1/quota", response_model=QuotaResponse)
    def quota(user_id: str = Query(default="anonymous", min_length=1, max_length=128)) -> QuotaResponse:
        return QuotaResponse(**guard.quota.snapshot(user_id))

    return app


app = create_app()
