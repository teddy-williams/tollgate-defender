"""Minimal redirect-tracing microservice: the ONLY component that needs outbound internet for URLs.

Run it in its own container with no database and no samples:
  TOLLGATE_TRACER_TOKEN=... uvicorn tollgate.tracer_service:create_app --factory --port 8081
It returns the raw hop list; the API adds verdicts and threat-intel matching.
"""
from __future__ import annotations

import hmac
import os

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from . import redirects


class TraceBody(BaseModel):
    url: str = Field(min_length=1, max_length=4096)


def create_app(token: str | None = None) -> FastAPI:
    secret = token if token is not None else os.environ.get("TOLLGATE_TRACER_TOKEN", "")
    if not secret:
        raise RuntimeError("TOLLGATE_TRACER_TOKEN must be set")
    app = FastAPI(title="Tollgate tracer", docs_url=None, redoc_url=None, openapi_url=None)

    @app.post("/trace")
    def trace(body: TraceBody, x_tracer_token: str | None = Header(None)):
        if not hmac.compare_digest((x_tracer_token or "").encode(), secret.encode()):
            raise HTTPException(401, "invalid token")
        return redirects.trace_raw(body.url).to_dict(raw=True)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app
