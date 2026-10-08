"""FastAPI de inferência com autenticação, rate limit e output minimization."""

from __future__ import annotations

import os
import secrets
from hashlib import sha256
from uuid import uuid4

import numpy as np
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import APIKeyHeader
from sklearn.datasets import load_iris
from sklearn.ensemble import RandomForestClassifier
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .limiter import SlidingWindowRateLimiter
from .monitoring import QueryMonitor
from .schemas import PredictionRequest, PredictionResponse


MODEL_VERSION = "2.3.0"
_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


def _default_model():
    dataset = load_iris()
    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(dataset.data, dataset.target)
    return model


def create_app(model=None, api_key=None, rate_limit=30, output_mode="rounded"):
    if output_mode not in {"full", "rounded", "label_only"}:
        raise ValueError("output_mode inválido")
    production = os.getenv("CYBERLAB_ENV", "development").lower() == "production"
    application = FastAPI(
        title="CyberLab Secure Model API",
        version=MODEL_VERSION,
        docs_url=None if production else "/docs",
        redoc_url=None if production else "/redoc",
        openapi_url=None if production else "/openapi.json",
    )
    allowed_hosts = [
        host.strip()
        for host in os.getenv(
            "CYBERLAB_ALLOWED_HOSTS", "localhost,127.0.0.1,testserver"
        ).split(",")
        if host.strip()
    ]
    application.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
    application.state.model = model or _default_model()
    application.state.api_key = api_key if api_key is not None else os.getenv("CYBERLAB_API_KEY")
    application.state.rate_limiter = SlidingWindowRateLimiter(rate_limit, 60.0)
    application.state.monitor = QueryMonitor()
    application.state.output_mode = output_mode

    def require_api_key(provided_key: str | None = Depends(_API_KEY_HEADER)):
        configured_key = application.state.api_key
        if not configured_key:
            raise HTTPException(status_code=503, detail="API key não configurada")
        if not provided_key or not secrets.compare_digest(provided_key, configured_key):
            raise HTTPException(status_code=401, detail="credencial inválida")
        return configured_key

    @application.get("/health")
    def health():
        return {"status": "ok"}

    @application.get("/model/version")
    def model_version():
        return {"model_version": MODEL_VERSION}

    @application.post("/predict", response_model=PredictionResponse)
    def predict(payload: PredictionRequest, verified_key: str = Depends(require_api_key)):
        client_key = sha256(verified_key.encode("utf-8")).hexdigest()
        if not application.state.rate_limiter.allow(client_key):
            raise HTTPException(status_code=429, detail="query budget excedido")
        features = np.asarray(payload.features, dtype=float)
        expected = int(application.state.model.n_features_in_)
        if features.ndim != 1 or len(features) != expected:
            raise HTTPException(status_code=422, detail=f"esperadas {expected} features")
        if not np.all(np.isfinite(features)):
            raise HTTPException(status_code=422, detail="features devem ser finitas")
        probabilities = application.state.model.predict_proba(features[None, :])[0]
        prediction = int(np.argmax(probabilities))
        confidence = float(probabilities[prediction])
        request_id = str(uuid4())
        application.state.monitor.record(
            request_id, payload.client_id, MODEL_VERSION, features, prediction, confidence
        )
        response_confidence = None
        if application.state.output_mode == "full":
            response_confidence = confidence
        elif application.state.output_mode == "rounded":
            response_confidence = round(confidence, 2)
        return PredictionResponse(
            request_id=request_id,
            model_version=MODEL_VERSION,
            prediction=prediction,
            confidence=response_confidence,
            policy_action="allow",
        )

    return application


app = create_app()
