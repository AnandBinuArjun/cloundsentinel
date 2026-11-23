"""Sanitized global exception handlers preventing internal information leakage."""

from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from packages.contracts.system import ErrorDetail, ErrorResponse

logger = logging.getLogger("cloudsentinel.api.errors")


def _get_request_id(request: Request) -> str:
    value = getattr(request.state, "request_id", None)
    return value if isinstance(value, str) and value else "unknown"


def register_exception_handlers(app: FastAPI) -> None:
    """Attach uniform, redacted exception handlers to the FastAPI application."""

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        request_id = _get_request_id(request)
        message = exc.detail if isinstance(exc.detail, str) else "Request failed."
        payload = ErrorResponse(
            error=ErrorDetail(
                code=f"http_{exc.status_code}",
                message=message,
                request_id=request_id,
            )
        )
        return JSONResponse(status_code=exc.status_code, content=payload.model_dump())

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request,
        _exc: RequestValidationError,
    ) -> JSONResponse:
        request_id = _get_request_id(request)
        payload = ErrorResponse(
            error=ErrorDetail(
                code="validation_error",
                message="Request validation failed.",
                request_id=request_id,
            )
        )
        return JSONResponse(status_code=422, content=payload.model_dump())

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        request_id = _get_request_id(request)
        logger.exception("Unhandled API exception", exc_info=exc)
        payload = ErrorResponse(
            error=ErrorDetail(
                code="internal_server_error",
                message="An unexpected error occurred.",
                request_id=request_id,
            )
        )
        return JSONResponse(status_code=500, content=payload.model_dump())
