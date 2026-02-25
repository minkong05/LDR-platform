import uuid

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = structlog.get_logger()


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())

        # Bind to structlog context (so every log line contains request_id)
        structlog.contextvars.bind_contextvars(request_id=request_id)

        try:
            response: Response = await call_next(request)
        finally:
            # Clear context to avoid leaking across requests
            structlog.contextvars.clear_contextvars()

        response.headers["X-Request-Id"] = request_id
        return response
