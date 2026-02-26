import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logger = structlog.get_logger()


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        # Log full details, but return safe error to client
        logger.exception("unhandled_exception", path=str(request.url.path))
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal Server Error"},
        )
