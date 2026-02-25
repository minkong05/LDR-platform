from app.error_handlers import register_exception_handlers
from app.logging import configure_logging
from app.middleware.request_id import RequestIDMiddleware
from app.routers.db_smoke import router as db_router
from app.routers.events import router as events_router
from app.routers.health import router as health_router
from app.routers.ingest import router as ingest_router
from app.settings import settings
from fastapi import FastAPI

configure_logging(env=settings.ENV)

app = FastAPI(title="LDR Platform", version="0.1.0")

# Middleware
app.add_middleware(RequestIDMiddleware)

# Exception handlers
register_exception_handlers(app)

# Routers
app.include_router(health_router, prefix="/v1")
app.include_router(db_router, prefix="/v1")
app.include_router(ingest_router, prefix="/v1")
app.include_router(events_router, prefix="/v1")
