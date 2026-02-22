from app.routers.db_smoke import router as db_router
from app.routers.health import router as health_router
from app.routers.ingest import router as ingest_router
from fastapi import FastAPI

app = FastAPI(title="LDR Platform", version="0.1.0")

app.include_router(health_router, prefix="/v1")
app.include_router(db_router, prefix="/v1")
app.include_router(ingest_router, prefix="/v1")
