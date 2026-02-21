from app.deps import get_db
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

router = APIRouter(tags=["db"])


@router.get("/db/ping")
def db_ping(db: Session = Depends(get_db)):  # noqa: B008
    # Minimal query to confirm connectivity
    db.execute(text("SELECT 1"))
    return {"db": "ok"}
