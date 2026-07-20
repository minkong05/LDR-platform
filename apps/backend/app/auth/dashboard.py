from app.settings import settings
from fastapi import Header, HTTPException, status


def require_dashboard_token(x_dashboard_token: str | None = Header(default=None)) -> None:
    if not x_dashboard_token or x_dashboard_token != settings.DASHBOARD_API_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid dashboard token",
        )
