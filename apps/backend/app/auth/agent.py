from app.settings import settings
from fastapi import Header, HTTPException, status


def require_agent_token(x_agent_token: str | None = Header(default=None)) -> None:
    if not x_agent_token or x_agent_token != settings.AGENT_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid agent token",
        )
