# 📄 apps/backend/app/routers/response.py

from app.deps import get_db
from app.schemas.response import BlockIn, BlockOut, BlockStatusOut, UnblockIn
from app.services.response.block import BlockService
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

router = APIRouter(prefix="/response", tags=["response"])


@router.post("/block", response_model=BlockOut)
def block_ip(
    body: BlockIn,
    db: Session = Depends(get_db),  # noqa: B008
):
    """
    Block an IP address.

    Creates a BlockedIP record and appends an audit log entry.
    If the IP is already blocked, returns the existing record
    with note='already_blocked' — no duplicate row is created.
    """
    svc = BlockService(db)
    result = svc.block_ip(
        body.ip,
        reason=body.reason,
        ttl_minutes=body.ttl_minutes,
        actor=body.actor,
    )
    return result


@router.post("/unblock/{ip}", response_model=BlockOut)
def unblock_ip(
    ip: str,
    body: UnblockIn = Depends(),  # noqa: B008
    db: Session = Depends(get_db),  # noqa: B008
):
    """
    Unblock an IP address.

    Deactivates all active blocks for the IP and appends an audit entry.
    If the IP is not currently blocked, returns note='not_blocked' —
    still audited so the attempt is visible.
    """
    svc = BlockService(db)
    result = svc.unblock_ip(
        ip,
        reason=body.reason,
        actor=body.actor,
    )
    return result


@router.get("/block-status/{ip}", response_model=BlockStatusOut)
def block_status(
    ip: str,
    db: Session = Depends(get_db),  # noqa: B008
):
    """
    Check whether an IP is currently blocked.

    Read-only — does not write an audit entry.
    Returns is_blocked=true/false and full block detail if active.
    """
    svc = BlockService(db)
    return svc.get_block_status(ip)
