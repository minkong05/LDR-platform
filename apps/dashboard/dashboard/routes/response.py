# 📄 apps/dashboard/dashboard/routes/response.py

from flask import Blueprint, flash, redirect, render_template, request, url_for

from dashboard import api_client
from dashboard.auth import role_required

bp = Blueprint("response", __name__)


@bp.get("/audit")
def audit_log():
    params = {
        "limit": request.args.get("limit", 50),
        "offset": request.args.get("offset", 0),
    }
    for key in ("target_ip", "action"):
        val = request.args.get(key)
        if val:
            params[key] = val

    try:
        data = api_client.get("/v1/response/audit-log", params=params)
    except Exception as exc:
        data = {"items": [], "limit": 50, "offset": 0}
        flash(f"Could not load audit log: {exc}", "danger")

    return render_template(
        "response/audit.html",
        entries=data["items"],
        limit=int(data["limit"]),
        offset=int(data["offset"]),
        filters=request.args,
    )


@bp.get("/audit/verify")
@role_required("admin")
def verify_audit_log():
    """
    Recompute and verify the audit log's tamper-evident hash chain via the
    backend, then redirect back to the audit log page with the result as
    a flash message.
    """
    try:
        result = api_client.get("/v1/response/audit-log/verify")
    except Exception as exc:
        flash(f"Could not verify audit log: {exc}", "danger")
        return redirect(url_for("response.audit_log"))

    if result.get("ok"):
        flash(f"Audit log integrity OK — {result.get('checked', 0)} entries verified.", "success")
    else:
        flash(
            f"TAMPER DETECTED — entry {result.get('first_invalid_id')} "
            f"failed verification ({result.get('reason')}). "
            f"{result.get('checked', 0)} entries verified before the mismatch.",
            "danger",
        )

    return redirect(url_for("response.audit_log"))
