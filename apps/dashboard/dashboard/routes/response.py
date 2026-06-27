# 📄 apps/dashboard/dashboard/routes/response.py

from flask import Blueprint, flash, render_template, request

from dashboard import api_client

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
