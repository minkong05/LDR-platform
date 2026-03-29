# 📄 apps/dashboard/dashboard/routes/alerts.py
from flask import Blueprint, flash, redirect, render_template, request, url_for

from dashboard import api_client

bp = Blueprint("alerts", __name__)


@bp.get("/")
def list_alerts():
    params = {
        "limit": request.args.get("limit", 50),
        "offset": request.args.get("offset", 0),
    }
    # Optional filters
    for key in ("status", "severity", "source_ip"):
        val = request.args.get(key)
        if val:
            params[key] = val

    try:
        data = api_client.get("/v1/alerts", params=params)
    except Exception as exc:
        data = {"items": [], "limit": 50, "offset": 0}
        flash(f"Could not reach LDR API: {exc}", "danger")

    return render_template(
        "alerts/list.html",
        alerts=data["items"],
        limit=int(data["limit"]),
        offset=int(data["offset"]),
        filters=request.args,
    )


@bp.get("/<alert_id>")
def alert_detail(alert_id: str):
    try:
        alert = api_client.get(f"/v1/alerts/{alert_id}")
    except Exception as exc:
        flash(f"Alert not found: {exc}", "danger")
        return redirect(url_for("alerts.list_alerts"))

    return render_template("alerts/detail.html", alert=alert)


@bp.post("/<alert_id>/triage")
def triage_alert(alert_id: str):
    payload = {
        "status": request.form["status"],
        "closure_reason": request.form.get("closure_reason") or None,
        "notes": request.form.get("notes") or None,
    }
    try:
        api_client.patch(f"/v1/alerts/{alert_id}", payload)
        flash("Alert updated.", "success")
    except Exception as exc:
        flash(f"Update failed: {exc}", "danger")

    return redirect(url_for("alerts.alert_detail", alert_id=alert_id))
