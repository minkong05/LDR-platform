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
    for key in ("status", "severity", "source_ip"):
        val = request.args.get(key)
        if val:
            params[key] = val

    try:
        data = api_client.get("/v1/alerts", params=params)
    except Exception as exc:
        data = {"items": [], "limit": 50, "offset": 0}
        flash(f"Could not reach LDR API: {exc}", "danger")

    # Fetch risk scores for unique IPs on this page
    # One request per unique IP — small N in practice (≤50 rows, usually far fewer unique IPs)
    alerts = data["items"]
    unique_ips = list({a["source_ip"] for a in alerts})
    risk_by_ip: dict[str, dict] = {}
    for ip in unique_ips:
        try:
            risk_by_ip[ip] = api_client.get(f"/v1/entities/ip/{ip}/risk")
        except Exception:
            pass  # missing risk is non-fatal

    return render_template(
        "alerts/list.html",
        alerts=alerts,
        limit=int(data["limit"]),
        offset=int(data["offset"]),
        filters=request.args,
        risk_by_ip=risk_by_ip,
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
