# 📄 apps/dashboard/dashboard/routes/entities.py

from flask import Blueprint, flash, render_template

from dashboard import api_client

bp = Blueprint("entities", __name__)


@bp.get("/ip/<ip>")
def ip_summary(ip: str):
    try:
        data = api_client.get(f"/v1/entities/ip/{ip}")
    except Exception as exc:
        data = None
        flash(f"Could not load IP summary: {exc}", "danger")

    risk = None
    try:
        risk = api_client.get(f"/v1/entities/ip/{ip}/risk")
    except Exception:
        pass  # risk is optional — page still renders without it

    return render_template("entities/ip.html", summary=data, ip=ip, risk=risk)
