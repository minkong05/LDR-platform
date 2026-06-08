# 📄 apps/dashboard/dashboard/routes/entities.py

import requests
from flask import Blueprint, Response, flash, render_template, request

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
        pass

    return render_template("entities/ip.html", summary=data, ip=ip, risk=risk)


@bp.get("/ip/<ip>/evidence")
def ip_evidence(ip: str):
    """
    Proxy the evidence ZIP from the backend and stream it to the browser
    as a file download. Passes through ?start= and ?end= query params
    so the analyst can scope the export from the UI.
    """
    params = {}
    if request.args.get("start"):
        params["start"] = request.args["start"]
    if request.args.get("end"):
        params["end"] = request.args["end"]

    try:
        # Use requests directly so we get the raw bytes + response headers
        url = f"{api_client._base()}/v1/entities/ip/{ip}/evidence"
        resp = requests.get(url, params=params, timeout=api_client._timeout())
        resp.raise_for_status()
    except Exception as exc:
        flash(f"Evidence export failed: {exc}", "danger")
        from flask import redirect, url_for

        return redirect(url_for("entities.ip_summary", ip=ip))

    # Forward the filename from the backend's Content-Disposition header
    content_disposition = resp.headers.get(
        "content-disposition",
        f'attachment; filename="evidence_{ip}.zip"',
    )

    return Response(
        resp.content,
        status=200,
        mimetype="application/zip",
        headers={"Content-Disposition": content_disposition},
    )
