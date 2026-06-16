# 📄 apps/dashboard/dashboard/routes/entities.py

import requests
from flask import Blueprint, Response, flash, redirect, render_template, request, url_for

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

    # NEW — fetch block status so the template can show the badge + correct button
    block_status = None
    try:
        block_status = api_client.get(f"/v1/response/block-status/{ip}")
    except Exception:
        pass

    return render_template(
        "entities/ip.html",
        summary=data,
        ip=ip,
        risk=risk,
        block_status=block_status,  # NEW
    )


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
        url = f"{api_client._base()}/v1/entities/ip/{ip}/evidence"
        resp = requests.get(url, params=params, timeout=api_client._timeout())
        resp.raise_for_status()
    except Exception as exc:
        flash(f"Evidence export failed: {exc}", "danger")
        return redirect(url_for("entities.ip_summary", ip=ip))

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


@bp.post("/ip/<ip>/block")
def block_ip(ip: str):
    """
    Call the backend to block this IP and redirect back to the IP page.
    Reason is optionally submitted from a form field.
    """
    reason = request.form.get("reason") or "Blocked via dashboard"
    try:
        result = api_client.post(
            "/v1/response/block",
            {"ip": ip, "reason": reason, "actor": "analyst"},
        )
        note = result.get("note", "")
        if note == "already_blocked":
            flash(f"{ip} is already blocked.", "warning")
        else:
            flash(f"{ip} has been blocked.", "success")
    except Exception as exc:
        flash(f"Block failed: {exc}", "danger")

    return redirect(url_for("entities.ip_summary", ip=ip))


@bp.post("/ip/<ip>/unblock")
def unblock_ip(ip: str):
    """
    Call the backend to unblock this IP and redirect back to the IP page.
    """
    try:
        result = api_client.post(
            f"/v1/response/unblock/{ip}",
            {},
        )
        note = result.get("note", "")
        if note == "not_blocked":
            flash(f"{ip} was not blocked.", "warning")
        else:
            flash(f"{ip} has been unblocked.", "success")
    except Exception as exc:
        flash(f"Unblock failed: {exc}", "danger")

    return redirect(url_for("entities.ip_summary", ip=ip))
