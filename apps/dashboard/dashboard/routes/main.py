# apps/dashboard/dashboard/routes/main.py
from flask import Blueprint, redirect, url_for

bp = Blueprint("main", __name__)


@bp.get("/")
def index():
    return redirect(url_for("alerts.list_alerts"))


@bp.get("/health")
def health():
    return {"status": "ok"}
