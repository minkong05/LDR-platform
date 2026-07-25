# 📄 apps/dashboard/dashboard/routes/auth.py

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from dashboard.auth import verify_credentials

bp = Blueprint("auth", __name__)


def _is_safe_next(target: str | None) -> bool:
    """Only allow same-site relative redirects (block //host open-redirects)."""
    return bool(target) and target.startswith("/") and not target.startswith("//")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        role = verify_credentials(username, password)
        next_url = request.form.get("next")

        if role is None:
            flash("Invalid username or password.", "danger")
            return render_template("auth/login.html", next=next_url), 401

        session.clear()
        session.permanent = True
        session["username"] = username
        session["role"] = role
        return redirect(next_url if _is_safe_next(next_url) else url_for("main.index"))

    return render_template("auth/login.html", next=request.args.get("next", ""))


@bp.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
