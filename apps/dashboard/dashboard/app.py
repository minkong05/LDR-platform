# 📄 apps/dashboard/dashboard/app.py

from flask import Flask


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")

    from dashboard.config import Config

    app.config.from_object(Config)

    from dashboard.routes.alerts import bp as alerts_bp
    from dashboard.routes.entities import bp as entities_bp
    from dashboard.routes.main import bp as main_bp
    from dashboard.routes.response import bp as response_bp  # NEW

    app.register_blueprint(main_bp)
    app.register_blueprint(alerts_bp, url_prefix="/alerts")
    app.register_blueprint(entities_bp, url_prefix="/entities")
    app.register_blueprint(response_bp, url_prefix="/response")  # NEW

    return app
