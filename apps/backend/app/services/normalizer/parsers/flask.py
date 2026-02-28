from typing import Any


def parse_flask_json(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Expected (recommended) Flask structured log fields (examples):
      - ip
      - method
      - path
      - status
      - user_agent
      - action (e.g., login_failed, login_success, token_invalid)
      - username (attempted or authenticated)
      - route_group (auth/api/admin)
    """
    parsed: dict[str, Any] = {}

    if "ip" in raw:
        parsed["source_ip"] = str(raw["ip"])

    if "method" in raw:
        parsed["http_method"] = str(raw["method"])

    if "path" in raw:
        parsed["url_path"] = str(raw["path"])

    if "status" in raw:
        try:
            parsed["status_code"] = int(raw["status"])
        except Exception:
            pass

    if "user_agent" in raw:
        parsed["user_agent"] = str(raw["user_agent"])

    if "action" in raw:
        parsed["action"] = str(raw["action"])

    if "username" in raw:
        parsed["username"] = str(raw["username"])

    if "route_group" in raw:
        parsed["route_group"] = str(raw["route_group"])

    return parsed
