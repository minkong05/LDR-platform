"""Synthetic per-rule attack event builders.

Fabricates flask/nginx ingest payloads that satisfy a given detection rule's
`match` conditions, using that rule's own `condition.count`/`condition.window`
so the simulator can't silently drift from the YAML it's meant to exercise.
Local/demo data only — never send this to a real deployment.
"""

from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.domain.rules.rule_schema import Rule
from app.services.detection.rule_loader import load_rules


def synthetic_ip_for_rule(rule_id: str) -> str:
    suffix = rule_id.rsplit("-", 1)[-1]
    try:
        n = int(suffix)
    except ValueError as e:
        raise ValueError(f"cannot derive synthetic IP from rule id {rule_id!r}") from e
    return f"203.0.121.{n * 10}"


def get_rule_by_id(rules_dir: Path, rule_id: str) -> Rule:
    rules = load_rules(rules_dir)

    for rule in rules:
        if rule.id == rule_id:
            return rule

    raise ValueError(f"no rule with id {rule_id!r} found in {rules_dir}")


def _flask_event(
    *,
    timestamp: datetime,
    ip: str,
    path: str,
    status: int,
    action: str,
    route_group: str,
    username: str,
) -> dict[str, Any]:
    return {
        "event_timestamp": timestamp.isoformat(),
        "log_source": "flask",
        "service_name": "simulated-attack",
        "source_ip": ip,
        "raw": {
            "ip": ip,
            "method": "POST",
            "path": path,
            "status": status,
            "action": action,
            "route_group": route_group,
            "username": username,
        },
    }


def _nginx_event(
    *, timestamp: datetime, ip: str, path: str, status: int, user_agent: str
) -> dict[str, Any]:
    ts_log = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")
    line = f'{ip} - - [{ts_log}] "GET {path} HTTP/1.1" {status} 0 "-" "{user_agent}"'
    return {
        "event_timestamp": timestamp.isoformat(),
        "log_source": "nginx",
        "service_name": "simulated-attack",
        "source_ip": ip,
        "raw": {"nginx_line": line},
    }


def _build_web_001(rule: Rule, ip: str) -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    return [
        _flask_event(
            timestamp=now + timedelta(seconds=i),
            ip=ip,
            path="/login",
            status=401,
            action="login_failed",
            route_group="auth",
            username=f"user{i}",
        )
        for i in range(rule.condition.count)
    ]


def _build_web_002(rule: Rule, ip: str) -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    return [
        _nginx_event(
            timestamp=now + timedelta(seconds=i),
            ip=ip,
            path="/login",
            status=401,
            user_agent="python-requests/2.31",
        )
        for i in range(rule.condition.count)
    ]


def _build_web_003(rule: Rule, ip: str) -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    return [
        _nginx_event(
            timestamp=now + timedelta(seconds=i),
            ip=ip,
            path="/admin",
            status=403,
            user_agent="curl/7.88",
        )
        for i in range(rule.condition.count)
    ]


def _build_web_004(rule: Rule, ip: str) -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    return [
        _nginx_event(
            timestamp=now + timedelta(seconds=i),
            ip=ip,
            path=f"/probe/path{i}",
            status=404,
            user_agent="gobuster/3.6",
        )
        for i in range(rule.condition.count)
    ]


def _build_web_005(rule: Rule, ip: str) -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    return [
        _flask_event(
            timestamp=now + timedelta(seconds=i),
            ip=ip,
            path="/login",
            status=200,
            action="login_success",
            route_group="auth",
            username="admin",
        )
        for i in range(rule.condition.count)
    ]


def _build_web_006(rule: Rule, ip: str) -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    return [
        _flask_event(
            timestamp=now + timedelta(seconds=i),
            ip=ip,
            path="/login",
            status=401,
            action="login_failed",
            route_group="auth",
            username=f"probe_user{i}",
        )
        for i in range(rule.condition.count)
    ]


_BUILDERS: dict[str, Callable[[Rule, str], list[dict[str, Any]]]] = {
    "LDR-WEB-001": _build_web_001,
    "LDR-WEB-002": _build_web_002,
    "LDR-WEB-003": _build_web_003,
    "LDR-WEB-004": _build_web_004,
    "LDR-WEB-005": _build_web_005,
    "LDR-WEB-006": _build_web_006,
}


def build_events_for_rule(rule: Rule, ip: str | None = None) -> list[dict[str, Any]]:
    builder = _BUILDERS.get(rule.id)
    if builder is None:
        raise ValueError(f"no attack shape defined for rule {rule.id!r}")

    return builder(rule, ip or synthetic_ip_for_rule(rule.id))
