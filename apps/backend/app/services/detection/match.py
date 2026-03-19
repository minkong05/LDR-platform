from typing import Any


def get_by_dotted_path(obj: dict[str, Any], path: str) -> Any:
    cur: Any = obj
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def rule_matches(event: dict[str, Any], match: dict[str, str]) -> bool:
    for k, expected in match.items():
        actual = get_by_dotted_path(event, k)
        if actual is None:
            return False
        # normalize to string compare for now (simple + deterministic)
        if str(actual) != str(expected):
            return False
    return True
