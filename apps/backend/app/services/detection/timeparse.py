import re
from datetime import timedelta

DUR_RE = re.compile(r"^(?P<n>\d+)(?P<u>[smhd])$")


def parse_duration(s: str) -> timedelta:
    """
    Parse strings like:
      30s, 5m, 2h, 1d
    """
    m = DUR_RE.match(s.strip())
    if not m:
        raise ValueError(f"Invalid duration: {s}")

    n = int(m.group("n"))
    u = m.group("u")

    if u == "s":
        return timedelta(seconds=n)
    if u == "m":
        return timedelta(minutes=n)
    if u == "h":
        return timedelta(hours=n)
    if u == "d":
        return timedelta(days=n)

    raise ValueError(f"Invalid duration unit: {u}")
