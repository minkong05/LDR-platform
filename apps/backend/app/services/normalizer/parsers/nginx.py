import re
from typing import Any

# Example expected format (we will enforce this in your demo nginx config later):
# Example expected format (enforced in demo nginx config):
# $remote_addr - $remote_user [$time_iso8601] "$request" $status
# $body_bytes_sent "$http_referer" "$http_user_agent"
NGINX_ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+-\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+)\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"\s*$'
)


def parse_nginx_access_line(line: str) -> dict[str, Any]:
    m = NGINX_ACCESS_RE.match(line.strip())
    if not m:
        raise ValueError("Unparseable nginx access log line")

    request = m.group("request")
    parts = request.split()
    method = parts[0] if len(parts) > 0 else None
    path = parts[1] if len(parts) > 1 else None

    return {
        "source_ip": m.group("ip"),
        "http_method": method,
        "url_path": path,
        "status_code": int(m.group("status")),
        "response_bytes": int(m.group("bytes")),
        "user_agent": m.group("ua"),
        "referer": m.group("referer"),
        "nginx_time_raw": m.group("time"),
    }
