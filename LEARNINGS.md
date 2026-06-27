# LDR Platform — Engineering Retrospective

Technical decisions, trade-offs, and failure modes encountered while building
a mini SOC platform from scratch over 16 weeks.

---

## 1. Close before extend

Resist the urge to bolt on integrations (MITRE ATT&CK deep links,
VirusTotal enrichment) before the core platform is properly closed. A clean
v1.0 with passing tests, a coherent demo, and complete documentation is worth
more than a sprawling project with half-finished extras. Ship a closed v1,
then layer on v2.


## 2. Trace every feature end-to-end before calling it done

A full code audit before close-out revealed that the entire response layer —
`BlockService`, the FastAPI router, audit log writes — was built and working
but completely invisible to dashboard users. No UI existed to trigger any of
it.

A feature is not done when the backend works. It is done when a user can
exercise it from the UI through to the database. Always trace the full path
before marking a feature complete.


## 3. JSONB vs JSON in SQLAlchemy — the SQLite trap

Unit tests running against SQLite (in-memory) failed with:
`CompileError: postgresql JSONB type is not supported in SQLite`

`JSONB()` is a PostgreSQL-specific type. SQLAlchemy cannot compile the DDL
for SQLite.

**Fix:** Use `JSON().with_variant(JSONB(), "postgresql")` across all models
with JSONB columns (`audit_log.py`, `alert.py`, `event.py`). SQLAlchemy then
selects plain JSON for SQLite and JSONB for PostgreSQL.

**Secondary issue:** The `.astext` accessor on JSONB columns also breaks
after this change. Replace with `cast(column, String)`, which works across
both dialects.


## 4. Test observable behaviour, not framework internals

An early route registration test introspected FastAPI internals:

```python
# Brittle — coupled to framework internals
routes = [r.path for r in app.routes]
assert "/v1/events" in routes
```

This broke silently in CI. The correct approach tests the contract:

```python
# Stable — tests the actual HTTP interface
client = TestClient(app)
r = client.get("/v1/events")
assert r.status_code != 404
```

Test the contract (HTTP response), not the implementation (internal route
list). Framework internals can change between versions; HTTP responses are
the public interface.


## 5. Pin tool versions across every environment

Ruff was installed at different versions across the local venv, pre-commit
hooks, and GitHub Actions CI — causing CI to fail on formatting that passed
locally.

**Fix:** Pin explicitly in all three places:
- `pyproject.toml` (or `requirements-dev.txt`) for the local venv
- `.pre-commit-config.yaml` `rev:` field for the hook
- `ci.yml` pip install step for CI

An unpinned version in any one of these will eventually cause a mismatch.


## 6. Anchor test paths to `__file__`, not CWD

```python
rules_dir = Path("rules")                              # Breaks outside project root
rules_dir = Path(__file__).parent / "fixtures" / "rules"  # Portable
```

Relative paths resolve against the working directory, which varies between
local runs, Docker containers, and CI jobs. Anchoring to `__file__` makes
path resolution deterministic.


## 7. Cross-rule correlation is an architectural gap

Rule `LDR-WEB-005` detects a successful login after a brute-force sequence
from the same IP. With `count: 1`, any successful login from a high-traffic
IP triggers it — producing excessive false positives.

Proper correlation would require the detection engine to query prior alert
state ("has this IP triggered LDR-WEB-001 in the last N minutes?") before
firing. The current architecture evaluates each rule independently against
raw events with no cross-rule awareness.

Fixing this requires a second-pass correlation engine that reads alert state,
not just event state. This is a documented, intentional scope boundary for
v1.0.


## 8. Proxy backend responses — never leak internal URLs

The evidence export ZIP is served by the FastAPI backend at
`GET /v1/entities/ip/{ip}/evidence`. Linking directly from the Flask template
exposes the internal Docker hostname (`http://backend:8000`), which is
unreachable from the browser.

**Fix:** The Flask dashboard proxies the request — it fetches the ZIP
internally and streams it to the browser under a Flask route. The browser
only communicates with the dashboard on port 5001.

In a multi-service architecture, the frontend service should be the sole
ingress point. Backend services must be unreachable from outside the network.


## 9. structlog + middleware + contextvars

The platform uses `structlog` for structured JSON logging, a
`RequestIDMiddleware` that generates a `request_id` per request, and
`contextvars` to propagate that ID through the call stack without passing it
as an argument. These three layers work together to produce correlated,
structured logs per request. A deeper review of the `contextvars` binding
lifecycle is planned as a follow-up.

---

## What I would do differently

- **Add integration tests from day one.** Several bugs (JSONB/SQLite, path
  resolution) would have been caught immediately with integration tests
  rather than surfacing weeks later.
- **Design UI and backend together.** The block/unblock backend was built
  with no dashboard integration, requiring a follow-up audit to catch the
  gap. Plan both layers of any feature at the same time.
- **Write retrospective notes incrementally.** Reconstructing decisions at
  the end is less accurate than a short weekly note written in context.
