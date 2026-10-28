# app-platform

Generic web app infrastructure for PostgreSQL pooling, structured logging, auth, middleware, and gateway proxying.

## Installation

```bash
pip install "app-platform[all]"
pip install "app-platform[fastapi]"
pip install "app-platform[fastapi,auth-google]"
pip install "app-platform[fastapi,gateway]"
```

`import app_platform` eagerly re-exports `db`, `logging`, and `middleware`, and
`middleware` is FastAPI-side, so the `fastapi` extra is the minimum supported
install. A bare `pip install app-platform` installs the package without those
runtime dependencies and is not a supported configuration.

## Included subpackages

| Subpackage | Provides |
| --- | --- |
| `db` | PostgreSQL connection pooling, pooled session helpers, migrations, and database exception utilities |
| `logging` | Structured file and JSONL logging, context helpers, logger access, and decorators for timing/error instrumentation |
| `middleware` | FastAPI middleware configuration for rate limiting, sessions, CORS, and validation/error handling |
| `auth` | Pluggable auth service base with in-memory and PostgreSQL-backed user/session stores |
| `gateway` | FastAPI router factory for proxying chat and tool approval requests to an upstream gateway |

Risk application assembly lives separately in `risk_app/` at the monorepo root:
app factories and route adapters, commercial policy, and provider-budget controls
are application code, not part of this distribution. The published `app_platform`
namespace contains only the library members above and its package metadata.

## Quick usage

### Database

```python
import os

from app_platform.db import PoolManager, get_db_session

os.environ["DATABASE_URL"] = "postgresql://postgres:postgres@localhost:5432/app"

pool_manager = PoolManager(min_connections=2, max_connections=10)
pool_manager.get_pool()

with get_db_session() as conn:
    with conn.cursor() as cursor:
        cursor.execute("SELECT 1 AS ok")
        print(cursor.fetchone())

pool_manager.close()
```

### Logging

```python
from app_platform.logging import (
    LoggingManager,
    configure_logging,
    log_errors,
    log_operation,
    log_timing,
)

logging_manager: LoggingManager = configure_logging(app_name="orders", log_dir="./logs")
logger = logging_manager.get_logger("service")

@log_errors()
@log_timing(threshold_s=0.25)
@log_operation("create_order")
def create_order(order_id: str) -> None:
    logger.info("creating order %s", order_id)


create_order("ord_123")
```

### Auth

```python
from app_platform.auth import AuthServiceBase, InMemorySessionStore, InMemoryUserStore

users = {}
sessions = {}

auth = AuthServiceBase(
    session_store=InMemorySessionStore(users_dict=users, sessions_dict=sessions),
    user_store=InMemoryUserStore(users_dict=users),
)

session_id = auth.create_user_session(
    {
        "google_user_id": "user-123",
        "email": "user@example.com",
        "name": "Example User",
    }
)

print(auth.get_user_by_session(session_id))
```

### Gateway

```python
from fastapi import FastAPI

from app_platform.gateway import GatewayConfig, create_gateway_router

app = FastAPI()


def get_current_user():
    return {"user_id": "user-123", "email": "user@example.com"}


gateway_router = create_gateway_router(
    GatewayConfig(
        gateway_url="https://gateway.example.com",
        api_key="gateway-api-key",
        channel="web",
    ),
    get_current_user=get_current_user,
)

app.include_router(gateway_router, prefix="/gateway")
```

The proxy is the cookie-authenticated edge: `get_current_user` supplies the
authoritative user identity, and the proxy enforces that identity and the web
channel upstream. Browser-supplied bearer credentials are not forwarded. Gateway
SSE bytes pass through unchanged, with bare heartbeat frames added while idle;
the proxy does not parse chat events or implement another chat client library.

`GatewaySessionManager` holds a bounded warm cache per user and, when supplied,
per conversation. Init alone does not establish conversation continuity: the
first chat POST accepted with HTTP 200 records that POST's session id as the log
identity. Later bearer refreshes present this opening id as `resume_session_id`,
not the newer session ids returned by resumed inits. A chat POST rejected for an
expired session is retried once with the same payload. Subscribe, cancel, and
approval requests are session-bound and are never replayed on a new session;
subscribe/cancel authentication failures invalidate the bearer while keeping the
opening log id for the next new chat turn. Approval failures return directly,
and the next chat can refresh if its bearer is rejected.
An init overlapping the opening POST is reconciled with that accepted log
before its bearer can be reused for another turn. If the competing init already
completed, acceptance invalidates its incompatible bearer; if it is still pending,
it completes by resuming the newly established log. Reset and eviction retire the
conversation, so delayed acceptance cannot restore it.

Continuity is warm-cache-only, not durable proxy storage. Process restart,
explicit reset, or idle cache eviction loses the held log identity; a later turn
starts a new conversation. If the gateway refuses a held resume identity, the
manager logs the continuity loss and initializes without it.

## Requirements

Python 3.11+

## License

MIT
