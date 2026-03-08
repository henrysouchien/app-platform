# app-platform

Generic web app infrastructure for PostgreSQL pooling, structured logging, auth, middleware, and gateway proxying.

## Installation

```bash
pip install app-platform
pip install "app-platform[all]"
pip install "app-platform[fastapi]"
pip install "app-platform[auth-google]"
pip install "app-platform[gateway]"
```

## Included subpackages

| Subpackage | Provides |
| --- | --- |
| `db` | PostgreSQL connection pooling, pooled session helpers, migrations, and database exception utilities |
| `logging` | Structured file and JSONL logging, context helpers, logger access, and decorators for timing/error instrumentation |
| `middleware` | FastAPI middleware configuration for rate limiting, sessions, CORS, and validation/error handling |
| `auth` | Pluggable auth service base with in-memory and PostgreSQL-backed user/session stores |
| `gateway` | FastAPI router factory for proxying chat and tool approval requests to an upstream gateway |

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

## Requirements

Python 3.11+

## License

MIT
