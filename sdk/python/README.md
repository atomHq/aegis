# Aegis Python SDK

```bash
pip install aegis-sdk
```

```python
import os
from aegis_sdk import AegisClient

aegis = AegisClient(
    api_key=os.environ["AEGIS_API_KEY"],
    base_url=os.environ.get("AEGIS_BASE_URL", "http://localhost:8080"),
)

project = aegis.create_project({
    "name": "Backend",
    "slug": "backend",
    "environment": "production",
})

aegis.put_secret(project["id"], {
    "key": "DATABASE_URL",
    "value": "postgres://prod:secret@example/db",
})

secret = aegis.get_secret(project["id"], "DATABASE_URL")
print(secret["value"])
```

API key management endpoints are JWT-authenticated in the Aegis API:

```python
dashboard = AegisClient(auth_token=os.environ["AEGIS_JWT"])
created = dashboard.create_api_key({
    "name": "CI read only",
    "scopes": ["secrets:read"],
})
```
