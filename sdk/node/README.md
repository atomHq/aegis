# Aegis Node SDK

```bash
npm install @aegis/sdk
```

```ts
import { AegisClient } from "@aegis/sdk";

const aegis = new AegisClient({
  apiKey: process.env.AEGIS_API_KEY,
  baseUrl: process.env.AEGIS_BASE_URL ?? "http://localhost:8080",
});

const project = await aegis.createProject({
  name: "Backend",
  slug: "backend",
  environment: "production",
});

await aegis.putSecret(project.id, {
  key: "DATABASE_URL",
  value: "postgres://prod:secret@example/db",
});

const secret = await aegis.getSecret(project.id, "DATABASE_URL");
console.log(secret.value);
```

API key management endpoints are JWT-authenticated in the Aegis API:

```ts
const dashboard = new AegisClient({ authToken: process.env.AEGIS_JWT });
const created = await dashboard.createAPIKey({
  name: "CI read only",
  scopes: ["secrets:read"],
});
```
