# Aegis

**Production-ready, multi-tenant secrets management platform** — built in Go with PostgreSQL.

Similar to HashiCorp Vault / AWS SSM Parameter Store, designed as a SaaS that other businesses integrate via API.

---

## Features

- **Envelope Encryption** — AES-256-GCM with per-tenant KEK derivation (HKDF-SHA256)
- **Multi-Tenant Isolation** — Row-level tenant filtering on every database query
- **Versioned Secrets** — Full version history with rollback capability
- **Scoped API Keys** — RBAC with granular scopes (`secrets:read`, `secrets:write`, `secrets:admin`, `projects:manage`, `api_keys:manage`, `audit:read`)
- **User Authentication** — Email/password signup with bcrypt, JWT sessions, email verification
- **Audit Trail** — Immutable, async audit logging for every operation
- **Per-Tenant Rate Limiting** — Token bucket rate limiter with plan-based limits
- **Plan-Based Limits** — Configurable max secrets, max projects, and rate limits per plan

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        HTTP Layer                            │
│  ┌─────────┐  ┌──────────┐  ┌────────┐  ┌───────────────┐   │
│  │RequestID│→ │ RealIP   │→ │ Logger │→ │ Auth (JWT/Key)│   │
│  └─────────┘  └──────────┘  └────────┘  └───────────────┘   │
├──────────────────────────────────────────────────────────────┤
│                       Handler Layer                          │
│  Auth │ Tenant │ Project │ Secret │ APIKey │ Health          │
├──────────────────────────────────────────────────────────────┤
│                       Service Layer                          │
│  User │ Tenant │ Project │ Secret │ APIKey │ Audit │ Email   │
├──────────────────────────────────────────────────────────────┤
│                      Repository Layer                        │
│  pgx/v5 + pgxpool — parameterized queries, tenant isolation │
├──────────────────────────────────────────────────────────────┤
│                       Crypto Module                          │
│  Envelope Encryption │ HKDF KEK │ bcrypt │ JWT │ API Keys   │
├──────────────────────────────────────────────────────────────┤
│                      PostgreSQL 16                           │
│  tenants │ projects │ secrets │ api_keys │ audit_logs │users │
└──────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Go 1.21+
- Docker & Docker Compose
- Make

### Setup

```bash
# Clone
git clone https://github.com/oluwasemilore/aegis.git
cd aegis

# Generate encryption keys
make generate-key
# Copy the output — you need it twice (MASTER_KEY and JWT_SECRET)

# Configure environment
cp .env.example .env
# Edit .env and set:
#   MASTER_KEY=<base64 key from above>
#   JWT_SECRET=<base64 key from above>
#   DATABASE_URL=postgres://aegis:aegis@localhost:5432/aegis?sslmode=disable

# Start PostgreSQL
make docker-up

# Run database migrations
make migrate-up

# Start the server
make dev
```

The server starts on `http://localhost:8080`.

## API Reference

### Authentication

#### Sign Up

```bash
curl -X POST http://localhost:8080/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "password": "securepass123",
    "first_name": "Alice",
    "last_name": "Smith",
    "org_name": "Acme Corp",
    "org_slug": "acme"
  }'
```

Creates a user, organization (tenant), default project, and admin API key atomically. Sends a 5-digit verification code to the email (logged to console in development mode).

#### Verify Email

```bash
curl -X POST http://localhost:8080/api/v1/auth/verify-email \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "code": "48291"
  }'
```

#### Login

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "password": "securepass123"
  }'
```

Returns a JWT token (24h expiry):
```json
{
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "token_type": "Bearer",
    "expires_in": 86400
  }
}
```

#### Resend Verification

```bash
curl -X POST http://localhost:8080/api/v1/auth/resend-verification \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com"}'
```

---

### Secrets (API Key Auth)

Use the admin API key created during signup. All secret operations require `Authorization: Bearer <api_key>`.

#### Store a Secret

```bash
curl -X PUT http://localhost:8080/api/v1/projects/{project_id}/secrets \
  -H "Authorization: Bearer aegis_sk_live_..." \
  -H "Content-Type: application/json" \
  -d '{
    "key": "DATABASE_URL",
    "value": "postgres://prod:secret@db.example.com/myapp"
  }'
```

#### Retrieve a Secret

```bash
curl http://localhost:8080/api/v1/projects/{project_id}/secrets/DATABASE_URL \
  -H "Authorization: Bearer aegis_sk_live_..."
```

#### Bulk Retrieve

```bash
curl -X POST http://localhost:8080/api/v1/projects/{project_id}/secrets/bulk \
  -H "Authorization: Bearer aegis_sk_live_..." \
  -H "Content-Type: application/json" \
  -d '{"keys": ["DATABASE_URL", "REDIS_URL", "STRIPE_KEY"]}'
```

#### List Secret Keys

```bash
curl http://localhost:8080/api/v1/projects/{project_id}/secrets \
  -H "Authorization: Bearer aegis_sk_live_..."
```

#### Get Specific Version

```bash
curl http://localhost:8080/api/v1/projects/{project_id}/secrets/DATABASE_URL/versions/2 \
  -H "Authorization: Bearer aegis_sk_live_..."
```

#### Delete a Secret

```bash
curl -X DELETE http://localhost:8080/api/v1/projects/{project_id}/secrets/DATABASE_URL \
  -H "Authorization: Bearer aegis_sk_live_..."
```

---

### Projects (API Key Auth)

```bash
# Create
curl -X POST http://localhost:8080/api/v1/projects \
  -H "Authorization: Bearer aegis_sk_live_..." \
  -H "Content-Type: application/json" \
  -d '{"name": "Backend", "slug": "backend", "environment": "production"}'

# List
curl http://localhost:8080/api/v1/projects \
  -H "Authorization: Bearer aegis_sk_live_..."
```

---

### API Keys (JWT Auth)

Manage API keys through the dashboard using your JWT token:

```bash
# Create a read-only key
curl -X POST http://localhost:8080/api/v1/api-keys \
  -H "Authorization: Bearer eyJhbGci..." \
  -H "Content-Type: application/json" \
  -d '{"name": "CI/CD Read Only", "scopes": ["secrets:read"]}'

# List keys
curl http://localhost:8080/api/v1/api-keys \
  -H "Authorization: Bearer eyJhbGci..."

# Revoke a key
curl -X DELETE http://localhost:8080/api/v1/api-keys/{key_id} \
  -H "Authorization: Bearer eyJhbGci..."
```

---

### Audit Logs (API Key Auth)

```bash
curl "http://localhost:8080/api/v1/audit-logs?limit=20&action=secret.read" \
  -H "Authorization: Bearer aegis_sk_live_..."
```

---

## API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | — | Health check |
| `/api/v1/auth/signup` | POST | — | Register user + org |
| `/api/v1/auth/login` | POST | — | Get JWT token |
| `/api/v1/auth/verify-email` | POST | — | Verify email code |
| `/api/v1/auth/resend-verification` | POST | — | Resend code |
| `/api/v1/tenants/{id}` | GET | JWT | Get tenant |
| `/api/v1/tenants/{id}` | PATCH | JWT | Update tenant name |
| `/api/v1/api-keys` | POST | JWT | Create API key |
| `/api/v1/api-keys` | GET | JWT | List API keys |
| `/api/v1/api-keys/{id}` | DELETE | JWT | Revoke API key |
| `/api/v1/projects` | POST | API Key | Create project |
| `/api/v1/projects` | GET | API Key | List projects |
| `/api/v1/projects/{id}` | GET | API Key | Get project |
| `/api/v1/projects/{id}` | PATCH | API Key | Update project |
| `/api/v1/projects/{id}` | DELETE | API Key | Delete project |
| `/api/v1/projects/{id}/secrets` | PUT | API Key | Store secret |
| `/api/v1/projects/{id}/secrets` | GET | API Key | List secret keys |
| `/api/v1/projects/{id}/secrets/bulk` | POST | API Key | Bulk retrieve |
| `/api/v1/projects/{id}/secrets/{key}` | GET | API Key | Get secret |
| `/api/v1/projects/{id}/secrets/{key}` | DELETE | API Key | Delete secret |
| `/api/v1/projects/{id}/secrets/{key}/versions` | GET | API Key | List versions |
| `/api/v1/projects/{id}/secrets/{key}/versions/{v}` | GET | API Key | Get version |
| `/api/v1/audit-logs` | GET | API Key | Query audit logs |

## Encryption Design

```
Master Key (32 bytes, from env)
    │
    ├─ HKDF-SHA256(master_key, salt=tenant_id, info="aegis-kek")
    │       │
    │       └─ Tenant KEK (Key Encryption Key)
    │               │
    │               ├─ AES-256-GCM(DEK, KEK) → Encrypted DEK
    │               │
    │               └─ Per-secret random DEK (Data Encryption Key)
    │                       │
    │                       └─ AES-256-GCM(secret_value, DEK) → Encrypted Value
    │
    └─ Each tenant gets a unique KEK derived from the master key
       Each secret gets a unique DEK — compromise of one secret doesn't expose others
```

- **Master Key** — Single 32-byte key stored in environment variable
- **KEK** — Per-tenant key derived via HKDF-SHA256 (never stored)
- **DEK** — Per-secret random key, encrypted with KEK and stored alongside the ciphertext
- **Zeroing** — DEKs and KEKs are zeroed from memory after use

## Project Structure

```
aegis/
├── cmd/server/main.go              # Entry point, dependency wiring
├── internal/
│   ├── config/config.go            # Env-based config (viper)
│   ├── crypto/
│   │   ├── envelope.go             # AES-256-GCM envelope encryption
│   │   ├── hash.go                 # API key generation + SHA-256 hashing
│   │   ├── jwt.go                  # JWT token generation/validation
│   │   ├── kek.go                  # HKDF key derivation
│   │   └── password.go             # bcrypt password hashing
│   ├── domain/                     # Entities, DTOs, repository interfaces
│   ├── handler/                    # HTTP handlers
│   ├── middleware/                  # Auth, rate limit, logging, JWT
│   ├── pkg/                        # Shared utilities (apierror, pagination, validator)
│   ├── repository/                 # PostgreSQL implementations
│   ├── server/                     # Router + HTTP server
│   └── service/                    # Business logic
├── migrations/                     # SQL migrations (golang-migrate)
├── Dockerfile                      # Multi-stage build
├── docker-compose.yml              # PostgreSQL + app
└── Makefile                        # Dev commands
```

## Makefile Commands

```bash
make build          # Build binary to bin/aegis
make run            # Build and run
make dev            # Run with go run (development)
make test           # Run tests with race detector
make migrate-up     # Apply all migrations
make migrate-down   # Rollback last migration
make docker-up      # Start PostgreSQL
make docker-down    # Stop PostgreSQL
make generate-key   # Generate a 32-byte base64 key
make lint           # Run golangci-lint
make clean          # Remove build artifacts
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PORT` | No | `8080` | Server port |
| `ENV` | No | `development` | Environment (`development`, `staging`, `production`) |
| `DATABASE_URL` | Yes | — | PostgreSQL connection string |
| `MASTER_KEY` | Yes | — | Base64-encoded 32-byte encryption key |
| `JWT_SECRET` | Yes | — | Base64-encoded 32+ byte JWT signing key |
| `DB_MAX_CONNS` | No | `25` | Max database connections |
| `DB_MIN_CONNS` | No | `5` | Min database connections |
| `DEFAULT_RATE_LIMIT` | No | `60` | Default requests per minute |
| `LOG_LEVEL` | No | `info` | Log level (`debug`, `info`, `warn`, `error`) |
| `SMTP_HOST` | Prod only | — | SMTP server host |
| `SMTP_PORT` | No | `587` | SMTP server port |
| `SMTP_USER` | Prod only | — | SMTP username |
| `SMTP_PASS` | Prod only | — | SMTP password |
| `SMTP_FROM` | No | `noreply@aegis.dev` | From email address |

> **Note**: In development mode, verification codes are logged to the console instead of being sent via SMTP.

## Security

- Secrets encrypted at rest with AES-256-GCM envelope encryption
- Per-tenant key isolation via HKDF-SHA256
- API keys stored as SHA-256 hashes — plaintext shown only once at creation
- Passwords hashed with bcrypt (cost 12)
- JWT tokens with HS256 signing and 24h expiry
- Request body size limits on all endpoints
- Per-tenant rate limiting
- Structured audit trail for all operations
- Tenant isolation enforced at the repository layer

## License

MIT
