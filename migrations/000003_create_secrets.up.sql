CREATE TABLE secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    key VARCHAR(255) NOT NULL,
    encrypted_value BYTEA NOT NULL,
    encrypted_dek BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    dek_nonce BYTEA NOT NULL,
    version INT NOT NULL DEFAULT 1,
    is_active BOOLEAN NOT NULL DEFAULT true,
    expires_at TIMESTAMPTZ,
    tags JSONB DEFAULT '{}',
    created_by VARCHAR(255),
    updated_by VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(project_id, key, version)
);

CREATE INDEX idx_secrets_project ON secrets(project_id);
CREATE INDEX idx_secrets_tenant ON secrets(tenant_id);
CREATE INDEX idx_secrets_key ON secrets(project_id, key);
CREATE INDEX idx_secrets_expires ON secrets(expires_at) WHERE expires_at IS NOT NULL;
