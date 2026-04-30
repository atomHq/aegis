export type Scope =
  | "secrets:read"
  | "secrets:write"
  | "secrets:admin"
  | "projects:manage"
  | "api_keys:manage"
  | "audit:read";

export interface Project {
  id: string;
  tenant_id: string;
  name: string;
  slug: string;
  description?: string;
  environment: "development" | "staging" | "production";
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateProjectInput {
  name: string;
  slug: string;
  description?: string;
  environment: "development" | "staging" | "production";
}

export interface UpdateProjectInput {
  name?: string;
  description?: string;
  is_active?: boolean;
}

export interface Secret {
  id: string;
  key: string;
  value: string;
  version: number;
  expires_at?: string;
  tags?: Record<string, unknown>;
  created_by?: string;
  created_at: string;
}

export interface PutSecretInput {
  key: string;
  value: string;
  expires_at?: string;
  tags?: Record<string, unknown>;
}

export interface SecretWriteResult {
  id: string;
  key: string;
  version: number;
  created_at: string;
}

export interface SecretKey {
  key: string;
  latest_version: number;
  created_at: string;
  updated_at: string;
}

export interface SecretVersion {
  id: string;
  version: number;
  is_active: boolean;
  created_by?: string;
  created_at: string;
}

export interface APIKey {
  id: string;
  tenant_id: string;
  name: string;
  key_prefix: string;
  scopes: Scope[];
  project_ids?: string[];
  is_active: boolean;
  last_used_at?: string;
  expires_at?: string;
  created_at: string;
}

export interface CreateAPIKeyInput {
  name: string;
  scopes: Scope[];
  project_ids?: string[];
  expires_at?: string;
}

export interface CreateAPIKeyResult {
  key: APIKey;
  plaintext_key: string;
  warning: string;
}

export interface AuditLog {
  id: string;
  tenant_id: string;
  actor: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  metadata?: Record<string, unknown>;
  ip_address?: string;
  created_at: string;
}

export interface ListOptions {
  limit?: number;
  cursor?: string | Date;
}

export interface AuditLogFilter extends ListOptions {
  action?: string;
  resource_type?: string;
  start_time?: string | Date;
  end_time?: string | Date;
}

export interface AegisClientOptions {
  apiKey?: string;
  authToken?: string;
  baseUrl?: string;
  fetch?: typeof globalThis.fetch;
  userAgent?: string;
}
