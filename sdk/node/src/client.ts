import { AegisApiError } from "./errors.js";
import type {
  AegisClientOptions,
  APIKey,
  AuditLog,
  AuditLogFilter,
  CreateAPIKeyInput,
  CreateAPIKeyResult,
  CreateProjectInput,
  ListOptions,
  Project,
  PutSecretInput,
  Secret,
  SecretKey,
  SecretVersion,
  SecretWriteResult,
  UpdateProjectInput,
} from "./types.js";

interface SuccessEnvelope<T> {
  status: "success";
  data: T;
  meta: {
    request_id: string;
    timestamp: string;
  };
}

interface ErrorEnvelope {
  status: "error";
  error: {
    code: string;
    message: string;
    details?: unknown;
  };
  meta: {
    request_id: string;
    timestamp: string;
  };
}

export class AegisClient {
  private readonly apiKey?: string;
  private readonly authToken?: string;
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof globalThis.fetch;
  private readonly userAgent: string;

  constructor(options: AegisClientOptions = {}) {
    this.apiKey = options.apiKey;
    this.authToken = options.authToken;
    this.baseUrl = (options.baseUrl ?? "http://localhost:8080").replace(/\/+$/, "");
    this.fetchImpl = options.fetch ?? globalThis.fetch;
    this.userAgent = options.userAgent ?? "aegis-node/0.1.0";

    if (!this.fetchImpl) {
      throw new Error("AegisClient requires a fetch implementation.");
    }
  }

  async createProject(input: CreateProjectInput): Promise<Project> {
    return this.request("POST", "/api/v1/projects", { body: input });
  }

  async listProjects(options?: ListOptions): Promise<Project[]> {
    return this.request("GET", "/api/v1/projects", { query: options });
  }

  async getProject(projectId: string): Promise<Project> {
    return this.request("GET", `/api/v1/projects/${encodeURIComponent(projectId)}`);
  }

  async updateProject(projectId: string, input: UpdateProjectInput): Promise<Project> {
    return this.request("PATCH", `/api/v1/projects/${encodeURIComponent(projectId)}`, {
      body: input,
    });
  }

  async deleteProject(projectId: string): Promise<void> {
    await this.request("DELETE", `/api/v1/projects/${encodeURIComponent(projectId)}`);
  }

  async putSecret(projectId: string, input: PutSecretInput): Promise<SecretWriteResult> {
    return this.request("PUT", `/api/v1/projects/${encodeURIComponent(projectId)}/secrets`, {
      body: input,
    });
  }

  async bulkPutSecrets(
    projectId: string,
    secrets: PutSecretInput[]
  ): Promise<SecretWriteResult[]> {
    return this.request("PUT", `/api/v1/projects/${encodeURIComponent(projectId)}/secrets/bulk`, {
      body: { secrets },
    });
  }

  async getSecret(projectId: string, key: string): Promise<Secret> {
    return this.request(
      "GET",
      `/api/v1/projects/${encodeURIComponent(projectId)}/secrets/${encodeURIComponent(key)}`
    );
  }

  async bulkGetSecrets(projectId: string, keys: string[]): Promise<Record<string, string>> {
    return this.request("POST", `/api/v1/projects/${encodeURIComponent(projectId)}/secrets/bulk`, {
      body: { keys },
    });
  }

  async listSecretKeys(projectId: string, options?: ListOptions): Promise<SecretKey[]> {
    return this.request("GET", `/api/v1/projects/${encodeURIComponent(projectId)}/secrets`, {
      query: options,
    });
  }

  async deleteSecret(projectId: string, key: string): Promise<void> {
    await this.request(
      "DELETE",
      `/api/v1/projects/${encodeURIComponent(projectId)}/secrets/${encodeURIComponent(key)}`
    );
  }

  async listSecretVersions(projectId: string, key: string): Promise<SecretVersion[]> {
    return this.request(
      "GET",
      `/api/v1/projects/${encodeURIComponent(projectId)}/secrets/${encodeURIComponent(key)}/versions`
    );
  }

  async getSecretVersion(projectId: string, key: string, version: number): Promise<Secret> {
    return this.request(
      "GET",
      `/api/v1/projects/${encodeURIComponent(projectId)}/secrets/${encodeURIComponent(key)}/versions/${version}`
    );
  }

  async listAuditLogs(filter?: AuditLogFilter): Promise<AuditLog[]> {
    return this.request("GET", "/api/v1/audit-logs", { query: filter });
  }

  async createAPIKey(input: CreateAPIKeyInput): Promise<CreateAPIKeyResult> {
    return this.request("POST", "/api/v1/api-keys", { body: input, auth: "jwt" });
  }

  async listAPIKeys(): Promise<APIKey[]> {
    return this.request("GET", "/api/v1/api-keys", { auth: "jwt" });
  }

  async revokeAPIKey(keyId: string): Promise<void> {
    await this.request("DELETE", `/api/v1/api-keys/${encodeURIComponent(keyId)}`, {
      auth: "jwt",
    });
  }

  private async request<T>(
    method: string,
    path: string,
    options: {
      body?: unknown;
      query?: object;
      auth?: "apiKey" | "jwt";
    } = {}
  ): Promise<T> {
    const token = options.auth === "jwt" ? this.authToken : this.apiKey;
    if (!token) {
      throw new Error(
        options.auth === "jwt"
          ? "AegisClient requires authToken for API key management endpoints."
          : "AegisClient requires apiKey for API-key authenticated endpoints."
      );
    }

    const url = new URL(`${this.baseUrl}${path}`);
    appendQuery(url, options.query);

    const headers = new Headers({
      Accept: "application/json",
      Authorization: `Bearer ${token}`,
      "User-Agent": this.userAgent,
    });
    let body: string | undefined;
    if (options.body !== undefined) {
      headers.set("Content-Type", "application/json");
      body = JSON.stringify(options.body);
    }

    const response = await this.fetchImpl(url, { method, headers, body });
    const text = await response.text();
    const parsed = text ? safeJson(text) : null;

    if (!response.ok) {
      if (isErrorEnvelope(parsed)) {
        throw new AegisApiError({
          code: parsed.error.code,
          message: parsed.error.message,
          status: response.status,
          details: parsed.error.details,
          requestId: parsed.meta.request_id,
        });
      }
      throw new AegisApiError({
        code: "UNEXPECTED_RESPONSE",
        message: text || response.statusText,
        status: response.status,
      });
    }

    if (isSuccessEnvelope<T>(parsed)) {
      return parsed.data;
    }

    if (text.length === 0) {
      return undefined as T;
    }

    throw new AegisApiError({
      code: "UNEXPECTED_RESPONSE",
      message: "Received an unexpected response from the Aegis API.",
      status: response.status,
    });
  }
}

function appendQuery(url: URL, query?: object): void {
  if (!query) return;
  for (const [key, value] of Object.entries(query as Record<string, unknown>)) {
    if (value === undefined || value === null || value === "") continue;
    if (value instanceof Date) {
      url.searchParams.set(key, value.toISOString());
    } else {
      url.searchParams.set(key, String(value));
    }
  }
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function isSuccessEnvelope<T>(value: unknown): value is SuccessEnvelope<T> {
  return !!value && typeof value === "object" && (value as SuccessEnvelope<T>).status === "success";
}

function isErrorEnvelope(value: unknown): value is ErrorEnvelope {
  return !!value && typeof value === "object" && (value as ErrorEnvelope).status === "error";
}
