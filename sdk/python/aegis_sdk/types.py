from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional, TypedDict


Scope = Literal[
    "secrets:read",
    "secrets:write",
    "secrets:admin",
    "projects:manage",
    "api_keys:manage",
    "audit:read",
]


class Project(TypedDict, total=False):
    id: str
    tenant_id: str
    name: str
    slug: str
    description: str
    environment: Literal["development", "staging", "production"]
    is_active: bool
    created_at: str
    updated_at: str


class CreateProjectInput(TypedDict, total=False):
    name: str
    slug: str
    description: str
    environment: Literal["development", "staging", "production"]


class UpdateProjectInput(TypedDict, total=False):
    name: str
    description: str
    is_active: bool


class Secret(TypedDict, total=False):
    id: str
    key: str
    value: str
    version: int
    expires_at: str
    tags: Dict[str, Any]
    created_by: str
    created_at: str


class PutSecretInput(TypedDict, total=False):
    key: str
    value: str
    expires_at: str
    tags: Dict[str, Any]


class SecretWriteResult(TypedDict, total=False):
    id: str
    key: str
    version: int
    created_at: str


class SecretKey(TypedDict, total=False):
    key: str
    latest_version: int
    created_at: str
    updated_at: str


class SecretVersion(TypedDict, total=False):
    id: str
    version: int
    is_active: bool
    created_by: str
    created_at: str


class APIKey(TypedDict, total=False):
    id: str
    tenant_id: str
    name: str
    key_prefix: str
    scopes: List[Scope]
    project_ids: List[str]
    is_active: bool
    last_used_at: str
    expires_at: str
    created_at: str


class CreateAPIKeyInput(TypedDict, total=False):
    name: str
    scopes: List[Scope]
    project_ids: List[str]
    expires_at: str


class CreateAPIKeyResult(TypedDict, total=False):
    key: APIKey
    plaintext_key: str
    warning: str


class AuditLog(TypedDict, total=False):
    id: str
    tenant_id: str
    actor: str
    action: str
    resource_type: str
    resource_id: str
    metadata: Dict[str, Any]
    ip_address: str
    created_at: str


class ListOptions(TypedDict, total=False):
    limit: int
    cursor: str


class AuditLogFilter(ListOptions, total=False):
    action: str
    resource_type: str
    start_time: str
    end_time: str
