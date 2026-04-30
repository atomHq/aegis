from __future__ import annotations

import json
from typing import Any, Dict, List, Mapping, Optional
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from .types import (
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
)


class AegisAPIError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        status: int,
        details: Optional[Any] = None,
        request_id: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status = status
        self.details = details
        self.request_id = request_id


class AegisClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        auth_token: Optional[str] = None,
        base_url: str = "http://localhost:8080",
        timeout: float = 30.0,
        user_agent: str = "aegis-python/0.1.0",
    ) -> None:
        self.api_key = api_key
        self.auth_token = auth_token
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.user_agent = user_agent

    def create_project(self, data: CreateProjectInput) -> Project:
        return self._request("POST", "/api/v1/projects", body=data)

    def list_projects(self, options: Optional[ListOptions] = None) -> List[Project]:
        return self._request("GET", "/api/v1/projects", query=options)

    def get_project(self, project_id: str) -> Project:
        return self._request("GET", f"/api/v1/projects/{quote(project_id, safe='')}")

    def update_project(self, project_id: str, data: UpdateProjectInput) -> Project:
        return self._request(
            "PATCH",
            f"/api/v1/projects/{quote(project_id, safe='')}",
            body=data,
        )

    def delete_project(self, project_id: str) -> None:
        self._request("DELETE", f"/api/v1/projects/{quote(project_id, safe='')}")

    def put_secret(self, project_id: str, data: PutSecretInput) -> SecretWriteResult:
        return self._request(
            "PUT",
            f"/api/v1/projects/{quote(project_id, safe='')}/secrets",
            body=data,
        )

    def bulk_put_secrets(
        self, project_id: str, secrets: List[PutSecretInput]
    ) -> List[SecretWriteResult]:
        return self._request(
            "PUT",
            f"/api/v1/projects/{quote(project_id, safe='')}/secrets/bulk",
            body={"secrets": secrets},
        )

    def get_secret(self, project_id: str, key: str) -> Secret:
        return self._request(
            "GET",
            f"/api/v1/projects/{quote(project_id, safe='')}/secrets/{quote(key, safe='')}",
        )

    def bulk_get_secrets(self, project_id: str, keys: List[str]) -> Dict[str, str]:
        return self._request(
            "POST",
            f"/api/v1/projects/{quote(project_id, safe='')}/secrets/bulk",
            body={"keys": keys},
        )

    def list_secret_keys(
        self, project_id: str, options: Optional[ListOptions] = None
    ) -> List[SecretKey]:
        return self._request(
            "GET",
            f"/api/v1/projects/{quote(project_id, safe='')}/secrets",
            query=options,
        )

    def delete_secret(self, project_id: str, key: str) -> None:
        self._request(
            "DELETE",
            f"/api/v1/projects/{quote(project_id, safe='')}/secrets/{quote(key, safe='')}",
        )

    def list_secret_versions(self, project_id: str, key: str) -> List[SecretVersion]:
        return self._request(
            "GET",
            f"/api/v1/projects/{quote(project_id, safe='')}/secrets/{quote(key, safe='')}/versions",
        )

    def get_secret_version(self, project_id: str, key: str, version: int) -> Secret:
        return self._request(
            "GET",
            f"/api/v1/projects/{quote(project_id, safe='')}/secrets/{quote(key, safe='')}/versions/{version}",
        )

    def list_audit_logs(
        self, filters: Optional[AuditLogFilter] = None
    ) -> List[AuditLog]:
        return self._request("GET", "/api/v1/audit-logs", query=filters)

    def create_api_key(self, data: CreateAPIKeyInput) -> CreateAPIKeyResult:
        return self._request("POST", "/api/v1/api-keys", body=data, auth="jwt")

    def list_api_keys(self) -> List[APIKey]:
        return self._request("GET", "/api/v1/api-keys", auth="jwt")

    def revoke_api_key(self, key_id: str) -> None:
        self._request("DELETE", f"/api/v1/api-keys/{quote(key_id, safe='')}", auth="jwt")

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Optional[Any] = None,
        query: Optional[Mapping[str, Any]] = None,
        auth: str = "api_key",
    ) -> Any:
        token = self.auth_token if auth == "jwt" else self.api_key
        if not token:
            if auth == "jwt":
                raise ValueError("auth_token is required for API key management endpoints")
            raise ValueError("api_key is required for API-key authenticated endpoints")

        url = f"{self.base_url}{path}"
        encoded_query = _encode_query(query)
        if encoded_query:
            url = f"{url}?{encoded_query}"

        payload = None
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": self.user_agent,
        }
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        request = Request(url, data=payload, headers=headers, method=method)
        try:
            with urlopen(request, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8")
                status = response.status
        except HTTPError as err:
            raw = err.read().decode("utf-8")
            self._raise_api_error(raw, err.code)

        if not raw:
            return None

        parsed = json.loads(raw)
        if parsed.get("status") != "success":
            raise AegisAPIError("UNEXPECTED_RESPONSE", "Unexpected Aegis API response", status)
        return parsed.get("data")

    def _raise_api_error(self, raw: str, status: int) -> None:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            raise AegisAPIError("UNEXPECTED_RESPONSE", raw or "Unexpected Aegis API error", status)

        if parsed.get("status") == "error" and "error" in parsed:
            error = parsed["error"]
            meta = parsed.get("meta", {})
            raise AegisAPIError(
                error.get("code", "UNEXPECTED_RESPONSE"),
                error.get("message", "Unexpected Aegis API error"),
                status,
                error.get("details"),
                meta.get("request_id"),
            )

        raise AegisAPIError("UNEXPECTED_RESPONSE", raw, status)


def _encode_query(query: Optional[Mapping[str, Any]]) -> str:
    if not query:
        return ""
    clean = {
        key: value
        for key, value in query.items()
        if value is not None and value != ""
    }
    return urlencode(clean)
