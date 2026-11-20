"""Trustrail Security Cloud Python 3 SDK (standard-library zero-dependency client)."""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional


class TrustrailApiError(Exception):
    def __init__(self, message: str, status: int, code: str = "API_ERROR", details: Any = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.details = details


class TrustrailClient:
    def __init__(self, base_url: str, token: Optional[str] = None, timeout_sec: float = 15.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout_sec = timeout_sec

    def set_token(self, token: str) -> None:
        self.token = token

    def _request(self, path: str, method: str = "GET", payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        headers: Dict[str, str] = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = urllib.request.Request(f"{self.base_url}{path}", data=data, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_sec) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            try:
                err_json = json.loads(raw)
            except Exception:
                err_json = {"error": raw or f"HTTP {exc.code}", "code": "API_ERROR"}
            raise TrustrailApiError(
                str(err_json.get("error", f"HTTP {exc.code}")),
                exc.code,
                str(err_json.get("code", "API_ERROR")),
                err_json.get("details"),
            ) from exc

    def health(self) -> Dict[str, Any]:
        return self._request("/api/health")

    def login(self, email: str, password: str, org_id: Optional[str] = None) -> Dict[str, Any]:
        body: Dict[str, Any] = {"email": email, "password": password}
        if org_id:
            body["orgId"] = org_id
        res = self._request("/api/v1/auth/login", method="POST", payload=body)
        if "token" in res:
            self.token = str(res["token"])
        return res

    def get_organization(self) -> Dict[str, Any]:
        return self._request("/api/v1/organizations")

    def run_scan(
        self,
        project_name: str,
        code_content: Optional[str] = None,
        package_json_content: Optional[str] = None,
        terraform_content: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"projectName": project_name}
        if code_content is not None:
            payload["codeContent"] = code_content
        if package_json_content is not None:
            payload["packageJsonContent"] = package_json_content
        if terraform_content is not None:
            payload["terraformContent"] = terraform_content
        return self._request("/api/v1/scans", method="POST", payload=payload)

    def list_findings(self, severity: Optional[str] = None, status: Optional[str] = None) -> Dict[str, Any]:
        params: Dict[str, str] = {}
        if severity:
            params["severity"] = severity
        if status:
            params["status"] = status
        qs = f"?{urllib.parse.urlencode(params)}" if params else ""
        return self._request(f"/api/v1/findings{qs}")

    def get_attack_paths(self) -> Dict[str, Any]:
        return self._request("/api/v1/attack-paths")

    def evaluate_policy(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("/api/v1/policies/evaluate", method="POST", payload=payload)

    def query_intel(self, cve_ids: Optional[List[str]] = None, force_refresh: bool = False) -> Dict[str, Any]:
        return self._request(
            "/api/v1/intel/query",
            method="POST",
            payload={"cveIds": cve_ids or [], "forceRefresh": force_refresh},
        )

    def ingest_runtime_event(
        self,
        source: str,
        severity: str,
        event_type: str,
        actor: str,
        resource: str,
        summary: str,
    ) -> Dict[str, Any]:
        return self._request(
            "/api/v1/events/ingest",
            method="POST",
            payload={
                "source": source,
                "severity": severity,
                "eventType": event_type,
                "actor": actor,
                "resource": resource,
                "summary": summary,
            },
        )

    def list_fabric_events(self, status: Optional[str] = None, limit: int = 50) -> Dict[str, Any]:
        params: Dict[str, str] = {"limit": str(limit)}
        if status:
            params["status"] = status
        return self._request(f"/api/v1/fabric/events?{urllib.parse.urlencode(params)}")
