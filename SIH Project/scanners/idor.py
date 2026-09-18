"""Opt-in, non-destructive insecure direct object reference checks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

from core.base import Scanner
from core.models import Finding
from scanners.dast import DastScanner


_UUID_RE = re.compile(
    r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\b"
)
_ID_KEY_RE = re.compile(r"(?i)(?:^|[_-])(?:id|ids|uuid|key)$|(?:^|[_-])id$")
_NUMBER_RE = re.compile(r"\b[1-9][0-9]{0,11}\b")


@dataclass(frozen=True)
class ObjectReference:
    value: str
    key: str
    location: str


class IdorScanner(Scanner):
    """Compare same-role accounts after substituting each other's object IDs."""

    name = "idor"

    def scan(self) -> List[Finding]:
        settings = self.config.get("idor", {})
        if not isinstance(settings, dict) or not self.active_scope(settings, self.name):
            return self.findings

        endpoints = self._endpoint_specs(settings)
        accounts = self._accounts(settings)
        if not endpoints or len(accounts) < 2:
            return self.findings

        try:
            discovered = self._discovered_paths()
        except requests.RequestException:
            return self.findings
        endpoints = [
            item
            for item in endpoints
            if item["path"] in discovered or self._template_matches(item["path"], discovered)
        ]
        if not endpoints:
            return self.findings

        sessions = self._sessions(accounts, settings.get("login", {}))
        baselines: Dict[Tuple[str, str], Tuple[requests.Response, List[ObjectReference]]] = {}
        account_references: Dict[str, List[ObjectReference]] = {}
        for account in accounts:
            session = sessions.get(account["name"])
            if session is None:
                continue
            for endpoint in endpoints:
                if "{" in endpoint["path"]:
                    continue
                try:
                    response = self.request(
                        endpoint["method"], endpoint["path"], session=session
                    )
                except (requests.RequestException, ValueError):
                    continue
                references = self._extract_references(response)
                baselines[(account["name"], endpoint["path"])] = (response, references)
                account_references[account["name"]] = self._unique_references(
                    [*account_references.get(account["name"], []), *references]
                )

        for account in accounts:
            session = sessions.get(account["name"])
            for endpoint in endpoints:
                if session is None or "{" not in endpoint["path"]:
                    continue
                own_reference = self._reference_for_template(
                    endpoint["path"], account_references.get(account["name"], [])
                )
                if own_reference is None:
                    continue
                replay = self._substitute(endpoint, own_reference)
                if replay is None:
                    continue
                try:
                    response = self.request(
                        endpoint["method"],
                        replay["path"],
                        session=session,
                        json=replay.get("json"),
                    )
                except (requests.RequestException, ValueError):
                    continue
                references = self._extract_references(response)
                baselines[(account["name"], endpoint["path"])] = (response, references)
                account_references[account["name"]] = self._unique_references(
                    [*account_references.get(account["name"], []), *references]
                )

        for source, target in self._same_role_pairs(accounts):
            target_session = sessions.get(target["name"])
            if target_session is None:
                continue
            for endpoint in endpoints:
                source_data = baselines.get((source["name"], endpoint["path"]))
                target_data = baselines.get((target["name"], endpoint["path"]))
                if source_data is None or target_data is None:
                    continue
                target_response, target_refs = target_data
                source_refs = self._unique_references(
                    [*account_references.get(source["name"], []), *source_data[1]]
                )
                target_owned_values = {
                    item.value
                    for item in [
                        *account_references.get(target["name"], []),
                        *target_refs,
                    ]
                }
                for reference in source_refs:
                    if reference.value in target_owned_values:
                        continue
                    replay = self._substitute(endpoint, reference)
                    if replay is None:
                        continue
                    try:
                        response = self.request(
                            endpoint["method"],
                            replay["path"],
                            session=target_session,
                            json=replay.get("json"),
                        )
                    except (requests.RequestException, ValueError):
                        continue
                    if self._looks_accessible(response, settings):
                        self._add_idor_finding(
                            source,
                            target,
                            endpoint,
                            reference,
                            target_response,
                            response,
                            settings,
                        )
        return self.findings

    def _discovered_paths(self) -> set[str]:
        discovery = DastScanner(self.target_url, self.config)
        root = discovery.request("GET", "/")
        return set(discovery.discover_endpoints(root))

    @staticmethod
    def _endpoint_specs(settings: Dict[str, Any]) -> List[Dict[str, Any]]:
        configured = settings.get("endpoints", [])
        if not isinstance(configured, list):
            return []
        result: List[Dict[str, Any]] = []
        for item in configured:
            if not isinstance(item, dict):
                continue
            path = item.get("path")
            method = str(item.get("method", "GET")).upper()
            if (
                isinstance(path, str)
                and path.startswith("/")
                and method == "GET"
                and not urlsplit(path).netloc
            ):
                result.append({"path": path, "method": method, "json": item.get("json")})
        return result

    @staticmethod
    def _accounts(settings: Dict[str, Any]) -> List[Dict[str, str]]:
        raw = settings.get("accounts", [])
        if not isinstance(raw, list):
            return []
        accounts: List[Dict[str, str]] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            values = {key: item.get(key) for key in ("name", "role", "username", "password")}
            if all(isinstance(value, str) and value for value in values.values()):
                accounts.append(values)
        return accounts

    @staticmethod
    def _same_role_pairs(
        accounts: Iterable[Dict[str, str]],
    ) -> Iterable[Tuple[Dict[str, str], Dict[str, str]]]:
        grouped: Dict[str, List[Dict[str, str]]] = {}
        for account in accounts:
            grouped.setdefault(account["role"], []).append(account)
        for same_role in grouped.values():
            for index, source in enumerate(same_role):
                for target in same_role[index + 1 :]:
                    yield source, target
                    yield target, source

    def _sessions(
        self, accounts: Iterable[Dict[str, str]], login: Any
    ) -> Dict[str, requests.Session]:
        if not isinstance(login, dict) or not str(login.get("path", "")).startswith("/"):
            return {}
        sessions: Dict[str, requests.Session] = {}
        for account in accounts:
            session = requests.Session()
            session.headers["User-Agent"] = "WorldMonitor-Security-Assessment/0.1"
            payload = {
                str(login.get("username_field", "username")): account["username"],
                str(login.get("password_field", "password")): account["password"],
            }
            try:
                response = self.request(
                    str(login.get("method", "POST")).upper(),
                    str(login["path"]),
                    session=session,
                    json=payload if login.get("format") == "json" else None,
                    data=None if login.get("format") == "json" else payload,
                )
            except (requests.RequestException, ValueError):
                continue
            statuses = login.get("success_statuses", [200, 201, 204, 302])
            if not isinstance(statuses, list):
                statuses = [200, 201, 204, 302]
            if response.status_code in statuses:
                sessions[account["name"]] = session
        return sessions

    @staticmethod
    def _extract_references(response: requests.Response) -> List[ObjectReference]:
        references: List[ObjectReference] = []
        try:
            payload = response.json()
        except ValueError:
            payload = None
        if payload is not None:
            references.extend(IdorScanner._walk_json(payload, "$"))
        references.extend(IdorScanner._extract_url_references(response.text))
        return IdorScanner._unique_references(references)

    @staticmethod
    def _walk_json(value: Any, location: str) -> List[ObjectReference]:
        found: List[ObjectReference] = []
        if isinstance(value, dict):
            for key, child in value.items():
                child_location = f"{location}.{key}"
                if isinstance(child, (str, int)) and (
                    IdorScanner._is_id_key(str(key))
                    or _UUID_RE.fullmatch(str(child))
                ):
                    found.extend(
                        IdorScanner._typed_reference(str(child), str(key), child_location)
                    )
                found.extend(IdorScanner._walk_json(child, child_location))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                found.extend(IdorScanner._walk_json(child, f"{location}[{index}]"))
        elif isinstance(value, str):
            found.extend(IdorScanner._extract_url_references(value, location))
        return found

    @staticmethod
    def _extract_url_references(
        text: str, location: str = "response.body"
    ) -> List[ObjectReference]:
        found: List[ObjectReference] = []
        for match in _UUID_RE.finditer(text):
            found.append(ObjectReference(match.group(), "id", f"{location}[uuid]"))
        for match in re.finditer(r"(?P<key>[A-Za-z][\w-]*(?:id|uuid))=(?P<value>[^&#\s]+)", text):
            found.extend(
                IdorScanner._typed_reference(
                    match.group("value"), match.group("key"), f"{location}.query.{match.group('key')}"
                )
            )
        for index, segment in enumerate(urlsplit(text).path.split("/")):
            if _UUID_RE.fullmatch(segment) or _NUMBER_RE.fullmatch(segment):
                found.append(ObjectReference(segment, "id", f"{location}.path[{index}]"))
        for match in re.finditer(r"""(?P<url>(?:https?://|/)[^"'<>\\s]+)""", text):
            parsed_url = urlsplit(match.group("url"))
            for index, segment in enumerate(parsed_url.path.split("/")):
                if _UUID_RE.fullmatch(segment) or _NUMBER_RE.fullmatch(segment):
                    found.append(
                        ObjectReference(
                            segment,
                            "id",
                            f"{location}.url.path[{index}]",
                        )
                    )
        return found

    @staticmethod
    def _template_matches(template: str, discovered: Iterable[str]) -> bool:
        pattern = re.escape(template)
        pattern = re.sub(r"\\\{[A-Za-z_][A-Za-z0-9_-]*\\\}", r"[^/?#]+", pattern)
        return any(re.fullmatch(pattern, path) for path in discovered)

    @staticmethod
    def _typed_reference(value: str, key: str, location: str) -> List[ObjectReference]:
        if _UUID_RE.fullmatch(value) or (_ID_KEY_RE.search(key) and _NUMBER_RE.fullmatch(value)):
            return [ObjectReference(value, key, location)]
        return []

    @staticmethod
    def _is_id_key(key: str) -> bool:
        return bool(_ID_KEY_RE.search(key)) or key.lower().endswith(("id", "uuid"))

    @staticmethod
    def _unique_references(
        references: Iterable[ObjectReference],
    ) -> List[ObjectReference]:
        seen: set[Tuple[str, str]] = set()
        unique: List[ObjectReference] = []
        for reference in references:
            key = (reference.value, reference.key.lower())
            if key not in seen:
                seen.add(key)
                unique.append(reference)
        return unique

    @staticmethod
    def _substitute(
        endpoint: Dict[str, Any], reference: ObjectReference
    ) -> Dict[str, Any] | None:
        path = endpoint["path"]
        json_body = endpoint.get("json")
        key_names = {reference.key, reference.key.lower(), "id"}
        changed = False
        for key in key_names:
            placeholder = "{" + key + "}"
            if placeholder in path:
                path = path.replace(placeholder, reference.value)
                changed = True
        parsed = urlsplit(path)
        query = parse_qsl(parsed.query, keep_blank_values=True)
        updated_query = []
        for key, value in query:
            if key.lower() in {name.lower() for name in key_names}:
                value = reference.value
                changed = True
            updated_query.append((key, value))
        if changed or updated_query != query:
            path = urlunsplit(
                ("", "", parsed.path, urlencode(updated_query), parsed.fragment)
            )
        if isinstance(json_body, dict):
            json_body = json.loads(json.dumps(json_body))
            changed = IdorScanner._replace_json_ids(json_body, reference, key_names) or changed
        if not changed:
            return None
        return {"path": path, "json": json_body}

    @staticmethod
    def _reference_for_template(
        template: str, references: Iterable[ObjectReference]
    ) -> ObjectReference | None:
        keys = set(re.findall(r"\{([A-Za-z_][A-Za-z0-9_-]*)\}", template))
        for reference in references:
            normalized_keys = {key.lower() for key in keys}
            if (
                not keys
                or reference.key.lower() in normalized_keys
                or ("id" in normalized_keys and IdorScanner._is_id_key(reference.key))
            ):
                return reference
        return None

    @staticmethod
    def _replace_json_ids(value: Any, reference: ObjectReference, key_names: set[str]) -> bool:
        changed = False
        if isinstance(value, dict):
            for key, child in value.items():
                if key.lower() in {name.lower() for name in key_names}:
                    value[key] = reference.value
                    changed = True
                else:
                    changed = IdorScanner._replace_json_ids(child, reference, key_names) or changed
        elif isinstance(value, list):
            for child in value:
                changed = IdorScanner._replace_json_ids(child, reference, key_names) or changed
        return changed

    @staticmethod
    def _looks_accessible(response: requests.Response, settings: Dict[str, Any]) -> bool:
        if 200 <= response.status_code < 300:
            return True
        markers = settings.get("sensitive_markers", [])
        return isinstance(markers, list) and any(
            isinstance(marker, str) and marker.lower() in response.text.lower()
            for marker in markers
        )

    def _add_idor_finding(
        self,
        source: Dict[str, str],
        target: Dict[str, str],
        endpoint: Dict[str, Any],
        reference: ObjectReference,
        baseline: requests.Response,
        response: requests.Response,
        settings: Dict[str, Any],
    ) -> None:
        evidence = json.dumps(
            {
                "endpoint": endpoint["path"],
                "identifier": {
                    "location": reference.location,
                    "value": "[REDACTED]",
                    "source_account": source["name"],
                },
                "requesting_account": target["name"],
                "role": target["role"],
                "baseline_status": baseline.status_code,
                "cross_object_status": response.status_code,
                "response_excerpt": self._redact(response.text[: int(settings.get("max_evidence_bytes", 500))]),
            },
            sort_keys=True,
        )
        self.add_finding(
            f"IDOR-{len(self.findings) + 1:03d}",
            "IDOR",
            "High",
            f"Account {target['name']} accessed an object identifier owned by {source['name']} at {endpoint['path']}.",
            evidence,
            "Enforce object-level authorization on every read and verify ownership before returning the resource.",
            "A01:2021 Broken Access Control",
            cvss=8.1,
            confidence="high",
        )

    @staticmethod
    def _redact(value: str) -> str:
        value = re.sub(
            r"(?i)(authorization|cookie|password|token|secret|api[-_]?key)\s*[:=]\s*[^,\s}]+",
            r"\1=[REDACTED]",
            value,
        )
        return re.sub(r"(?i)bearer\s+[A-Za-z0-9._~-]+", "Bearer [REDACTED]", value)
