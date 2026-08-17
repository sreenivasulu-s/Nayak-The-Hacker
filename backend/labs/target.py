from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


ACADEMY_HOST_SUFFIX = ".web-security-academy.net"
ACADEMY_DOC_HOST = "portswigger.net"


@dataclass(frozen=True, slots=True)
class LabTarget:
    url: str
    host: str
    lab_id: str
    category: str


def is_authorized_training_target(url: str) -> bool:
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    host = parsed.hostname.lower().rstrip(".")
    return host == ACADEMY_DOC_HOST or host.endswith(ACADEMY_HOST_SUFFIX)


def classify_path(path: str) -> str:
    value = path.lower()
    markers = {
        "sql": "sql-injection",
        "xss": "cross-site-scripting",
        "csrf": "csrf",
        "ssrf": "ssrf",
        "access-control": "access-control",
        "authentication": "authentication",
        "oauth": "oauth",
        "jwt": "jwt",
        "graphql": "graphql",
        "web-cache": "web-cache",
        "deserialization": "deserialization",
        "request-smuggling": "request-smuggling",
        "prototype-pollution": "prototype-pollution",
        "file-upload": "file-upload",
        "command-injection": "os-command-injection",
        "ssti": "ssti",
        "path-traversal": "path-traversal",
        "business-logic": "business-logic",
        "websockets": "websockets",
    }
    for marker, category in markers.items():
        if marker in value:
            return category
    return "unknown"


def normalize_lab_target(url: str) -> LabTarget:
    raw = url.strip()
    parsed = urlparse(raw)
    if not is_authorized_training_target(raw):
        raise ValueError(
            "Only PortSwigger Web Security Academy training targets are accepted."
        )
    host = parsed.hostname.lower()
    if host == ACADEMY_DOC_HOST:
        lab_id = parsed.path.rstrip("/").split("/")[-1] or "academy"
    else:
        lab_id = host.split(".", 1)[0]
    return LabTarget(
        url=raw,
        host=host,
        lab_id=lab_id,
        category=classify_path(parsed.path),
    )
