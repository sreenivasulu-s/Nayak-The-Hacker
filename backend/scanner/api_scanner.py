import httpx

from backend.scanner.base import ScannerBase


class ApiScanner(ScannerBase):
    """
    Passive API assessment for authorized targets.

    Checks for common OpenAPI/Swagger documentation endpoints,
    parses reachable OpenAPI JSON, checks JSON content type,
    CORS exposure, and standard security headers.
    """

    async def scan(self, target: str) -> list[dict]:
        target = self._normalize_target(target)
        findings: list[dict] = []

        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=5.0,
            ) as client:
                response = await client.get(target)

                findings.append(
                    {
                        "title": "API endpoint reachable",
                        "severity": "info",
                        "description": (
                            "The authorized API target responded to an HTTP GET request."
                        ),
                        "evidence": (
                            f"HTTP {response.status_code} from {response.url}"
                        ),
                        "tool": "httpx",
                    }
                )

                content_type = response.headers.get("content-type", "").lower()

                if "application/json" not in content_type:
                    findings.append(
                        {
                            "title": "API response is not JSON",
                            "severity": "low",
                            "description": (
                                "The target response does not advertise a JSON content type."
                            ),
                            "evidence": f"Content-Type: {content_type or 'missing'}",
                            "tool": "httpx",
                        }
                    )

                allow_origin = response.headers.get("access-control-allow-origin")

                if allow_origin == "*":
                    findings.append(
                        {
                            "title": "Wildcard CORS policy",
                            "severity": "low",
                            "description": (
                                "The API response allows requests from all origins."
                            ),
                            "evidence": "Access-Control-Allow-Origin: *",
                            "tool": "httpx",
                        }
                    )

                for header, title in {
                    "x-content-type-options": "Missing X-Content-Type-Options header",
                    "content-security-policy": "Missing Content-Security-Policy header",
                    "referrer-policy": "Missing Referrer-Policy header",
                }.items():
                    if header not in response.headers:
                        findings.append(
                            {
                                "title": title,
                                "severity": "low",
                                "description": (
                                    f"The API response does not include {header.title()}."
                                ),
                                "evidence": (
                                    f"HTTP {response.status_code} from {response.url}"
                                ),
                                "tool": "httpx",
                            }
                        )

                origin = f"{response.url.scheme}://{response.url.netloc}"

                for path, name in [
                    ("/openapi.json", "OpenAPI"),
                    ("/swagger.json", "Swagger"),
                    ("/docs", "Swagger UI"),
                ]:
                    try:
                        doc_response = await client.get(f"{origin}{path}")

                        if doc_response.status_code == 200:
                            findings.append(
                                {
                                    "title": f"{name} documentation endpoint detected",
                                    "severity": "info",
                                    "description": (
                                        f"The API exposes a reachable {name} documentation endpoint."
                                    ),
                                    "evidence": (
                                        f"HTTP 200 from {origin}{path}"
                                    ),
                                    "tool": "httpx",
                                }
                            )

                            if name == "OpenAPI":
                                findings.extend(
                                    self._inventory_openapi(doc_response)
                                )

                    except httpx.HTTPError:
                        continue

        except httpx.HTTPError as exc:
            findings.append(
                {
                    "title": "API request failed",
                    "severity": "info",
                    "description": (
                        "The authorized API target could not be reached."
                    ),
                    "evidence": str(exc),
                    "tool": "httpx",
                }
            )

        return findings

    @staticmethod
    def _normalize_target(target: str) -> str:
        import re

        value = target.strip().strip("`").strip()

        markdown_match = re.fullmatch(r"\[([^\]]+)\]\(([^)]+)\)", value)
        if markdown_match:
            value = markdown_match.group(2).strip()

        return value

    @staticmethod
    def _inventory_openapi(response: httpx.Response) -> list[dict]:
        try:
            document = response.json()
        except ValueError:
            return [
                {
                    "title": "OpenAPI document is not valid JSON",
                    "severity": "low",
                    "description": (
                        "The reachable OpenAPI endpoint did not return valid JSON."
                    ),
                    "evidence": "JSON parsing failed",
                    "tool": "openapi-static",
                }
            ]

        if "paths" not in document or not isinstance(document["paths"], dict):
            return [
                {
                    "title": "OpenAPI paths section missing",
                    "severity": "low",
                    "description": (
                        "The OpenAPI document does not contain a valid paths object."
                    ),
                    "evidence": "paths missing or invalid",
                    "tool": "openapi-static",
                }
            ]

        paths = document["paths"]

        if not isinstance(paths, dict):
            return [
                {
                    "title": "OpenAPI paths section missing",
                    "severity": "low",
                    "description": (
                        "The OpenAPI document does not contain a valid paths object."
                    ),
                    "evidence": "paths missing or invalid",
                    "tool": "openapi-static",
                }
            ]

        methods = {
            method.upper()
            for item in paths.values()
            if isinstance(item, dict)
            for method in item
            if method.lower()
            in {
                "get",
                "post",
                "put",
                "patch",
                "delete",
                "options",
                "head",
                "trace",
            }
        }

        endpoint_count = len(paths)

        return [
            {
                "title": "OpenAPI endpoint inventory generated",
                "severity": "info",
                "description": (
                    "The reachable OpenAPI document was parsed without invoking "
                    "individual API operations."
                ),
                "evidence": (
                    f"{endpoint_count} documented path(s); "
                    f"methods: {', '.join(sorted(methods)) or 'none'}"
                ),
                "tool": "openapi-static",
            }
        ]
