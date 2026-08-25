from urllib.parse import urlparse

from .models import LabJob

ALLOWED_HOST_SUFFIXES = (".web-security-academy.net",)


def validate_lab_url(lab_url: str) -> str:
    parsed = urlparse(lab_url.strip())
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("PortSwigger lab URL must use HTTPS")
    host = parsed.hostname.lower().rstrip(".")
    if not host.endswith(ALLOWED_HOST_SUFFIXES):
        raise PermissionError("Only PortSwigger Web Security Academy lab hosts are allowed")
    return host


def build_lab_plan(job: LabJob) -> dict:
    """Create the first deterministic plan; workers will later execute each stage.

    The planner deliberately does not accept arbitrary hosts. This keeps the
    autonomous solver bounded to the training-lab environment.
    """
    host = validate_lab_url(job.lab_url)
    job.lab_host = host
    job.event("target_validated", host=host)
    job.hypothesis = [
        "Identify the lab scenario and application surface",
        "Capture normal browser traffic through the controlled proxy",
        "Classify candidate vulnerability from observable behavior",
        "Run bounded validation tests against the lab target",
        "Verify the PortSwigger success condition",
        "Collect reproducible evidence and generate a report",
    ]
    return {
        "scope": {"host": host, "scheme": "https"},
        "stages": ["discover", "plan", "test", "verify", "report"],
        "authorization": "PortSwigger Academy lab host only",
    }
