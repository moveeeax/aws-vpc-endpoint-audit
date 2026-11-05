"""Shared vocabulary: severities, finding records and the service-name helpers.

The collector produces plain dicts and the rule engine consumes them, so this
module holds the only types both sides need to agree on.
"""

from __future__ import annotations

from dataclasses import dataclass, field

OK = "ok"
WARN = "warn"
CRITICAL = "critical"

SEVERITY_ORDER = {OK: 0, WARN: 1, CRITICAL: 2}

GATEWAY_SERVICES = ("s3", "dynamodb")

DEFAULT_EXPECTED_INTERFACE_SERVICES = (
    "ecr.api",
    "ecr.dkr",
    "ssm",
    "ssmmessages",
    "ec2messages",
    "logs",
)


def service_name(region: str, short_name: str) -> str:
    """Build the full endpoint service name AWS expects.

    >>> service_name("eu-central-1", "s3")
    'com.amazonaws.eu-central-1.s3'
    """
    if short_name.startswith("com.amazonaws."):
        return short_name
    return f"com.amazonaws.{region}.{short_name}"


def short_service_name(full_name: str) -> str:
    """Strip the ``com.amazonaws.<region>.`` prefix off a service name."""
    parts = full_name.split(".")
    if len(parts) >= 4 and parts[0] == "com" and parts[1] == "amazonaws":
        return ".".join(parts[3:])
    return full_name


def max_severity(severities) -> str:
    """Return the worst severity in ``severities``, or ``ok`` when empty."""
    worst = OK
    for severity in severities:
        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER[worst]:
            worst = severity
    return worst


@dataclass(frozen=True)
class Finding:
    """One thing that is wrong (or absent) in one VPC."""

    rule: str
    severity: str
    resource: str
    message: str
    fix: str
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        payload = {
            "rule": self.rule,
            "severity": self.severity,
            "resource": self.resource,
            "message": self.message,
            "fix": self.fix,
        }
        if self.details:
            payload["details"] = self.details
        return payload
