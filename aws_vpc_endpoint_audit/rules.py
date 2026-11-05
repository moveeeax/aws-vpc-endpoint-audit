"""The rules. Everything here is a pure function over the collected payload.

Each rule takes one VPC dict and yields :class:`~aws_vpc_endpoint_audit.model.Finding`
records, which keeps them trivially testable against the JSON fixtures in
``tests/fixtures/``.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Iterable, Iterator

from .model import (
    CRITICAL,
    DEFAULT_EXPECTED_INTERFACE_SERVICES,
    GATEWAY_SERVICES,
    OK,
    WARN,
    Finding,
    max_severity,
    service_name,
    short_service_name,
)

HTTPS_PORT = 443
NAT_LIVE_STATES = ("available", "pending")
ANY_IPV4 = "0.0.0.0/0"


def audit(payload: dict, expect: Iterable[str] | None = None) -> dict:
    """Run every rule over every VPC in ``payload`` and build the report."""
    region = payload.get("region", "")
    expected = tuple(expect) if expect is not None else DEFAULT_EXPECTED_INTERFACE_SERVICES

    vpc_reports = []
    for vpc in payload.get("vpcs", []):
        findings = list(vpc_findings(vpc, region=region, expect=expected))
        findings.sort(
            key=lambda finding: (-_rank(finding.severity), finding.rule, finding.resource)
        )
        vpc_reports.append(
            {
                "vpc_id": vpc.get("vpc_id", ""),
                "name": vpc.get("name", ""),
                "severity": max_severity(finding.severity for finding in findings),
                "nat_gateway_present": has_live_nat_gateway(vpc),
                "endpoint_count": len(vpc.get("endpoints", [])),
                "findings": [finding.to_dict() for finding in findings],
            }
        )

    all_findings = [finding for report in vpc_reports for finding in report["findings"]]
    return {
        "region": region,
        "summary": {
            "vpcs": len(vpc_reports),
            "findings": len(all_findings),
            "critical": sum(1 for f in all_findings if f["severity"] == CRITICAL),
            "warn": sum(1 for f in all_findings if f["severity"] == WARN),
            "severity": max_severity(report["severity"] for report in vpc_reports),
        },
        "vpcs": vpc_reports,
    }


def vpc_findings(vpc: dict, region: str, expect: Iterable[str]) -> Iterator[Finding]:
    yield from missing_gateway_endpoints(vpc, region)
    yield from missing_expected_interface_endpoints(vpc, region, expect)
    yield from gateway_route_coverage(vpc)
    yield from interface_endpoint_reachability(vpc)
    yield from interface_endpoint_private_dns(vpc)
    yield from interface_endpoint_az_spread(vpc)
    yield from endpoint_state(vpc)
    yield from endpoint_policy(vpc)


# --------------------------------------------------------------------------- #
# rules
# --------------------------------------------------------------------------- #


def missing_gateway_endpoints(vpc: dict, region: str) -> Iterator[Finding]:
    """A VPC paying for NAT with no S3 or DynamoDB gateway endpoint."""
    if not has_live_nat_gateway(vpc):
        return

    for short_name in GATEWAY_SERVICES:
        wanted = service_name(region, short_name)
        if any(
            endpoint.get("service_name") == wanted and endpoint.get("state") == "available"
            for endpoint in vpc.get("endpoints", [])
        ):
            continue
        yield Finding(
            rule="missing-gateway-endpoint",
            severity=CRITICAL,
            resource=vpc.get("vpc_id", ""),
            message=(
                f"no {short_name} endpoint while a NAT gateway is present, so every "
                f"{short_name} request from a private subnet is billed as NAT data processing"
            ),
            fix=(
                f"create a Gateway endpoint for {wanted} and associate it with the "
                "private route tables"
            ),
            details={"service_name": wanted, "endpoint_type": "Gateway"},
        )


def missing_expected_interface_endpoints(
    vpc: dict, region: str, expect: Iterable[str]
) -> Iterator[Finding]:
    """Interface endpoints the operator said this VPC should have."""
    present = {
        endpoint.get("service_name")
        for endpoint in vpc.get("endpoints", [])
        if endpoint.get("state") == "available"
    }
    for short_name in expect:
        short_name = short_name.strip()
        if not short_name:
            continue
        wanted = service_name(region, short_name)
        if wanted in present:
            continue
        yield Finding(
            rule="missing-expected-endpoint",
            severity=WARN,
            resource=vpc.get("vpc_id", ""),
            message=f"expected interface endpoint for {short_name} is absent",
            fix=f"create an Interface endpoint for {wanted} across the private subnets",
            details={"service_name": wanted, "endpoint_type": "Interface"},
        )


def gateway_route_coverage(vpc: dict) -> Iterator[Finding]:
    """Gateway endpoints wired to no route table, or to only some of them."""
    nat_routed = {table["route_table_id"]: table for table in nat_routed_route_tables(vpc)}

    for endpoint in gateway_endpoints(vpc):
        associated = set(endpoint.get("route_table_ids") or [])
        service = short_service_name(endpoint.get("service_name", ""))

        if not associated:
            yield Finding(
                rule="gateway-endpoint-unassociated",
                severity=CRITICAL,
                resource=endpoint.get("vpc_endpoint_id", ""),
                message=(
                    f"{service} gateway endpoint is associated with no route table, so it carries "
                    "no traffic and the VPC still egresses through NAT"
                ),
                fix=(
                    "associate the endpoint with every private route table that defaults "
                    "to the NAT gateway"
                ),
                details={"service_name": endpoint.get("service_name", "")},
            )
            continue

        missing = sorted(set(nat_routed) - associated)
        if missing:
            verb = "is" if len(missing) == 1 else "are"
            yield Finding(
                rule="gateway-endpoint-partial-route-coverage",
                severity=WARN,
                resource=endpoint.get("vpc_endpoint_id", ""),
                message=(
                    f"{service} gateway endpoint covers {len(associated & set(nat_routed))} of "
                    f"{len(nat_routed)} NAT-routed route tables; {', '.join(missing)} {verb} "
                    "still routed to the service through NAT"
                ),
                fix=f"add the endpoint association for {', '.join(missing)}",
                details={
                    "service_name": endpoint.get("service_name", ""),
                    "unassociated_route_tables": missing,
                },
            )


def interface_endpoint_reachability(vpc: dict) -> Iterator[Finding]:
    """Interface endpoints no caller inside the VPC can reach on 443."""
    vpc_networks = _networks(vpc.get("cidr_blocks") or [])
    groups = {group["group_id"]: group for group in vpc.get("security_groups", [])}

    for endpoint in interface_endpoints(vpc):
        group_ids = endpoint.get("security_group_ids") or []
        attached = [groups[group_id] for group_id in group_ids if group_id in groups]
        coverage = https_coverage(attached, vpc_networks)

        if coverage == "none":
            detail = "no security group is attached" if not group_ids else "no rule allows 443"
            yield Finding(
                rule="interface-endpoint-unreachable",
                severity=CRITICAL,
                resource=endpoint.get("vpc_endpoint_id", ""),
                message=(
                    f"{short_service_name(endpoint.get('service_name', ''))} interface endpoint is "
                    f"billed hourly but unreachable from the VPC CIDR on 443: {detail}"
                ),
                fix="allow TCP 443 from the VPC CIDR on a security group attached to the endpoint",
                details={
                    "security_group_ids": group_ids,
                    "vpc_cidr_blocks": vpc.get("cidr_blocks") or [],
                },
            )
        elif coverage == "partial":
            yield Finding(
                rule="interface-endpoint-partial-reachability",
                severity=WARN,
                resource=endpoint.get("vpc_endpoint_id", ""),
                message=(
                    f"{short_service_name(endpoint.get('service_name', ''))} interface endpoint "
                    "allows 443 from part of the VPC CIDR only, so some subnets fall back to the "
                    "public path"
                ),
                fix=(
                    "widen the 443 ingress rule to the whole VPC CIDR, or confirm the narrow "
                    "range is deliberate"
                ),
                details={
                    "security_group_ids": group_ids,
                    "vpc_cidr_blocks": vpc.get("cidr_blocks") or [],
                },
            )


def interface_endpoint_private_dns(vpc: dict) -> Iterator[Finding]:
    """Private DNS off means callers keep resolving the public name."""
    for endpoint in interface_endpoints(vpc):
        if endpoint.get("private_dns_enabled") is not False:
            continue
        yield Finding(
            rule="interface-endpoint-private-dns-disabled",
            severity=WARN,
            resource=endpoint.get("vpc_endpoint_id", ""),
            message=(
                f"{short_service_name(endpoint.get('service_name', ''))} interface endpoint has "
                "private DNS disabled, so unmodified SDK calls still resolve the public name"
            ),
            fix=(
                "enable PrivateDnsEnabled, or point callers at the endpoint-specific DNS name "
                "on purpose"
            ),
            details={"private_dns_enabled": False},
        )


def interface_endpoint_az_spread(vpc: dict) -> Iterator[Finding]:
    """One endpoint ENI in a VPC that spans several AZs is a single point of failure."""
    az_by_subnet = {
        subnet.get("subnet_id"): subnet.get("availability_zone", "")
        for subnet in vpc.get("subnets", [])
    }
    vpc_azs = {az for az in az_by_subnet.values() if az}
    if len(vpc_azs) < 2:
        return

    for endpoint in interface_endpoints(vpc):
        subnet_ids = endpoint.get("subnet_ids") or []
        endpoint_azs = {az_by_subnet.get(subnet_id, "") for subnet_id in subnet_ids}
        endpoint_azs.discard("")
        if len(endpoint_azs) >= 2:
            continue
        yield Finding(
            rule="interface-endpoint-single-az",
            severity=WARN,
            resource=endpoint.get("vpc_endpoint_id", ""),
            message=(
                f"{short_service_name(endpoint.get('service_name', ''))} interface endpoint lives "
                f"in {len(endpoint_azs) or 0} AZ while the VPC spans {len(vpc_azs)}"
            ),
            fix="add a subnet from each remaining availability zone to the endpoint",
            details={
                "endpoint_azs": sorted(endpoint_azs),
                "vpc_azs": sorted(vpc_azs),
            },
        )


def endpoint_state(vpc: dict) -> Iterator[Finding]:
    """An endpoint stuck in pending or failed is not carrying traffic."""
    for endpoint in vpc.get("endpoints", []):
        state = endpoint.get("state", "")
        if state == "available":
            continue
        yield Finding(
            rule="endpoint-not-available",
            severity=WARN,
            resource=endpoint.get("vpc_endpoint_id", ""),
            message=(
                f"{short_service_name(endpoint.get('service_name', ''))} endpoint is in state "
                f"{state or 'unknown'}, not available"
            ),
            fix="delete and recreate the endpoint, or finish the pending acceptance",
            details={"state": state},
        )


def endpoint_policy(vpc: dict) -> Iterator[Finding]:
    """A full-wildcard endpoint policy gives up the point of having one."""
    for endpoint in vpc.get("endpoints", []):
        document = endpoint.get("policy_document")
        if not document or not is_wildcard_policy(document):
            continue
        yield Finding(
            rule="endpoint-wildcard-policy",
            severity=WARN,
            resource=endpoint.get("vpc_endpoint_id", ""),
            message=(
                f"{short_service_name(endpoint.get('service_name', ''))} endpoint policy allows "
                "every action for every principal with no condition"
            ),
            fix="narrow the policy to the buckets, tables or API calls this path is meant to reach",
            details={"service_name": endpoint.get("service_name", "")},
        )


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def gateway_endpoints(vpc: dict) -> list[dict]:
    return [
        endpoint
        for endpoint in vpc.get("endpoints", [])
        if (endpoint.get("type") or "").lower() == "gateway"
    ]


def interface_endpoints(vpc: dict) -> list[dict]:
    return [
        endpoint
        for endpoint in vpc.get("endpoints", [])
        if (endpoint.get("type") or "").lower() == "interface"
    ]


def has_live_nat_gateway(vpc: dict) -> bool:
    return any(
        (nat.get("state") or "").lower() in NAT_LIVE_STATES for nat in vpc.get("nat_gateways", [])
    )


def is_private_route_table(table: dict) -> bool:
    """Private means no default route to an internet gateway."""
    for route in table.get("routes", []):
        gateway = route.get("gateway_id") or ""
        if gateway.startswith("igw-"):
            return False
    return True


def nat_routed_route_tables(vpc: dict) -> list[dict]:
    """Route tables actually in use whose default route goes through NAT."""
    tables = []
    for table in vpc.get("route_tables", []):
        if not table.get("associated_subnets") and not table.get("main"):
            continue
        if not is_private_route_table(table):
            continue
        if any(
            route.get("nat_gateway_id") and route.get("destination_cidr_block") == ANY_IPV4
            for route in table.get("routes", [])
        ):
            tables.append(table)
    return tables


def permission_allows_https(permission: dict) -> bool:
    protocol = str(permission.get("ip_protocol", "")).lower()
    if protocol in ("-1", "all"):
        return True
    if protocol not in ("tcp", "6"):
        return False
    from_port = permission.get("from_port")
    to_port = permission.get("to_port")
    if from_port is None or to_port is None:
        return True
    return int(from_port) <= HTTPS_PORT <= int(to_port)


def https_coverage(groups: Iterable[dict], vpc_networks: list) -> str:
    """How much of the VPC CIDR can reach 443: ``full``, ``partial`` or ``none``."""
    if not vpc_networks:
        vpc_networks = _networks([ANY_IPV4])

    remaining = list(vpc_networks)
    saw_overlap = False

    for group in groups:
        for permission in group.get("ip_permissions", []):
            if not permission_allows_https(permission):
                continue
            # A source security group or prefix list is reachability we cannot
            # disprove from the CIDR alone, so treat it as in-VPC access.
            if permission.get("source_group_ids") or permission.get("prefix_list_ids"):
                return "full"
            for network in _networks(permission.get("ipv4_ranges") or []):
                still_needed = []
                for wanted in remaining:
                    if wanted.version != network.version:
                        still_needed.append(wanted)
                        continue
                    if wanted.subnet_of(network):
                        saw_overlap = True
                        continue
                    if wanted.overlaps(network):
                        saw_overlap = True
                    still_needed.append(wanted)
                remaining = still_needed

    if not remaining:
        return "full"
    return "partial" if saw_overlap else "none"


def is_wildcard_policy(document) -> bool:
    """True when some Allow statement has a wildcard principal, action and no condition."""
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except (TypeError, json.JSONDecodeError):
            return False
    if not isinstance(document, dict):
        return False

    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return False

    for statement in statements:
        if not isinstance(statement, dict):
            continue
        if statement.get("Effect", "Allow") != "Allow":
            continue
        if statement.get("Condition"):
            continue
        if _is_wildcard(statement.get("Principal", "*")) and _is_wildcard(statement.get("Action")):
            return True
    return False


def _is_wildcard(value) -> bool:
    if value == "*":
        return True
    if isinstance(value, dict):
        return any(_is_wildcard(item) for item in value.values())
    if isinstance(value, list):
        return any(_is_wildcard(item) for item in value)
    return False


def _networks(cidrs: Iterable[str]) -> list:
    networks = []
    for cidr in cidrs:
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    return networks


def _rank(severity: str) -> int:
    return {OK: 0, WARN: 1, CRITICAL: 2}.get(severity, 0)
