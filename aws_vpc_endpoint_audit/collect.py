"""Turn the EC2 describe calls into the plain payload the rules run on.

``boto3`` is imported inside :func:`collect` on purpose: ``--from-json`` replays a
saved payload with no AWS calls, and the test suite exercises every rule against
fixtures, so neither path should need credentials or the SDK installed.
"""

from __future__ import annotations

import json
from typing import Any

PAYLOAD_VERSION = 1


class PayloadError(ValueError):
    """A ``--from-json`` file that is not a payload this version understands."""


def collect(region: str | None = None, vpc_ids: list[str] | None = None) -> dict:
    """Describe endpoints, route tables, subnets, NAT gateways and groups."""
    import boto3  # imported lazily; offline paths never touch the SDK

    ec2 = boto3.client("ec2", region_name=region)
    resolved_region = ec2.meta.region_name

    vpc_filters = [{"Name": "vpc-id", "Values": vpc_ids}] if vpc_ids else []
    vpcs = _paginate(ec2, "describe_vpcs", "Vpcs", Filters=vpc_filters)

    payload: dict[str, Any] = {
        "payload_version": PAYLOAD_VERSION,
        "region": resolved_region,
        "vpcs": [],
    }

    for vpc in vpcs:
        vpc_id = vpc["VpcId"]
        in_vpc = [{"Name": "vpc-id", "Values": [vpc_id]}]
        subnets = _paginate(ec2, "describe_subnets", "Subnets", Filters=in_vpc)
        route_tables = _paginate(ec2, "describe_route_tables", "RouteTables", Filters=in_vpc)
        endpoints = _paginate(ec2, "describe_vpc_endpoints", "VpcEndpoints", Filters=in_vpc)
        nat_gateways = _paginate(
            ec2,
            "describe_nat_gateways",
            "NatGateways",
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}],
        )
        groups = _paginate(ec2, "describe_security_groups", "SecurityGroups", Filters=in_vpc)

        payload["vpcs"].append(
            {
                "vpc_id": vpc_id,
                "name": _name_tag(vpc.get("Tags")),
                "cidr_blocks": _cidr_blocks(vpc),
                "subnets": [
                    {
                        "subnet_id": subnet["SubnetId"],
                        "availability_zone": subnet.get("AvailabilityZone", ""),
                        "cidr_block": subnet.get("CidrBlock", ""),
                    }
                    for subnet in subnets
                ],
                "route_tables": [_route_table(table) for table in route_tables],
                "nat_gateways": [
                    {
                        "nat_gateway_id": nat["NatGatewayId"],
                        "subnet_id": nat.get("SubnetId", ""),
                        "state": nat.get("State", ""),
                    }
                    for nat in nat_gateways
                ],
                "endpoints": [_endpoint(endpoint) for endpoint in endpoints],
                "security_groups": [_security_group(group) for group in groups],
            }
        )

    return payload


def load_payload(path: str) -> dict:
    """Read a saved payload, raising :class:`PayloadError` on anything unusable."""
    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except OSError as exc:
        raise PayloadError(f"cannot read {path}: {exc.strerror or exc}") from exc
    except json.JSONDecodeError as exc:
        raise PayloadError(f"{path} is not valid JSON: {exc.msg} at line {exc.lineno}") from exc

    return validate_payload(payload, source=path)


def validate_payload(payload: Any, source: str = "payload") -> dict:
    """Check the shape the rule engine depends on."""
    if not isinstance(payload, dict):
        raise PayloadError(f"{source} must be a JSON object, got {type(payload).__name__}")
    if not isinstance(payload.get("region", ""), str):
        raise PayloadError(f"{source}: 'region' must be a string")
    vpcs = payload.get("vpcs")
    if not isinstance(vpcs, list):
        raise PayloadError(f"{source}: 'vpcs' must be a list")
    for index, vpc in enumerate(vpcs):
        if not isinstance(vpc, dict):
            raise PayloadError(f"{source}: vpcs[{index}] must be an object")
        if not vpc.get("vpc_id"):
            raise PayloadError(f"{source}: vpcs[{index}] is missing 'vpc_id'")
        for key in ("endpoints", "route_tables", "subnets", "nat_gateways", "security_groups"):
            value = vpc.get(key, [])
            if not isinstance(value, list):
                raise PayloadError(f"{source}: vpcs[{index}].{key} must be a list")
    return payload


def _paginate(client, operation: str, key: str, **kwargs) -> list[dict]:
    if kwargs.get("Filters") == []:
        kwargs.pop("Filters")
    if client.can_paginate(operation):
        pages = client.get_paginator(operation).paginate(**kwargs)
        return [item for page in pages for item in page.get(key, [])]
    return list(getattr(client, operation)(**kwargs).get(key, []))


def _name_tag(tags) -> str:
    for tag in tags or []:
        if tag.get("Key") == "Name":
            return tag.get("Value", "")
    return ""


def _cidr_blocks(vpc: dict) -> list[str]:
    blocks = []
    for association in vpc.get("CidrBlockAssociationSet") or []:
        state = (association.get("CidrBlockState") or {}).get("State")
        if state in (None, "associated") and association.get("CidrBlock"):
            blocks.append(association["CidrBlock"])
    if not blocks and vpc.get("CidrBlock"):
        blocks.append(vpc["CidrBlock"])
    return blocks


def _route_table(table: dict) -> dict:
    associations = table.get("Associations") or []
    return {
        "route_table_id": table["RouteTableId"],
        "main": any(association.get("Main") for association in associations),
        "associated_subnets": [
            association["SubnetId"] for association in associations if association.get("SubnetId")
        ],
        "routes": [
            {
                "destination_cidr_block": route.get("DestinationCidrBlock", ""),
                "gateway_id": route.get("GatewayId", ""),
                "nat_gateway_id": route.get("NatGatewayId", ""),
                "transit_gateway_id": route.get("TransitGatewayId", ""),
            }
            for route in table.get("Routes") or []
        ],
    }


def _endpoint(endpoint: dict) -> dict:
    return {
        "vpc_endpoint_id": endpoint["VpcEndpointId"],
        "service_name": endpoint.get("ServiceName", ""),
        "type": endpoint.get("VpcEndpointType", ""),
        "state": endpoint.get("State", ""),
        "route_table_ids": list(endpoint.get("RouteTableIds") or []),
        "subnet_ids": list(endpoint.get("SubnetIds") or []),
        "private_dns_enabled": endpoint.get("PrivateDnsEnabled"),
        "security_group_ids": [
            group["GroupId"] for group in endpoint.get("Groups") or [] if group.get("GroupId")
        ],
        "policy_document": endpoint.get("PolicyDocument", ""),
    }


def _security_group(group: dict) -> dict:
    return {
        "group_id": group["GroupId"],
        "group_name": group.get("GroupName", ""),
        "ip_permissions": [
            {
                "ip_protocol": permission.get("IpProtocol", ""),
                "from_port": permission.get("FromPort"),
                "to_port": permission.get("ToPort"),
                "ipv4_ranges": [
                    item["CidrIp"]
                    for item in permission.get("IpRanges") or []
                    if item.get("CidrIp")
                ],
                "source_group_ids": [
                    item["GroupId"]
                    for item in permission.get("UserIdGroupPairs") or []
                    if item.get("GroupId")
                ],
                "prefix_list_ids": [
                    item["PrefixListId"]
                    for item in permission.get("PrefixListIds") or []
                    if item.get("PrefixListId")
                ],
            }
            for permission in group.get("IpPermissions") or []
        ],
    }
