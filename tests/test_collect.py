import pytest

from aws_vpc_endpoint_audit.collect import (
    PayloadError,
    _cidr_blocks,
    _endpoint,
    _name_tag,
    _paginate,
    _route_table,
    _security_group,
    validate_payload,
)


class FakeClient:
    """Stands in for the ec2 client: paginated and unpaginated operations."""

    def __init__(self):
        self.calls = []

    def can_paginate(self, operation):
        return operation == "describe_subnets"

    def get_paginator(self, operation):
        self.calls.append(operation)

        class Paginator:
            def paginate(self, **kwargs):
                return [
                    {"Subnets": [{"SubnetId": "subnet-1"}]},
                    {"Subnets": [{"SubnetId": "subnet-2"}]},
                ]

        return Paginator()

    def describe_nat_gateways(self, **kwargs):
        self.calls.append(("describe_nat_gateways", kwargs))
        return {"NatGateways": [{"NatGatewayId": "nat-1"}]}


def test_paginate_walks_every_page():
    client = FakeClient()
    items = _paginate(client, "describe_subnets", "Subnets", Filters=[])
    assert [item["SubnetId"] for item in items] == ["subnet-1", "subnet-2"]


def test_paginate_falls_back_to_a_single_call():
    client = FakeClient()
    items = _paginate(client, "describe_nat_gateways", "NatGateways", Filters=[])
    assert items == [{"NatGatewayId": "nat-1"}]
    assert client.calls[0][1] == {}


def test_name_tag_and_cidr_blocks():
    assert _name_tag([{"Key": "Name", "Value": "prod"}]) == "prod"
    assert _name_tag(None) == ""
    vpc = {
        "CidrBlock": "10.0.0.0/16",
        "CidrBlockAssociationSet": [
            {"CidrBlock": "10.0.0.0/16", "CidrBlockState": {"State": "associated"}},
            {"CidrBlock": "10.1.0.0/16", "CidrBlockState": {"State": "disassociated"}},
        ],
    }
    assert _cidr_blocks(vpc) == ["10.0.0.0/16"]
    assert _cidr_blocks({"CidrBlock": "172.16.0.0/16"}) == ["172.16.0.0/16"]


def test_route_table_shape():
    table = _route_table(
        {
            "RouteTableId": "rtb-1",
            "Associations": [{"Main": True}, {"SubnetId": "subnet-1"}],
            "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1"}],
        }
    )
    assert table["main"] is True
    assert table["associated_subnets"] == ["subnet-1"]
    assert table["routes"][0]["nat_gateway_id"] == "nat-1"
    assert table["routes"][0]["gateway_id"] == ""


def test_endpoint_and_security_group_shape():
    endpoint = _endpoint(
        {
            "VpcEndpointId": "vpce-1",
            "ServiceName": "com.amazonaws.eu-central-1.ssm",
            "VpcEndpointType": "Interface",
            "State": "available",
            "SubnetIds": ["subnet-1"],
            "PrivateDnsEnabled": False,
            "Groups": [{"GroupId": "sg-1", "GroupName": "endpoints"}],
        }
    )
    assert endpoint["security_group_ids"] == ["sg-1"]
    assert endpoint["private_dns_enabled"] is False
    assert endpoint["route_table_ids"] == []

    group = _security_group(
        {
            "GroupId": "sg-1",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
                    "UserIdGroupPairs": [{"GroupId": "sg-app"}],
                    "PrefixListIds": [{"PrefixListId": "pl-1"}],
                }
            ],
        }
    )
    permission = group["ip_permissions"][0]
    assert permission["ipv4_ranges"] == ["10.0.0.0/16"]
    assert permission["source_group_ids"] == ["sg-app"]
    assert permission["prefix_list_ids"] == ["pl-1"]


@pytest.mark.parametrize(
    "payload,message",
    [
        ([], "must be a JSON object"),
        ({"vpcs": "all"}, "'vpcs' must be a list"),
        ({"vpcs": ["vpc-1"]}, "must be an object"),
        ({"vpcs": [{}]}, "missing 'vpc_id'"),
        ({"vpcs": [{"vpc_id": "vpc-1", "endpoints": {}}]}, "endpoints must be a list"),
        ({"region": 7, "vpcs": []}, "'region' must be a string"),
    ],
)
def test_validate_payload_rejects_bad_shapes(payload, message):
    with pytest.raises(PayloadError, match=message):
        validate_payload(payload)


def test_validate_payload_accepts_a_minimal_payload():
    payload = {"region": "eu-central-1", "vpcs": [{"vpc_id": "vpc-1"}]}
    assert validate_payload(payload) is payload
