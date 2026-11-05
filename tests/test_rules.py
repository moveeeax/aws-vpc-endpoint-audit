import copy

from aws_vpc_endpoint_audit.model import CRITICAL, OK, WARN
from aws_vpc_endpoint_audit.rules import (
    audit,
    https_coverage,
    is_wildcard_policy,
    nat_routed_route_tables,
)


def findings(report, rule=None, resource=None):
    out = [f for vpc in report["vpcs"] for f in vpc["findings"]]
    if rule:
        out = [f for f in out if f["rule"] == rule]
    if resource:
        out = [f for f in out if f["resource"] == resource]
    return out


def test_clean_vpc_has_no_findings(clean):
    report = audit(clean, expect=["ssm"])
    assert report["summary"]["findings"] == 0
    assert report["summary"]["severity"] == OK
    assert report["vpcs"][0]["severity"] == OK
    assert report["vpcs"][0]["nat_gateway_present"] is True


def test_missing_s3_gateway_endpoint_is_critical(nat_only):
    report = audit(nat_only, expect=[])
    s3 = findings(report, rule="missing-gateway-endpoint")
    services = {f["details"]["service_name"] for f in s3}
    assert services == {
        "com.amazonaws.eu-central-1.s3",
        "com.amazonaws.eu-central-1.dynamodb",
    }
    assert {f["severity"] for f in s3} == {CRITICAL}
    assert report["summary"]["severity"] == CRITICAL
    assert "com.amazonaws.eu-central-1.s3" in next(
        f["fix"] for f in s3 if f["details"]["service_name"].endswith(".s3")
    )


def test_missing_gateway_endpoint_is_silent_without_nat(interface_problems):
    report = audit(interface_problems, expect=[])
    assert findings(report, rule="missing-gateway-endpoint") == []


def test_present_s3_endpoint_clears_the_finding(clean):
    report = audit(clean, expect=[])
    assert findings(report, rule="missing-gateway-endpoint") == []


def test_pending_gateway_endpoint_does_not_count_as_present(clean):
    payload = copy.deepcopy(clean)
    payload["vpcs"][0]["endpoints"][0]["state"] = "pending"
    report = audit(payload, expect=[])
    missing = findings(report, rule="missing-gateway-endpoint")
    assert [f["details"]["service_name"] for f in missing] == ["com.amazonaws.eu-central-1.s3"]


def test_partial_route_coverage_is_warn(partial_routes):
    report = audit(partial_routes, expect=[])
    found = findings(report, rule="gateway-endpoint-partial-route-coverage")
    assert len(found) == 1
    assert found[0]["severity"] == WARN
    assert found[0]["resource"] == "vpce-s3partial"
    assert found[0]["details"]["unassociated_route_tables"] == ["rtb-s-c"]
    assert "rtb-s-c" in found[0]["fix"]


def test_unassociated_gateway_endpoint_is_critical(partial_routes):
    found = findings(audit(partial_routes, expect=[]), rule="gateway-endpoint-unassociated")
    assert len(found) == 1
    assert found[0]["resource"] == "vpce-ddbunassoc"
    assert found[0]["severity"] == CRITICAL


def test_nat_routed_route_tables_skips_public_and_unassociated(clean):
    tables = {t["route_table_id"] for t in nat_routed_route_tables(clean["vpcs"][0])}
    assert tables == {"rtb-priv-a", "rtb-priv-b"}


def test_interface_endpoint_without_443_is_critical(interface_problems):
    found = findings(audit(interface_problems, expect=[]), rule="interface-endpoint-unreachable")
    assert [f["resource"] for f in found] == ["vpce-ecrunreachable"]
    assert found[0]["severity"] == CRITICAL
    assert found[0]["details"]["vpc_cidr_blocks"] == ["10.40.0.0/16"]


def test_interface_endpoint_partial_cidr_is_warn(interface_problems):
    found = findings(
        audit(interface_problems, expect=[]), rule="interface-endpoint-partial-reachability"
    )
    assert [f["resource"] for f in found] == ["vpce-partialcidr"]
    assert found[0]["severity"] == WARN


def test_private_dns_disabled_is_warn(interface_problems):
    found = findings(
        audit(interface_problems, expect=[]), rule="interface-endpoint-private-dns-disabled"
    )
    assert [f["resource"] for f in found] == ["vpce-nodns"]
    assert found[0]["severity"] == WARN


def test_single_az_interface_endpoint_is_warn(interface_problems):
    found = findings(audit(interface_problems, expect=[]), rule="interface-endpoint-single-az")
    assert [f["resource"] for f in found] == ["vpce-nodns"]
    assert found[0]["details"]["vpc_azs"] == [
        "eu-central-1a",
        "eu-central-1b",
        "eu-central-1c",
    ]


def test_single_az_rule_is_quiet_in_single_az_vpc(interface_problems):
    payload = copy.deepcopy(interface_problems)
    payload["vpcs"][0]["subnets"] = [payload["vpcs"][0]["subnets"][0]]
    assert findings(audit(payload, expect=[]), rule="interface-endpoint-single-az") == []


def test_endpoint_not_available_is_warn(interface_problems):
    found = findings(audit(interface_problems, expect=[]), rule="endpoint-not-available")
    assert [f["resource"] for f in found] == ["vpce-partialcidr"]
    assert found[0]["details"]["state"] == "pending"


def test_wildcard_policy_is_warn(interface_problems):
    found = findings(audit(interface_problems, expect=[]), rule="endpoint-wildcard-policy")
    assert [f["resource"] for f in found] == ["vpce-nodns"]
    assert found[0]["severity"] == WARN


def test_scoped_policy_is_not_flagged(clean):
    assert findings(audit(clean, expect=[]), rule="endpoint-wildcard-policy") == []


def test_expect_list_reports_missing_interface_endpoints(clean):
    found = findings(audit(clean, expect=["ssm", "ecr.api"]), rule="missing-expected-endpoint")
    assert [f["details"]["service_name"] for f in found] == ["com.amazonaws.eu-central-1.ecr.api"]
    assert found[0]["severity"] == WARN


def test_findings_are_sorted_critical_first(partial_routes):
    severities = [f["severity"] for f in audit(partial_routes, expect=[])["vpcs"][0]["findings"]]
    assert severities == sorted(severities, key=lambda s: 0 if s == CRITICAL else 1)


def test_summary_counts(interface_problems):
    summary = audit(interface_problems, expect=[])["summary"]
    assert summary["vpcs"] == 1
    assert summary["critical"] == 1
    assert summary["findings"] == summary["critical"] + summary["warn"]
    assert summary["severity"] == CRITICAL


def test_https_coverage_source_group_counts_as_reachable():
    groups = [
        {
            "ip_permissions": [
                {
                    "ip_protocol": "tcp",
                    "from_port": 443,
                    "to_port": 443,
                    "ipv4_ranges": [],
                    "source_group_ids": ["sg-app"],
                    "prefix_list_ids": [],
                }
            ]
        }
    ]
    import ipaddress

    assert https_coverage(groups, [ipaddress.ip_network("10.0.0.0/16")]) == "full"


def test_https_coverage_all_protocols_and_empty_groups():
    import ipaddress

    vpc = [ipaddress.ip_network("10.0.0.0/16")]
    all_traffic = [
        {
            "ip_permissions": [
                {
                    "ip_protocol": "-1",
                    "from_port": None,
                    "to_port": None,
                    "ipv4_ranges": ["0.0.0.0/0"],
                    "source_group_ids": [],
                    "prefix_list_ids": [],
                }
            ]
        }
    ]
    assert https_coverage(all_traffic, vpc) == "full"
    assert https_coverage([], vpc) == "none"


def test_is_wildcard_policy_variants():
    assert is_wildcard_policy('{"Statement":[{"Principal":{"AWS":"*"},"Action":["*"]}]}')
    assert is_wildcard_policy({"Statement": {"Principal": "*", "Action": "*"}})
    assert not is_wildcard_policy('{"Statement":[{"Principal":"*","Action":"s3:GetObject"}]}')
    assert not is_wildcard_policy(
        '{"Statement":[{"Principal":"*","Action":"*","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-1"}}}]}'
    )
    assert not is_wildcard_policy("not json at all")
    assert not is_wildcard_policy("")
