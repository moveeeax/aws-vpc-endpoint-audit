import json

import pytest

from aws_vpc_endpoint_audit.report import render
from aws_vpc_endpoint_audit.rules import audit


def test_text_output_names_resource_and_fix(partial_routes):
    text = render(audit(partial_routes, expect=[]), "text")
    assert "region: eu-central-1" in text
    assert "vpce-ddbunassoc" in text
    assert "CRIT" in text and "WARN" in text
    assert "fix:" in text
    assert "1 vpc(s), 2 finding(s): 1 critical, 1 warn" in text


def test_text_output_says_ok_for_clean_vpc(clean):
    text = render(audit(clean, expect=["ssm"]), "text")
    assert "no endpoint gaps found" in text
    assert "CRIT" not in text


def test_json_output_round_trips(interface_problems):
    report = audit(interface_problems, expect=[])
    parsed = json.loads(render(report, "json"))
    assert parsed == report
    assert parsed["vpcs"][0]["findings"][0]["severity"] == "critical"


def test_markdown_output_has_a_table(partial_routes):
    markdown = render(audit(partial_routes, expect=[]), "markdown")
    assert markdown.startswith("# VPC endpoint audit")
    assert "| severity | resource | rule | finding | fix |" in markdown
    assert "`vpce-s3partial`" in markdown


def test_markdown_output_for_clean_vpc(clean):
    markdown = render(audit(clean, expect=["ssm"]), "markdown")
    assert "No endpoint gaps found." in markdown


def test_unknown_format_raises(clean):
    with pytest.raises(ValueError, match="unknown format"):
        render(audit(clean, expect=[]), "yaml")
