import json

import pytest

from aws_vpc_endpoint_audit.cli import main


def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_clean_payload_exits_zero(capsys, fixtures_dir):
    code, out, _ = run(
        capsys, "--from-json", str(fixtures_dir / "clean.json"), "--expect", "ssm"
    )
    assert code == 0
    assert "no endpoint gaps found" in out


def test_critical_findings_exit_one(capsys, fixtures_dir):
    code, out, _ = run(
        capsys,
        "--from-json",
        str(fixtures_dir / "nat_no_gateway_endpoints.json"),
        "--fail-on",
        "critical",
    )
    assert code == 1
    assert "missing-gateway-endpoint" in out


def test_warnings_only_respect_the_threshold(capsys, fixtures_dir):
    payload = str(fixtures_dir / "clean.json")
    critical_code, _, _ = run(capsys, "--from-json", payload, "--fail-on", "critical")
    warn_code, out, _ = run(capsys, "--from-json", payload, "--fail-on", "warn")
    assert critical_code == 0
    assert warn_code == 1
    assert "missing-expected-endpoint" in out


def test_fail_on_none_always_exits_zero(capsys, fixtures_dir):
    code, _, _ = run(
        capsys,
        "--from-json",
        str(fixtures_dir / "nat_no_gateway_endpoints.json"),
        "--fail-on",
        "none",
    )
    assert code == 0


def test_json_format_is_machine_readable(capsys, fixtures_dir):
    code, out, _ = run(
        capsys,
        "--from-json",
        str(fixtures_dir / "interface_problems.json"),
        "--format",
        "json",
        "--expect",
        "",
    )
    report = json.loads(out)
    assert code == 1
    assert report["region"] == "eu-central-1"
    assert report["summary"]["critical"] == 1


def test_markdown_format(capsys, fixtures_dir):
    code, out, _ = run(
        capsys,
        "--from-json",
        str(fixtures_dir / "partial_route_coverage.json"),
        "--format",
        "markdown",
    )
    assert code == 1
    assert out.startswith("# VPC endpoint audit")


def test_malformed_payload_exits_two_without_traceback(capsys, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    code, out, err = run(capsys, "--from-json", str(bad))
    assert code == 2
    assert out == ""
    assert "is not valid JSON" in err
    assert "Traceback" not in err


def test_payload_with_wrong_shape_exits_two(capsys, tmp_path):
    bad = tmp_path / "shape.json"
    bad.write_text(json.dumps({"region": "eu-central-1", "vpcs": {}}), encoding="utf-8")
    code, _, err = run(capsys, "--from-json", str(bad))
    assert code == 2
    assert "'vpcs' must be a list" in err


def test_missing_payload_file_exits_two(capsys, tmp_path):
    code, _, err = run(capsys, "--from-json", str(tmp_path / "nope.json"))
    assert code == 2
    assert "cannot read" in err


def test_dump_payload_writes_the_input_back(capsys, fixtures_dir, tmp_path):
    out_path = tmp_path / "dump.json"
    code, _, _ = run(
        capsys,
        "--from-json",
        str(fixtures_dir / "clean.json"),
        "--dump-payload",
        str(out_path),
        "--expect",
        "ssm",
    )
    assert code == 0
    assert json.loads(out_path.read_text(encoding="utf-8"))["vpcs"][0]["vpc_id"].startswith("vpc-")


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert "aws-vpc-endpoint-audit" in capsys.readouterr().out


def test_live_collection_without_boto3_is_an_error(capsys, monkeypatch):
    import aws_vpc_endpoint_audit.cli as cli_module

    def no_boto3(*_args, **_kwargs):
        raise ImportError("No module named 'boto3'")

    monkeypatch.setattr(cli_module, "collect", no_boto3)
    code, _, err = run(capsys, "--region", "eu-central-1")
    assert code == 2
    assert "boto3 is required" in err
