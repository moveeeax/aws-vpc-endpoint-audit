"""Command line entry point.

Exit codes: 0 clean (or ``--fail-on none``), 1 findings at or above the
threshold, 2 bad input or an AWS call that did not come back.
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .collect import PayloadError, collect, load_payload, validate_payload
from .model import CRITICAL, DEFAULT_EXPECTED_INTERFACE_SERVICES, SEVERITY_ORDER, WARN
from .report import render
from .rules import audit

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-vpc-endpoint-audit",
        description=(
            "Audit VPC endpoints against the traffic a NAT gateway is billing for: "
            "missing S3 and DynamoDB gateway endpoints, partial route-table coverage, "
            "unreachable or private-DNS-disabled interface endpoints, single-AZ placement "
            "and wildcard endpoint policies."
        ),
    )
    parser.add_argument("--region", help="AWS region (defaults to the usual boto3 resolution)")
    parser.add_argument(
        "--vpc-id",
        action="append",
        default=None,
        metavar="VPC_ID",
        help="limit the audit to this VPC; repeatable",
    )
    parser.add_argument(
        "--expect",
        default=",".join(DEFAULT_EXPECTED_INTERFACE_SERVICES),
        help=(
            "comma-separated interface endpoint short names a private VPC should have "
            "(default: %(default)s); pass an empty string to skip the check"
        ),
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
        help="output format (default: %(default)s)",
    )
    parser.add_argument(
        "--fail-on",
        choices=("warn", "critical", "none"),
        default="critical",
        help="severity that makes the exit code 1 (default: %(default)s)",
    )
    parser.add_argument(
        "--from-json",
        metavar="PATH",
        help="replay a saved payload instead of calling AWS",
    )
    parser.add_argument(
        "--dump-payload",
        metavar="PATH",
        help="write the collected payload to PATH for later --from-json runs",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def exit_code_for(report: dict, fail_on: str) -> int:
    if fail_on == "none":
        return EXIT_OK
    threshold = SEVERITY_ORDER[CRITICAL if fail_on == CRITICAL else WARN]
    worst = SEVERITY_ORDER.get(report.get("summary", {}).get("severity", "ok"), 0)
    return EXIT_FINDINGS if worst >= threshold else EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    expect = [item for item in args.expect.split(",") if item.strip()]

    try:
        if args.from_json:
            payload = load_payload(args.from_json)
        else:
            payload = validate_payload(collect(region=args.region, vpc_ids=args.vpc_id))
    except PayloadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except ImportError:
        print(
            "error: boto3 is required for live collection; install it or use --from-json",
            file=sys.stderr,
        )
        return EXIT_ERROR
    except Exception as exc:  # pragma: no cover - depends on live AWS
        print(f"error: AWS call failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.dump_payload:
        import json

        try:
            with open(args.dump_payload, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, default=str)
        except OSError as exc:
            print(f"error: cannot write {args.dump_payload}: {exc}", file=sys.stderr)
            return EXIT_ERROR

    report = audit(payload, expect=expect)
    print(render(report, args.format))
    return exit_code_for(report, args.fail_on)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
