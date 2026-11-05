"""Render an audit report as text, JSON or Markdown."""

from __future__ import annotations

import json

from .model import CRITICAL, OK, WARN

MARKERS = {CRITICAL: "CRIT", WARN: "WARN", OK: "OK"}


def render(report: dict, fmt: str = "text") -> str:
    if fmt == "json":
        return render_json(report)
    if fmt == "markdown":
        return render_markdown(report)
    if fmt == "text":
        return render_text(report)
    raise ValueError(f"unknown format: {fmt}")


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=False)


def render_text(report: dict) -> str:
    lines = [f"region: {report.get('region', '')}"]
    for vpc in report.get("vpcs", []):
        header = f"\n{vpc['vpc_id']}"
        if vpc.get("name"):
            header += f" ({vpc['name']})"
        header += f"  [{MARKERS.get(vpc['severity'], vpc['severity'])}]"
        header += f"  endpoints={vpc.get('endpoint_count', 0)}"
        header += f"  nat={'yes' if vpc.get('nat_gateway_present') else 'no'}"
        lines.append(header)

        if not vpc["findings"]:
            lines.append("  ok  no endpoint gaps found")
            continue
        for finding in vpc["findings"]:
            marker = MARKERS.get(finding["severity"], finding["severity"])
            lines.append(f"  {marker}  {finding['resource']}  {finding['rule']}")
            lines.append(f"        {finding['message']}")
            lines.append(f"        fix: {finding['fix']}")

    summary = report.get("summary", {})
    lines.append(
        f"\n{summary.get('vpcs', 0)} vpc(s), {summary.get('findings', 0)} finding(s): "
        f"{summary.get('critical', 0)} critical, {summary.get('warn', 0)} warn"
    )
    return "\n".join(lines)


def render_markdown(report: dict) -> str:
    summary = report.get("summary", {})
    lines = [
        "# VPC endpoint audit",
        "",
        f"- region: `{report.get('region', '')}`",
        f"- vpcs: {summary.get('vpcs', 0)}",
        f"- findings: {summary.get('findings', 0)} "
        f"({summary.get('critical', 0)} critical, {summary.get('warn', 0)} warn)",
        "",
    ]
    for vpc in report.get("vpcs", []):
        title = f"## `{vpc['vpc_id']}`"
        if vpc.get("name"):
            title += f" — {vpc['name']}"
        lines += [title, "", f"severity: **{vpc['severity']}**", ""]
        if not vpc["findings"]:
            lines += ["No endpoint gaps found.", ""]
            continue
        lines += [
            "| severity | resource | rule | finding | fix |",
            "| --- | --- | --- | --- | --- |",
        ]
        for finding in vpc["findings"]:
            lines.append(
                f"| {finding['severity']} | `{finding['resource']}` | `{finding['rule']}` | "
                f"{finding['message']} | {finding['fix']} |"
            )
        lines.append("")
    return "\n".join(lines)
