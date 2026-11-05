# aws-vpc-endpoint-audit

[![ci](https://github.com/moveeeax/aws-vpc-endpoint-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-vpc-endpoint-audit/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Audits VPC endpoints against the traffic a NAT gateway is billing for. Missing S3 and
DynamoDB gateway endpoints, gateway endpoints wired to only some private route tables,
interface endpoints nobody can reach on 443 or with private DNS switched off, single-AZ
placement in a multi-AZ VPC, and wildcard endpoint policies — one list, with the fix, and a
non-zero exit code for CI.

A VPC endpoint is cheap to add and invisible when absent. Without the S3 gateway endpoint
every `GET` from a private subnet is billed as NAT data processing on top of the transfer,
and the only evidence is a line item. Interface endpoints fail the other way: they bill per
AZ per hour whether or not anything uses them, and `PrivateDnsEnabled: false` or a security
group with no 443 ingress makes them useless while the meter runs.

## Install

```bash
pip install git+https://github.com/moveeeax/aws-vpc-endpoint-audit
```

## Usage

```bash
aws-vpc-endpoint-audit --region eu-central-1
aws-vpc-endpoint-audit --vpc-id vpc-0abc123 --expect ssm,ecr.api,ecr.dkr --fail-on critical
aws-vpc-endpoint-audit --format json | jq '.vpcs[] | select(.severity=="critical")'
aws-vpc-endpoint-audit --from-json examples/prod.json --format markdown
```

Real output against the bundled example payload:

```console
$ aws-vpc-endpoint-audit --from-json examples/prod.json --expect ""
region: eu-central-1

vpc-0a1b2c3d4e5f60001 (prod)  [CRIT]  endpoints=3  nat=yes
  CRIT  vpce-0prodecrdkr  interface-endpoint-unreachable
        ecr.dkr interface endpoint is billed hourly but unreachable from the VPC CIDR on 443: no rule allows 443
        fix: allow TCP 443 from the VPC CIDR on a security group attached to the endpoint
  CRIT  vpc-0a1b2c3d4e5f60001  missing-gateway-endpoint
        no dynamodb endpoint while a NAT gateway is present, so every dynamodb request from a private subnet is billed as NAT data processing
        fix: create a Gateway endpoint for com.amazonaws.eu-central-1.dynamodb and associate it with the private route tables
  WARN  vpce-0prods3  endpoint-wildcard-policy
        s3 endpoint policy allows every action for every principal with no condition
        fix: narrow the policy to the buckets, tables or API calls this path is meant to reach
  WARN  vpce-0prods3  gateway-endpoint-partial-route-coverage
        s3 gateway endpoint covers 2 of 3 NAT-routed route tables; rtb-0prod-priv-c is still routed to the service through NAT
        fix: add the endpoint association for rtb-0prod-priv-c
  WARN  vpce-0prodssm  interface-endpoint-private-dns-disabled
        ssm interface endpoint has private DNS disabled, so unmodified SDK calls still resolve the public name
        fix: enable PrivateDnsEnabled, or point callers at the endpoint-specific DNS name on purpose
  WARN  vpce-0prodssm  interface-endpoint-single-az
        ssm interface endpoint lives in 1 AZ while the VPC spans 3
        fix: add a subnet from each remaining availability zone to the endpoint

vpc-0a1b2c3d4e5f60002 (data)  [OK]  endpoints=2  nat=no
  ok  no endpoint gaps found

2 vpc(s), 6 finding(s): 2 critical, 4 warn
$ echo $?
1
```

### Flags

| flag | meaning |
| --- | --- |
| `--region` | AWS region; defaults to the usual boto3 resolution |
| `--vpc-id` | limit to one VPC, repeatable |
| `--expect` | comma-separated interface endpoint short names a private VPC should have; default `ecr.api,ecr.dkr,ssm,ssmmessages,ec2messages,logs`, empty string disables the check |
| `--format` | `text` (default), `json`, `markdown` |
| `--fail-on` | `critical` (default), `warn`, `none` — which severity makes the exit code 1 |
| `--from-json` | replay a saved payload with no AWS calls |
| `--dump-payload` | write the collected payload for a later `--from-json` run |

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` bad input or a failed AWS
call. A malformed `--from-json` file prints one line to stderr, never a traceback.

## How it works

Collection and judgement are separate. `collect.py` makes read-only `ec2` calls —
`describe_vpcs`, `describe_subnets`, `describe_route_tables`, `describe_vpc_endpoints`,
`describe_nat_gateways`, `describe_security_groups` — and flattens them into plain dicts.
`rules.py` is pure functions over that payload, so every rule is tested against JSON
fixtures with no credentials and no `moto`. `boto3` is imported lazily inside `collect()`,
which is why `--from-json` and the test suite run without the SDK installed at all.

### The rules

| rule | severity | when |
| --- | --- | --- |
| `missing-gateway-endpoint` | critical | a live NAT gateway and no available `s3` or `dynamodb` endpoint |
| `gateway-endpoint-unassociated` | critical | a gateway endpoint associated with no route table, so it carries nothing |
| `interface-endpoint-unreachable` | critical | no attached security group permits 443 from anywhere in the VPC CIDR |
| `gateway-endpoint-partial-route-coverage` | warn | associated with some, not all, NAT-routed private route tables |
| `interface-endpoint-partial-reachability` | warn | 443 allowed from part of the VPC CIDR only |
| `interface-endpoint-private-dns-disabled` | warn | `PrivateDnsEnabled: false` |
| `interface-endpoint-single-az` | warn | one AZ while the VPC spans several |
| `endpoint-not-available` | warn | state other than `available` |
| `endpoint-wildcard-policy` | warn | an Allow statement with wildcard principal and action and no condition |
| `missing-expected-endpoint` | warn | an interface endpoint from `--expect` is absent |

A route table counts as NAT-routed when it is attached to a subnet (or is the main table),
has no `igw-` route, and has a `0.0.0.0/0` route through a NAT gateway. Those are the tables
actually paying, so they are the ones a gateway endpoint has to cover.

Reachability uses `ipaddress`: a permission that allows TCP 443 (or all protocols) from a
CIDR that supersets the VPC CIDR is full coverage, an overlapping-but-narrower CIDR is
partial, nothing overlapping is `none`. A source security group or prefix list on 443 counts
as reachable — it is in-VPC access this tool cannot disprove from CIDRs alone, and guessing
otherwise would be a false positive on every well-built setup.

## In CI

```yaml
- name: Audit VPC endpoints
  run: aws-vpc-endpoint-audit --region eu-central-1 --fail-on critical
```

Needs `ec2:Describe*` and nothing else. Save a payload with `--dump-payload` to replay the
same run later, or to hand someone the evidence without giving them an account.

## Development

```bash
pip install -e '.[dev]'
ruff check .
pytest
```

## License

MIT
