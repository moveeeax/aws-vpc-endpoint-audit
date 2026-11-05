import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> dict:
    with open(FIXTURES / name, encoding="utf-8") as handle:
        return json.load(handle)


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def clean() -> dict:
    return load("clean.json")


@pytest.fixture
def nat_only() -> dict:
    return load("nat_no_gateway_endpoints.json")


@pytest.fixture
def partial_routes() -> dict:
    return load("partial_route_coverage.json")


@pytest.fixture
def interface_problems() -> dict:
    return load("interface_problems.json")
