import subprocess
from collections.abc import Iterator
from pathlib import Path

import jubilant
import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--charm_path", action="store", required=True, help="Path to the charm under test"
    )


@pytest.fixture(scope="session")
def charm_path(request: pytest.FixtureRequest) -> Path:
    path = Path(str(request.config.getoption("--charm_path"))).resolve()
    if not path.exists():
        pytest.exit(f"The path specified for the charm under test does not exist: {path}")
    return path


@pytest.fixture(scope="module")
def juju(request: pytest.FixtureRequest) -> Iterator[jubilant.Juju]:
    with jubilant.temp_model() as model:
        model.wait_timeout = 10 * 60
        yield model
        if request.session.testsfailed:
            Path("juju-debug.log").write_text(model.debug_log())
            subprocess.run(
                ["juju-crashdump", "-s", "-m", str(model.model), "-o", "."],
                check=False,
                timeout=120,
            )
