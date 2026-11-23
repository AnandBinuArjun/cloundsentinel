"""Static validation tests for Docker Compose, Dockerfiles, and GitHub Actions."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.unit
def test_docker_compose_schema_and_services() -> None:
    compose_path = REPO_ROOT / "docker-compose.yml"
    data = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    services = data.get("services")
    assert isinstance(services, dict)
    for required_service in ("postgres", "redis", "api", "worker", "web"):
        assert required_service in services
        assert "no-new-privileges:true" in services[required_service].get("security_opt", [])


@pytest.mark.unit
@pytest.mark.parametrize(
    "dockerfile_rel",
    [
        "infrastructure/docker/Dockerfile.api",
        "infrastructure/docker/Dockerfile.worker",
        "infrastructure/docker/Dockerfile.web",
    ],
)
def test_dockerfiles_enforce_non_root_user(dockerfile_rel: str) -> None:
    content = (REPO_ROOT / dockerfile_rel).read_text(encoding="utf-8")
    user_lines = [line.strip() for line in content.splitlines() if line.strip().startswith("USER ")]
    assert user_lines, f"{dockerfile_rel} must declare a non-root USER"
    assert all(line.lower() != "user root" for line in user_lines)
    assert "HEALTHCHECK " in content, f"{dockerfile_rel} must declare a HEALTHCHECK"


@pytest.mark.unit
@pytest.mark.parametrize(
    "dockerfile_rel",
    [
        "infrastructure/docker/Dockerfile.api",
        "infrastructure/docker/Dockerfile.worker",
    ],
)
def test_python_dockerfiles_copy_all_runtime_packages(dockerfile_rel: str) -> None:
    content = (REPO_ROOT / dockerfile_rel).read_text(encoding="utf-8")
    for pkg in ("apps", "packages", "cloud_connectors", "detections", "compliance"):
        assert f"./{pkg}" in content, f"{dockerfile_rel} must copy {pkg}"


@pytest.mark.unit
@pytest.mark.parametrize(
    "workflow_rel",
    [
        ".github/workflows/ci.yml",
        ".github/workflows/release.yml",
    ],
)
def test_github_workflows_are_valid_yaml_with_permissions(workflow_rel: str) -> None:
    data = yaml.safe_load((REPO_ROOT / workflow_rel).read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    assert "permissions" in data
    assert "jobs" in data and isinstance(data["jobs"], dict) and len(data["jobs"]) >= 1


@pytest.mark.unit
def test_gitignore_excludes_env_and_secret_files() -> None:
    gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    for pattern in (".env", "*.pem", "*.key", "*.tfstate"):
        assert pattern in gitignore
