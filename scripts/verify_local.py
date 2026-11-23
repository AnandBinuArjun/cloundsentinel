"""Local static verification helper for Docker Compose and GitHub Actions YAML files."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def verify_yaml_files() -> int:
    targets = [
        ROOT / "docker-compose.yml",
        ROOT / ".github" / "workflows" / "ci.yml",
        ROOT / ".github" / "workflows" / "release.yml",
        ROOT / ".github" / "workflows" / "cloud-lab-prowler.yml",
    ]
    failed = False
    for path in targets:
        if not path.exists():
            print(f"[FAIL] Missing file: {path}")
            failed = True
            continue
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                print(f"[FAIL] {path.name} did not parse to a YAML mapping")
                failed = True
            else:
                print(f"[OK] Valid YAML: {path.relative_to(ROOT)}")
        except yaml.YAMLError as exc:
            print(f"[FAIL] Invalid YAML in {path.relative_to(ROOT)}: {exc}")
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(verify_yaml_files())
