#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Materialize sanitized scan history into APISniffer history files."
    )
    parser.add_argument(
        "--state",
        default="data/scan-history.json",
        help="Path to the sanitized scan history file.",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory containing the APISniffer checkout.",
    )
    return parser.parse_args()


def load_state(path: Path) -> list[dict]:
    if not path.exists():
        return []

    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        repos = payload.get("repos", [])
    else:
        repos = payload

    return [entry for entry in repos if isinstance(entry, dict)]


def write_json(path: Path, payload: list[dict]) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main() -> int:
    args = parse_args()
    state_path = Path(args.state)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    leaks = []
    clean = []
    failed = []

    for entry in load_state(state_path):
        repo_name = str(entry.get("repo") or entry.get("name") or "").strip()
        if not repo_name:
            continue

        sanitized = {
            "repo": repo_name,
            "url": str(entry.get("url") or f"https://github.com/{repo_name}"),
            "status": str(entry.get("status") or "clean").strip().lower(),
        }

        if sanitized["status"] == "leaked":
            leaks.append(sanitized)
        elif sanitized["status"] == "failed":
            failed.append(sanitized)
        else:
            clean.append(sanitized)

    write_json(output_dir / "leaked_keys.json", leaks)
    write_json(output_dir / "clean_repos.json", clean)
    write_json(output_dir / "failed_repos.json", failed)

    recent_repos_path = output_dir / "recent_repos.json"
    if not recent_repos_path.exists():
        write_json(recent_repos_path, [])

    proxies_path = output_dir / "live_proxies.txt"
    if not proxies_path.exists():
        proxies_path.write_text("", encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
