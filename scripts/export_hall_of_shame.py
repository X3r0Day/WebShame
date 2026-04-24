#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


MAX_HISTORY_FILE_BYTES = 100 * 1024 * 1024
HISTORY_CHUNK_SAFETY_MARGIN_BYTES = 1024 * 1024


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sanitize XeroDay-APISniffer leaked_keys.json for GitHub Pages."
    )
    parser.add_argument(
        "--input",
        default="XeroDay-APISniffer/leaked_keys.json",
        help="Path to the raw leaked_keys.json file.",
    )
    parser.add_argument(
        "--output",
        default="data/hall-of-shame.json",
        help="Path to the public-safe exported dataset.",
    )
    parser.add_argument(
        "--clean-input",
        default="XeroDay-APISniffer/clean_repos.json",
        help="Path to the clean_repos.json file.",
    )
    parser.add_argument(
        "--failed-input",
        default="XeroDay-APISniffer/failed_repos.json",
        help="Path to the failed_repos.json file.",
    )
    parser.add_argument(
        "--history-output",
        default="data/scan-history.json",
        help="Path to the sanitized scan history file.",
    )
    parser.add_argument(
        "--max-findings",
        type=int,
        default=6,
        help="Maximum findings to keep per repository in the public export.",
    )
    parser.add_argument(
        "--history-max-bytes",
        type=int,
        default=MAX_HISTORY_FILE_BYTES,
        help="Maximum allowed size for data/scan-history JSON files before chunking.",
    )
    return parser.parse_args()


def mask_secret(secret: str) -> str:
    raw = str(secret or "").strip()
    if not raw:
        return "redacted"
    if len(raw) <= 8:
        return f"{raw[:2]}{'*' * max(len(raw) - 4, 2)}{raw[-2:]}"
    return f"{raw[:4]}{'*' * min(len(raw) - 8, 24)}{raw[-4:]}"


def derive_severity(total_secrets: int, unique_types: int, commit_findings: int) -> str:
    score = total_secrets * 12 + unique_types * 8 + commit_findings * 10
    if score >= 110:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def load_json(path: Path) -> list[dict]:
    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError(f"{path} did not contain a JSON list")
    return [entry for entry in payload if isinstance(entry, dict)]


def load_existing_site(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}

    payload = json.loads(path.read_text(encoding="utf-8"))
    repos = payload.get("repos", []) if isinstance(payload, dict) else []
    existing: dict[str, dict] = {}

    for repo in repos:
        if not isinstance(repo, dict):
            continue
        repo_name = str(repo.get("repo") or repo.get("name") or "").strip()
        if repo_name:
            existing[repo_name.lower()] = repo

    return existing


def sanitize_findings(findings: list[dict], max_findings: int) -> tuple[list[dict], Counter, int]:
    sanitized = []
    type_counter: Counter = Counter()
    commit_findings = 0

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        finding_type = str(finding.get("type") or "Unknown Secret")
        file_name = str(finding.get("file") or "unknown")
        source = "commit" if file_name.startswith("Commit ") else "file"

        if source == "commit":
            commit_findings += 1

        type_counter[finding_type] += 1

        if len(sanitized) >= max_findings:
            continue

        sanitized.append(
            {
                "type": finding_type,
                "file": file_name,
                "line": int(finding.get("line") or 0),
                "source": source,
                "preview": mask_secret(str(finding.get("secret") or "")),
            }
        )

    return sanitized, type_counter, commit_findings


def transform_repo(entry: dict, max_findings: int) -> dict | None:
    findings = entry.get("findings")
    if not isinstance(findings, list) or not findings:
        return None

    sanitized_findings, type_counter, commit_findings = sanitize_findings(findings, max_findings)
    repo_name = str(entry.get("repo") or entry.get("name") or "").strip()
    if not repo_name:
        return None

    total_secrets = int(entry.get("total_secrets") or len(findings))
    files_affected = len({str(finding.get("file") or "unknown") for finding in findings if isinstance(finding, dict)})
    unique_types = len(type_counter)
    severity = derive_severity(total_secrets, unique_types, commit_findings)
    exposure_score = total_secrets * 12 + unique_types * 8 + commit_findings * 10
    top_types = [name for name, _count in type_counter.most_common(4)]

    return {
        "repo": repo_name,
        "url": str(entry.get("url") or f"https://github.com/{repo_name}"),
        "status": "leaked",
        "severity": severity,
        "totalSecrets": total_secrets,
        "uniqueTypes": unique_types,
        "filesAffected": files_affected,
        "commitFindings": commit_findings,
        "scanTimeSeconds": round(float(entry.get("time_taken") or 0.0), 2),
        "exposureScore": exposure_score,
        "topTypes": top_types,
        "typeCounts": dict(type_counter),
        "findings": sanitized_findings,
    }


def history_precedence(status: str) -> int:
    return {
        "clean": 1,
        "failed": 2,
        "leaked": 3,
    }.get(status, 0)


def merge_history_entry(index: dict[str, dict], entry: dict, fallback_status: str, generated_at: str) -> None:
    repo_name = str(entry.get("repo") or entry.get("name") or "").strip()
    if not repo_name:
        return

    status = str(entry.get("status") or fallback_status).strip().lower() or fallback_status
    candidate = {
        "repo": repo_name,
        "url": str(entry.get("url") or f"https://github.com/{repo_name}"),
        "status": status,
        "totalSecrets": int(entry.get("total_secrets") or entry.get("totalSecrets") or 0),
        "lastScannedAt": generated_at,
    }

    existing = index.get(repo_name.lower())
    if existing and history_precedence(existing.get("status", "")) >= history_precedence(status):
        return

    index[repo_name.lower()] = candidate


def build_scan_history(
    leaked_entries: list[dict],
    clean_entries: list[dict],
    failed_entries: list[dict],
    generated_at: str,
) -> dict:
    history_index: dict[str, dict] = {}

    for entry in clean_entries:
        merge_history_entry(history_index, entry, "clean", generated_at)

    for entry in failed_entries:
        merge_history_entry(history_index, entry, "failed", generated_at)

    for entry in leaked_entries:
        merge_history_entry(history_index, entry, "leaked", generated_at)

    repos = sorted(
        history_index.values(),
        key=lambda repo: (
            -history_precedence(repo["status"]),
            repo["repo"],
        ),
    )
    return {
        "generatedAt": generated_at,
        "repos": repos,
    }


def write_json_compact(path: Path, payload: object) -> None:
    path.write_bytes(compact_json_bytes(payload))


def compact_json_bytes(payload: object) -> bytes:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def json_size_bytes(payload: object) -> int:
    return len(compact_json_bytes(payload))


def cleanup_history_parts(history_output_path: Path, keep_names: set[str]) -> None:
    part_prefix = f"{history_output_path.stem}.part"
    for existing_part in history_output_path.parent.glob(f"{part_prefix}*.json"):
        if existing_part.name not in keep_names:
            existing_part.unlink(missing_ok=True)


def write_chunked_json(output_path: Path, payload: dict, max_bytes: int, format_name: str) -> None:
    repos = payload.get("repos", [])
    if not isinstance(repos, list):
        repos = []

    compact_size = json_size_bytes(payload)
    if compact_size <= max_bytes:
        write_json_compact(output_path, payload)
        cleanup_history_parts(output_path, set())
        return

    chunk_target_bytes = max(1, max_bytes - HISTORY_CHUNK_SAFETY_MARGIN_BYTES)
    empty_repos_payload_size = json_size_bytes({"repos": []})
    chunked_repos: list[list[dict]] = []
    current_chunk: list[dict] = []
    current_chunk_payload_size = empty_repos_payload_size

    for repo in repos:
        repo_size = json_size_bytes(repo)
        next_len = len(current_chunk) + 1
        candidate_size = current_chunk_payload_size + repo_size + (1 if next_len > 1 else 0)

        if current_chunk and candidate_size > chunk_target_bytes:
            chunked_repos.append(current_chunk)
            current_chunk = [repo]
            current_chunk_payload_size = empty_repos_payload_size + repo_size
            continue

        current_chunk.append(repo)
        current_chunk_payload_size = candidate_size

    if current_chunk:
        chunked_repos.append(current_chunk)

    keep_names: set[str] = set()
    part_entries: list[dict] = []
    part_prefix = f"{output_path.stem}.part"

    for index, chunk in enumerate(chunked_repos, start=1):
        part_name = f"{part_prefix}{index:04d}.json"
        part_path = output_path.parent / part_name
        part_payload = {"repos": chunk}

        if json_size_bytes(part_payload) > max_bytes:
            raise ValueError(
                f"Could not split safely: {part_name} still exceeds {max_bytes} bytes"
            )

        write_json_compact(part_path, part_payload)
        keep_names.add(part_name)
        part_entries.append({"file": part_name, "repos": len(chunk)})

    manifest = {"generatedAt": payload.get("generatedAt")}
    if "source" in payload:
        manifest["source"] = payload["source"]
        
    manifest.update({
        "format": format_name,
        "chunked": True,
        "totalRepos": len(repos),
        "parts": part_entries,
    })
    write_json_compact(output_path, manifest)
    cleanup_history_parts(output_path, keep_names)


def main() -> int:
    args = parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)
    clean_input_path = Path(args.clean_input)
    failed_input_path = Path(args.failed_input)
    history_output_path = Path(args.history_output)

    raw_entries = load_json(input_path)
    clean_entries = load_json(clean_input_path)
    failed_entries = load_json(failed_input_path)
    existing_site = load_existing_site(output_path)
    repos = []

    for entry in raw_entries:
        if str(entry.get("status") or "").lower() not in {"leaked", "leak"}:
            continue
        transformed = transform_repo(entry, max(1, args.max_findings))
        if transformed:
            existing_site[transformed["repo"].lower()] = transformed

    repos = sorted(
        existing_site.values(),
        key=lambda repo: (-repo["exposureScore"], -repo["totalSecrets"], repo["repo"]),
    )

    generated_at = datetime.now(timezone.utc).isoformat()

    payload = {
        "generatedAt": generated_at,
        "source": "XeroDay-APISniffer",
        "repos": repos,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_chunked_json(
        output_path,
        payload,
        max(1, int(args.history_max_bytes)),
        "hall-of-shame-chunked-v1"
    )

    history_payload = build_scan_history(raw_entries, clean_entries, failed_entries, generated_at)
    history_output_path.parent.mkdir(parents=True, exist_ok=True)
    write_chunked_json(
        history_output_path,
        history_payload,
        max(1, int(args.history_max_bytes)),
        "scan-history-chunked-v1"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
