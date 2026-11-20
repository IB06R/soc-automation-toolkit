import argparse
import csv
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

DEFAULT_IGNORES = {".git", "__pycache__", ".venv", "venv"}


def hash_file(filepath: str) -> str:
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def scan_directory(
    target_dir: str, baseline_abs_path: str, ignore_dirs: set[str]
) -> dict[str, dict]:
    manifest = {}
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]

        for filename in sorted(files):
            full_path = os.path.join(root, filename)
            if os.path.abspath(full_path) == baseline_abs_path:
                continue

            rel_path = os.path.relpath(full_path, target_dir)
            try:
                stat = os.stat(full_path)
                manifest[rel_path] = {
                    "sha256": hash_file(full_path),
                    "size_bytes": stat.st_size,
                    "modified_utc": datetime.fromtimestamp(
                        stat.st_mtime, tz=timezone.utc
                    ).isoformat(),
                }
            except (PermissionError, OSError) as exc:
                print(f"[!] Skipped {rel_path}: {exc}")
    return manifest


def init_baseline(target_dir: str, baseline_path: str, ignore_dirs: set[str]):
    baseline_abs = os.path.abspath(baseline_path)
    manifest = scan_directory(target_dir, baseline_abs, ignore_dirs)
    payload = {
        "schema_version": 2,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "target_directory": os.path.abspath(target_dir),
        "files": manifest,
    }
    with open(baseline_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    print(f"[+] Baseline initialized with {len(manifest)} file(s) -> {baseline_path}")


def check_integrity(
    target_dir: str, baseline_path: str, ignore_dirs: set[str], output_csv: str
):
    if not os.path.exists(baseline_path):
        print(f"[!] Baseline not found: {baseline_path}. Run 'init' first.", file=sys.stderr)
        sys.exit(1)

    with open(baseline_path, "r", encoding="utf-8") as f:
        stored = json.load(f)

    expected_dir = stored.get("target_directory")
    actual_dir = os.path.abspath(target_dir)
    if expected_dir and expected_dir != actual_dir:
        print(
            f"[!] Directory mismatch: baseline was built for '{expected_dir}', "
            f"not '{actual_dir}'.",
            file=sys.stderr,
        )
        sys.exit(1)

    baseline = stored["files"]
    baseline_abs = os.path.abspath(baseline_path)
    current = scan_directory(target_dir, baseline_abs, ignore_dirs)
    alert_records = []

    for path, old_entry in baseline.items():
        old_hash = old_entry if isinstance(old_entry, str) else old_entry["sha256"]
        old_size = "N/A" if isinstance(old_entry, str) else old_entry["size_bytes"]

        if path not in current:
            print(f"[ALERT - DELETED]  {path}")
            alert_records.append(
                {
                    "alert_type": "DELETED",
                    "file_path": path,
                    "old_size_bytes": old_size,
                    "new_size_bytes": 0,
                    "modified_utc": "N/A",
                    "old_sha256": old_hash,
                    "current_sha256": "DELETED",
                }
            )
        elif current[path]["sha256"] != old_hash:
            print(
                f"[ALERT - MODIFIED] {path} "
                f"(Size: {old_size}B -> {current[path]['size_bytes']}B | "
                f"Modified: {current[path]['modified_utc']})"
            )
            alert_records.append(
                {
                    "alert_type": "MODIFIED",
                    "file_path": path,
                    "old_size_bytes": old_size,
                    "new_size_bytes": current[path]["size_bytes"],
                    "modified_utc": current[path]["modified_utc"],
                    "old_sha256": old_hash,
                    "current_sha256": current[path]["sha256"],
                }
            )

    for path, new_meta in current.items():
        if path not in baseline:
            print(
                f"[ALERT - CREATED]  {path} "
                f"(Size: {new_meta['size_bytes']}B | SHA256: {new_meta['sha256'][:16]}...)"
            )
            alert_records.append(
                {
                    "alert_type": "CREATED",
                    "file_path": path,
                    "old_size_bytes": 0,
                    "new_size_bytes": new_meta["size_bytes"],
                    "modified_utc": new_meta["modified_utc"],
                    "old_sha256": "NONE",
                    "current_sha256": new_meta["sha256"],
                }
            )

    if not alert_records:
        print("[+] Integrity check passed: 0 unauthorized changes detected.")
        sys.exit(0)

    with open(output_csv, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=[
                "alert_type",
                "file_path",
                "old_size_bytes",
                "new_size_bytes",
                "modified_utc",
                "old_sha256",
                "current_sha256",
            ],
        )
        writer.writeheader()
        writer.writerows(alert_records)

    print(f"\n[!] Integrity check complete: {len(alert_records)} alert(s) triggered.")
    print(f"[+] Exported forensic alert report to {output_csv}")
    sys.exit(2)


def main():
    parser = argparse.ArgumentParser(
        description="Cryptographic SHA-256 File Integrity Monitor (FIM)."
    )
    parser.add_argument("mode", choices=["init", "check"], help="Operation mode")
    parser.add_argument("directory", help="Target directory to baseline or audit")
    parser.add_argument(
        "-b",
        "--baseline",
        default="fim_baseline.json",
        help="Path to baseline JSON manifest (default: fim_baseline.json)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=f"fim_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        help="Output CSV path when tampering alerts trigger",
    )
    parser.add_argument(
        "--ignore",
        nargs="*",
        default=[],
        help="Additional directory names to exclude (e.g., logs cache)",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print(f"[!] Directory does not exist: {args.directory}", file=sys.stderr)
        sys.exit(1)

    ignore_dirs = DEFAULT_IGNORES.union(set(args.ignore))

    if args.mode == "init":
        init_baseline(args.directory, args.baseline, ignore_dirs)
    else:
        check_integrity(args.directory, args.baseline, ignore_dirs, args.output)


if __name__ == "__main__":
    main()
