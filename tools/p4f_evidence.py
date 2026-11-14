"""P4-F offline evidence snapshot CLI. Never reads SDK credentials or talks to AWS.

Usage:
  python tools/p4f_evidence.py init-key --key-file ./p4f.snapshot-key
  python tools/p4f_evidence.py export --report RESULTS.json --key-file ./p4f.snapshot-key --output snapshot.json
  python tools/p4f_evidence.py replay --snapshot snapshot.json --key-file ./p4f.snapshot-key
  python tools/p4f_evidence.py diff --before old.json --after new.json --key-file ./p4f.snapshot-key
"""
import argparse
import json
import os
import secrets
import stat
import sys
from pathlib import Path

from ScoutSuite.core.evidence_snapshot import (
    KEY_BYTES, MAX_SOURCE_BYTES, SnapshotError,
    diff_evidence_snapshots, export_evidence_snapshot, verify_evidence_snapshot,
)


def _read_bytes(path):
    file = Path(path)
    if file.is_symlink():
        raise SnapshotError("Symlink input rejected")
    with file.open("rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise SnapshotError("Not a regular input file")
        data = stream.read(MAX_SOURCE_BYTES + 1)
    if len(data) > MAX_SOURCE_BYTES:
        raise SnapshotError("Input exceeds snapshot size limit")
    return data


def _read_key(path):
    file = Path(path)
    if file.is_symlink():
        raise SnapshotError("Symlink key rejected")
    with file.open("rb") as stream:
        mode = os.fstat(stream.fileno()).st_mode
        if not stat.S_ISREG(mode):
            raise SnapshotError("Key must be a regular file")
        if os.name != "nt" and (stat.S_IMODE(mode) & 0o077):
            raise SnapshotError("Key permissions must be private")
        key = stream.read(KEY_BYTES + 1)
    if len(key) != KEY_BYTES:
        raise SnapshotError("Identity key must be 32 bytes")
    return key


def _create_private(path, value):
    target = Path(path)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(target, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            os.chmod(target, 0o600)
    except BaseException:
        try:
            os.unlink(target)
        except OSError:
            pass
        raise


def _load_json(path, kind):
    raw = _read_bytes(path)
    if kind == "results":
        # Strictly accept Scout JS JSON data assignment, never execute JS.
        prefix = b"scoutsuite_results ="
        compact = raw.lstrip(b" \t\r\n")
        if compact.startswith(prefix):
            raw = compact[len(prefix):].strip()
            if raw.endswith(b";"):
                raw = raw[:-1].rstrip()
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise SnapshotError("Input JSON cannot be decoded") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Offline, privacy-preserving Scout finding evidence snapshots")
    commands = parser.add_subparsers(dest="command", required=True)
    new = commands.add_parser("init-key", help="Create a local private 32-byte identity key")
    new.add_argument("--key-file", required=True)
    export = commands.add_parser("export", help="Export only allowlisted findings, never raw AWS inventory")
    export.add_argument("--report", required=True)
    export.add_argument("--key-file", required=True)
    export.add_argument("--output", required=True)
    replay = commands.add_parser("replay", help="Authenticate and replay observation aggregation")
    replay.add_argument("--snapshot", required=True)
    replay.add_argument("--key-file", required=True)
    diff = commands.add_parser("diff", help="Compare two snapshots using stable pseudonym tokens")
    diff.add_argument("--before", required=True)
    diff.add_argument("--after", required=True)
    diff.add_argument("--key-file", required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "init-key":
            _create_private(args.key_file, secrets.token_bytes(KEY_BYTES))
            print(json.dumps({"status": "private_key_created"}, sort_keys=True))
            return 0
        key = _read_key(args.key_file)
        if args.command == "export":
            record = _load_json(args.report, "results")
            snapshot = export_evidence_snapshot(record, key)
            _create_private(args.output, (json.dumps(snapshot, sort_keys=True,
                                                   separators=(",", ":"),
                                                   allow_nan=False) + "\n").encode("utf-8"))
            print(json.dumps({"status": "snapshot_created",
                              "rules_observed": sum(len(x) for x in snapshot["findings"].values()),
                              "schema_version": snapshot["schema_version"],
                              "key_id": snapshot["key_id"]}, sort_keys=True))
            return 0
        if args.command == "replay":
            outcome = verify_evidence_snapshot(_load_json(args.snapshot, "snapshot"), key)
            print(json.dumps(outcome, sort_keys=True))
            return 0 if outcome["replay_status"] == "verified_observations" else 2
        first = _load_json(args.before, "snapshot")
        second = _load_json(args.after, "snapshot")
        result = diff_evidence_snapshots(first, second, key)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (SnapshotError, OSError, TypeError, ValueError):
        # Never print raw exception strings: they might contain sensitive file
        # paths, JSON payloads, AWS credentials or report content.
        print(json.dumps({"status": "rejected", "reason": "invalid_or_unverifiable_input"}),
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
