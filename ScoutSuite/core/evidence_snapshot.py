"""P4-F: privacy-preserving, deterministic Scout evidence snapshots.

This is an *observation replay*, not a replay of raw AWS responses or an IAM
authorization simulator. Results are projected onto an explicit allowlist
before writing anything. No account IDs, resource paths, DNS names, policy
documents, AWS payloads, raw API errors or credentials are serialized.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from pathlib import Path
from functools import lru_cache

from ScoutSuite import __version__ as SCOUT_VERSION

SCHEMA = "scoutsuite-evidence-snapshot"
VERSION = 1
KEY_BYTES = 32
MAX_SOURCE_BYTES = 250 * 1024 * 1024
MAX_RULES = 2000
MAX_IDENTITIES_PER_RULE = 100000
MAX_ISSUES = 20000
_NAME = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.-]{0,127}$")
_STATUS = frozenset(("incomplete", "evaluated", "not_applicable", "review",
                     "unknown", "unavailable"))
_ISSUE_STATUS = frozenset(("partial", "failed", "denied", "unsupported"))
_COUNTS = ("secure", "insecure", "unknown", "not_applicable")
_RULES_DIR = Path(__file__).resolve().parents[1] / "providers" / "aws" / "rules" / "findings"


class SnapshotError(ValueError):
    """Snapshot integrity/privacy failure. Do not embed source values in errors."""


def _canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("utf-8")


def _digest(data):
    return hashlib.sha256(_canonical(data)).hexdigest()


def _checked_key(key):
    if not isinstance(key, bytes) or len(key) != KEY_BYTES:
        raise SnapshotError("Invalid identity key")
    return key


def _name(value):
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        raise SnapshotError("Invalid service or rule identifier")
    return value


def _integer(value, *, maximum=10000000):
    if type(value) is not int or value < 0 or value > maximum:
        raise SnapshotError("Invalid nonnegative evidence counter")
    return value


def _identity(key, account, service, rule, raw, label):
    if not isinstance(raw, str) or not raw or len(raw) > 16384:
        raise SnapshotError("Invalid resource identity")
    # The account scope is used ONLY as HMAC input and is never retained.
    text = "\x00".join((label, account, service, rule, raw)).encode("utf-8")
    return "hmac:" + hmac.new(key, text, hashlib.sha256).hexdigest()[:40]


@lru_cache(maxsize=1)
def _installed_services():
    """Service names are known package metadata, never untrusted report labels."""
    file = Path(__file__).resolve().parents[1] / "providers" / "aws" / "metadata.json"
    try:
        metadata = json.loads(file.read_text(encoding="utf-8"))
        return frozenset(name for group in metadata.values() if isinstance(group, dict)
                         for name, record in group.items()
                         if name != "summaries" and isinstance(record, dict))
    except (OSError, ValueError, TypeError):
        raise SnapshotError("AWS service metadata unavailable")


def _account_scope(payload):
    account = payload.get("account_id", "")
    if not isinstance(account, str) or len(account) > 128:
        raise SnapshotError("Invalid account scope")
    return account


def _rule_definition_digest(rule):
    """Digest exact local JSON rule definition, not any untrusted report text."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,119}", rule):
        return None
    file = _RULES_DIR / (rule + ".json")
    if not file.is_file() or file.is_symlink():
        return None
    try:
        data = json.loads(file.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return None
        return _digest(data)
    except (OSError, ValueError, TypeError):
        return None


def _issue_projection(collection, account, key):
    if not isinstance(collection, dict):
        return {"status": "unknown", "complete": False, "issues": []}
    complete = collection.get("complete") is True
    issues = collection.get("issues")
    if not isinstance(issues, list):
        complete = False
        issues = []
    if len(issues) > MAX_ISSUES:
        raise SnapshotError("Too many collection issues")
    safe = []
    for issue in issues:
        if not isinstance(issue, dict):
            complete = False
            continue
        scope = issue.get("scope")
        reason = issue.get("reason_code")
        status = issue.get("status")
        region = issue.get("region")
        if (status not in _ISSUE_STATUS or scope not in _installed_services() | {"assessment"}
                or not isinstance(reason, str) or not 1 <= len(reason) <= 2048):
            complete = False
            continue
        # Never copy an arbitrary exception-derived reason_code or Region string.
        # Keep the reason comparable by HMAC only, even if it contains identifiers.
        row = {"scope": scope, "status": status,
               "reason_token": _identity(key, account, scope, "collection", reason, "issue")}
        if isinstance(region, str) and re.fullmatch(
                r"(?:us|eu|ap|sa|ca|af|me|il|mx|cn)-(?:north|south|east|west|central|northeast|northwest|southeast|southwest)-[0-9]{1,2}", region):
            row["region"] = region
        safe.append(row)
    safe.sort(key=_canonical)
    if safe:
        complete = False
    return {
        "status": "observed_complete" if complete else "incomplete",
        "complete": complete, "issues": safe,
    }


def _finding_projection(source, account, service, rule, key):
    if not isinstance(source, dict):
        raise SnapshotError("Invalid finding")
    items = source.get("items")
    if not isinstance(items, list) or len(items) > MAX_IDENTITIES_PER_RULE:
        raise SnapshotError("Invalid finding item list")
    count = _integer(source.get("flagged_items"))
    if count != len(items):
        raise SnapshotError("Finding count mismatch")
    tokens = sorted(_identity(key, account, service, rule, item, "flagged")
                    for item in items)
    summary = source.get("evaluation_summary")
    if summary is None:
        counts = None
        unknown = []
        evidence_status = "unavailable"
    else:
        if not isinstance(summary, dict):
            raise SnapshotError("Invalid evaluation summary")
        raw_counts = summary.get("counts")
        if not isinstance(raw_counts, dict):
            raise SnapshotError("Missing evidence counts")
        counts = {part: _integer(raw_counts.get(part)) for part in _COUNTS}
        evidence_status = summary.get("assessment_status")
        if evidence_status not in _STATUS:
            raise SnapshotError("Invalid evidence assessment status")
        missing = summary.get("unknown_resources")
        if not isinstance(missing, list) or len(missing) > MAX_IDENTITIES_PER_RULE:
            raise SnapshotError("Invalid unknown resource identities")
        if len(missing) > counts["unknown"]:
            raise SnapshotError("Unknown path count exceeds unknown evidence")
        unknown = sorted(_identity(key, account, service, rule, item, "unknown")
                         for item in missing)
        if (evidence_status == "evaluated" and counts["unknown"] > 0):
            raise SnapshotError("Incomplete evidence mislabeled evaluated")
        if (evidence_status == "not_applicable" and
                counts["secure"] + counts["insecure"] > 0):
            raise SnapshotError("Evaluated evidence mislabeled not applicable")
    status = source.get("assessment_status")
    if status not in _STATUS:
        status = "unknown"
    return {
        "rule_definition_sha256": _rule_definition_digest(rule),
        "rule_verification": "definition_available" if _rule_definition_digest(rule) else "definition_unavailable",
        "assessment_status": status,
        "evidence_status": evidence_status,
        "flagged_items": count,
        "flagged_identity_tokens": tokens,
        "evidence_counts": counts,
        "unknown_identity_tokens": unknown,
        "verification_scope": "observed_finding_evidence_only",
        "effective_permission_verified": False,
        "compliance_verified": False,
    }


def export_evidence_snapshot(results, key):
    """Return an authenticated, safe-by-construction projection of RESULTS."""
    key = _checked_key(key)
    if not isinstance(results, dict) or not isinstance(results.get("services"), dict):
        raise SnapshotError("Invalid Scout RESULTS structure")
    version = results.get("report_schema_version", 0)
    if type(version) is not int or version not in (0, 1):
        raise SnapshotError("Unsupported Scout RESULTS version")
    account = _account_scope(results)
    services = results["services"]
    findings = {}
    total = 0
    for service, data in sorted(services.items()):
        _name(service)
        if service not in _installed_services():
            raise SnapshotError("Unrecognized AWS service name")
        if data is None:
            continue
        if not isinstance(data, dict):
            raise SnapshotError("Invalid AWS service inventory")
        registered = data.get("findings", {})
        if not isinstance(registered, dict):
            raise SnapshotError("Invalid findings inventory")
        if registered:
            rows = {}
            for raw_rule, record in sorted(registered.items()):
                _name(raw_rule)
                total += 1
                if total > MAX_RULES:
                    raise SnapshotError("Too many rules for snapshot")
                # Unknown/custom rule keys may themselves contain sensitive
                # customer naming. Pseudonymize rather than publish them.
                rule = (raw_rule if _rule_definition_digest(raw_rule) is not None else
                        "unregistered-" + _identity(key, account, service, "custom",
                                                    raw_rule, "rule")[5:])
                rows[rule] = _finding_projection(record, account, service, rule, key)
            findings[service] = rows

    body = {
        "format": SCHEMA,
        "schema_version": VERSION,
        "source_results_schema_version": version,
        "scanner_version": SCOUT_VERSION,
        "key_id": hmac.new(key, b"scoutsuite-p4f-key-id", hashlib.sha256).hexdigest()[:20],
        "source": "evaluated_results_only",
        "replay_contract": "observation_aggregation_not_rule_reevaluation",
        "collection": _issue_projection(results.get("collection_status"), account, key),
        "findings": findings,
    }
    serialized = _canonical(body)
    result = dict(body)
    result["integrity"] = {
        "sha256": hashlib.sha256(serialized).hexdigest(),
        "hmac_sha256": hmac.new(key, b"scoutsuite-p4f-v1\x00" + serialized,
                                hashlib.sha256).hexdigest(),
    }
    return result


def verify_evidence_snapshot(snapshot, key, *, check_rule_drift=True):
    """Verify HMAC, strict model and current rule-definition versions.

    NEVER calls AWS or evaluates changed rule predicates from absent inputs.
    """
    key = _checked_key(key)
    if not isinstance(snapshot, dict):
        raise SnapshotError("Malformed evidence snapshot")
    if set(snapshot) != {
            "format", "schema_version", "source_results_schema_version",
            "scanner_version", "key_id", "source", "replay_contract",
            "collection", "findings", "integrity"}:
        raise SnapshotError("Unexpected snapshot fields")
    if snapshot.get("format") != SCHEMA or snapshot.get("schema_version") != VERSION:
        raise SnapshotError("Unsupported evidence snapshot schema")
    if snapshot.get("source") != "evaluated_results_only" or snapshot.get(
            "replay_contract") != "observation_aggregation_not_rule_reevaluation":
        raise SnapshotError("Unsupported replay contract")
    expected_id = hmac.new(key, b"scoutsuite-p4f-key-id", hashlib.sha256).hexdigest()[:20]
    if not hmac.compare_digest(str(snapshot.get("key_id")), expected_id):
        raise SnapshotError("Identity key mismatch")
    integrity = snapshot["integrity"]
    if not isinstance(integrity, dict) or set(integrity) != {"sha256", "hmac_sha256"}:
        raise SnapshotError("Invalid integrity envelope")
    body = {k: v for k, v in snapshot.items() if k != "integrity"}
    encoded = _canonical(body)
    if not hmac.compare_digest(str(integrity["sha256"]), hashlib.sha256(encoded).hexdigest()):
        raise SnapshotError("Snapshot digest mismatch")
    expected = hmac.new(key, b"scoutsuite-p4f-v1\x00" + encoded, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(str(integrity["hmac_sha256"]), expected):
        raise SnapshotError("Snapshot signature mismatch")
    collection = snapshot.get("collection")
    if not isinstance(collection, dict) or set(collection) != {"status", "complete", "issues"}:
        raise SnapshotError("Invalid collection envelope")
    if collection["status"] not in ("observed_complete", "incomplete") or type(collection["complete"]) is not bool:
        raise SnapshotError("Invalid collection status")
    issues = collection["issues"]
    if not isinstance(issues, list) or len(issues) > MAX_ISSUES:
        raise SnapshotError("Invalid issue inventory")
    for issue in issues:
        if not isinstance(issue, dict) or not {"scope", "status", "reason_token"} <= set(issue):
            raise SnapshotError("Invalid issue observation")
        if issue["scope"] not in _installed_services() | {"assessment"} or issue["status"] not in _ISSUE_STATUS:
            raise SnapshotError("Invalid issue scope")
        if not isinstance(issue["reason_token"], str) or not re.fullmatch(r"hmac:[0-9a-f]{40}", issue["reason_token"]):
            raise SnapshotError("Invalid issue token")
    findings = snapshot.get("findings")
    if not isinstance(findings, dict):
        raise SnapshotError("Invalid finding envelope")
    total, unknown, changed, missing = 0, 0, [], []
    for service, rules in sorted(findings.items()):
        _name(service)
        if service not in _installed_services():
            raise SnapshotError("Unrecognized service scope")
        if not isinstance(rules, dict):
            raise SnapshotError("Invalid service findings")
        for rule, row in sorted(rules.items()):
            _name(rule)
            total += 1
            if total > MAX_RULES or not isinstance(row, dict):
                raise SnapshotError("Invalid rule observations")
            if set(row) != {
                    "rule_definition_sha256", "rule_verification", "assessment_status",
                    "evidence_status", "flagged_items", "flagged_identity_tokens",
                    "evidence_counts", "unknown_identity_tokens", "verification_scope",
                    "effective_permission_verified", "compliance_verified"}:
                raise SnapshotError("Invalid finding evidence fields")
            flags = row["flagged_identity_tokens"]
            ids = row["unknown_identity_tokens"]
            if not isinstance(flags, list) or not isinstance(ids, list):
                raise SnapshotError("Invalid identity token list")
            if len(flags) > MAX_IDENTITIES_PER_RULE or len(ids) > MAX_IDENTITIES_PER_RULE:
                raise SnapshotError("Too many identity observations")
            if (any(not isinstance(x, str) or not re.fullmatch(r"hmac:[0-9a-f]{40}", x)
                    for x in flags + ids) or
                    flags != sorted(flags) or ids != sorted(ids)):
                raise SnapshotError("Invalid identity token")
            if row["flagged_items"] != len(flags):
                raise SnapshotError("Snapshot finding count mismatch")
            if row["verification_scope"] != "observed_finding_evidence_only" or (
                    row["compliance_verified"] is not False or
                    row["effective_permission_verified"] is not False):
                raise SnapshotError("Unsupported verification claims")
            counts = row["evidence_counts"]
            if counts is None:
                if row["evidence_status"] != "unavailable" or ids:
                    raise SnapshotError("Missing evidence must be unknown")
                unknown += 1
            else:
                if not isinstance(counts, dict) or set(counts) != set(_COUNTS):
                    raise SnapshotError("Invalid evidence categories")
                for count in counts.values():
                    _integer(count)
                if len(ids) > counts["unknown"]:
                    raise SnapshotError("Invalid unknown evidence count")
                if counts["unknown"]:
                    unknown += 1
                if row["evidence_status"] == "evaluated" and counts["unknown"] > 0:
                    raise SnapshotError("Evidence cannot be fully evaluated")
                if (row["evidence_status"] == "not_applicable" and
                        counts["secure"] + counts["insecure"]):
                    raise SnapshotError("Invalid not applicable claim")
            if row["assessment_status"] not in _STATUS or row["evidence_status"] not in _STATUS:
                raise SnapshotError("Invalid evidence status")
            recorded = row["rule_definition_sha256"]
            if row["rule_verification"] not in (
                    "definition_available", "definition_unavailable"):
                raise SnapshotError("Invalid rule verification status")
            if (recorded is None) != (row["rule_verification"] == "definition_unavailable"):
                raise SnapshotError("Inconsistent rule availability")
            if recorded is not None and not (
                    isinstance(recorded, str) and re.fullmatch(r"[0-9a-f]{64}", recorded)):
                raise SnapshotError("Invalid rule digest")
            current = _rule_definition_digest(rule)
            if check_rule_drift:
                if recorded is None or current is None:
                    missing.append(service + "." + rule)
                elif not hmac.compare_digest(recorded, current):
                    changed.append(service + "." + rule)
    state = "verified_observations"
    if changed:
        state = "rule_definition_drift"
    elif missing:
        state = "rule_definition_unavailable"
    # Snapshot verification *never* means current security config is safe.
    return {"replay_status": state, "snapshot_verified": True,
            "rules_observed": total, "rules_with_unknown_evidence": unknown,
            "rules_with_changed_definitions": changed,
            "rules_with_unavailable_definitions": missing,
            "rule_conditions_reexecuted": False, "cloud_api_calls": 0,
            "effective_permission_verified": False, "compliance_verified": False}


def diff_evidence_snapshots(before, after, key):
    """Compare HMAC-pseudonymized observed findings; never expose raw paths."""
    verify_evidence_snapshot(before, key, check_rule_drift=False)
    verify_evidence_snapshot(after, key, check_rule_drift=False)
    if before["key_id"] != after["key_id"]:
        raise SnapshotError("Snapshot identity keys do not match")
    lhs = {(service, rule): row for service, rules in before["findings"].items()
           for rule, row in rules.items()}
    rhs = {(service, rule): row for service, rules in after["findings"].items()
           for rule, row in rules.items()}
    result = []
    for service, rule in sorted(set(lhs) | set(rhs)):
        first = lhs.get((service, rule))
        second = rhs.get((service, rule))
        previous = set(first["flagged_identity_tokens"]) if first else set()
        current = set(second["flagged_identity_tokens"]) if second else set()
        difference = {
            "service": service, "rule": rule,
            "new_tokens": sorted(current - previous),
            "resolved_tokens": sorted(previous - current),
            "rule_present_before": first is not None,
            "rule_present_after": second is not None,
            "observation_status_before": first["evidence_status"] if first else "unavailable",
            "observation_status_after": second["evidence_status"] if second else "unavailable",
            "definition_changed": (
                first is not None and second is not None and
                first["rule_definition_sha256"] != second["rule_definition_sha256"]),
        }
        if (difference["new_tokens"] or difference["resolved_tokens"] or
                difference["observation_status_before"] != difference["observation_status_after"]
                or difference["definition_changed"] or
                first is None or second is None):
            result.append(difference)
    return {"comparison_scope": "observed_pseudonymized_findings_only",
            "key_id": before["key_id"], "changes": result,
            "rule_conditions_reexecuted": False}
