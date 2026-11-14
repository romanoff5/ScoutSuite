"""P4-F2: explicitly allowlisted, privacy-preserving semantic AWS rule replay.

Separate from normal Scout RESULTS and HTML. This module does NOT modify report
serialization or cloud inventory; it projects only predefined safe enum values,
HMAC-pseudonymizes resource paths, and reexecutes current supported JSON conditions
via ScoutSuite's own recursive rule evaluator. No SDK, auth, network or subprocess.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from types import SimpleNamespace

from ScoutSuite import __version__ as SCOUT_VERSION
from ScoutSuite.core.evidence_snapshot import (
    SnapshotError, _account_scope, _canonical, _checked_key, _identity,
    _installed_services, _rule_definition_digest,
)
from ScoutSuite.core.utils import recurse

FORMAT = "scoutsuite-semantic-facts"
VERSION = 1
LIMIT = 100000
SAFE_ASSESSMENT = frozenset(("incomplete", "evaluated", "not_applicable", "review",
                              "unknown", "unavailable"))
HMAC_RE = re.compile(r"^hmac:[a-f0-9]{40}$")


@dataclass(frozen=True)
class Adapter:
    service: str
    path: str
    field: str
    allowed: frozenset[str]


# Explicit adapters, not arbitrary source-field selection. Adding a new rule
# requires a reviewed adapter and positive + negative rule-engine tests.
ADAPTERS = {
    "ec2-instance-imdsv1-enabled": Adapter(
        "ec2", "ec2.regions.id.vpcs.id.instances.id.imds_v2_status",
        "this", frozenset(("required", "optional", "disabled", "unknown"))),
    "ec2-account-imdsv2-not-required-default": Adapter(
        "ec2", "ec2.regions.id.regional_settings.id",
        "account_imds_default_status",
        frozenset(("required", "not_required", "unknown"))),
    "cloudwatch-log-group-unlimited-retention": Adapter(
        "cloudwatch", "cloudwatch.regions.id.log_groups.id",
        "retention_status",
        frozenset(("unlimited", "configured", "unknown"))),
    "cloudwatch-log-group-no-customer-kms": Adapter(
        "cloudwatch", "cloudwatch.regions.id.log_groups.id",
        "customer_kms_status",
        frozenset(("customer_kms", "aws_managed", "unknown"))),
    "rds-proxy-require-tls-disabled": Adapter(
        "rds", "rds.regions.id.proxies.id",
        "tls_status",
        frozenset(("enabled", "disabled", "unknown"))),
}


def _expected_rule(rule_id):
    """Use installed local definition, never arbitrary payload-provided code."""
    rule_digest = _rule_definition_digest(rule_id)
    if rule_digest is None:
        return None, None
    from ScoutSuite.core.evidence_snapshot import _RULES_DIR
    try:
        data = json.loads((_RULES_DIR / (rule_id + ".json")).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None, None
    if not isinstance(data, dict):
        return None, None
    return data, rule_digest


def _extract_collection(results):
    collection = results.get("collection_status")
    if not isinstance(collection, dict):
        return "incomplete"
    if collection.get("complete") is True and collection.get("status") == "success":
        return "observed_complete"
    return "incomplete"


def _walk(root, path):
    """Return (original internal resource path, raw object) pairs, or incomplete.

    All original identifiers remain in memory only; they are NEVER serialized.
    An empty observed dictionary of resources is a valid empty inventory.
    """
    segments = path.split(".")
    observed = []
    missing = False

    def recurse_source(node, remaining, prefix):
        nonlocal missing
        if not remaining:
            observed.append((".".join(prefix), node))
            return
        head, *tail = remaining
        if not isinstance(node, dict):
            missing = True
            return
        if head == "id":
            for key, child in node.items():
                if not isinstance(key, (str, int)) or isinstance(key, bool):
                    missing = True
                    continue
                recurse_source(child, tail, prefix + [str(key)])
        elif head in node:
            recurse_source(node[head], tail, prefix + [head])
        else:
            missing = True

    recurse_source(root, segments, [])
    return observed, missing


def _safe_value(raw, adapter):
    if adapter.field == "this":
        value = raw
    elif isinstance(raw, dict):
        value = raw.get(adapter.field)
    else:
        value = None
    # Do not even call str() on unknown source objects.
    return value if type(value) is str and value in adapter.allowed else "unknown"


def _make_body(results, key):
    if not isinstance(results, dict) or not isinstance(results.get("services"), dict):
        raise SnapshotError("Invalid Scout RESULTS")
    source_version = results.get("report_schema_version", 0)
    if type(source_version) is not int or source_version not in (0, 1):
        raise SnapshotError("Unsupported RESULTS schema")
    account = _account_scope(results)
    source_services = results["services"]
    if any(name not in _installed_services() for name in source_services):
        raise SnapshotError("Invalid AWS service scope")
    entries = {}
    for rule_id, adapter in sorted(ADAPTERS.items()):
        definition, digest = _expected_rule(rule_id)
        if not definition or definition.get("path") != adapter.path:
            raise SnapshotError("Supported rule definition unavailable")
        service_root = source_services.get(adapter.service)
        # Existing real RESULTS store resources at services.<service>...
        if not isinstance(service_root, dict):
            found, missing = [], True
        else:
            found, missing = _walk({adapter.service: service_root}, adapter.path)
        if len(found) > LIMIT:
            raise SnapshotError("Too many semantic facts")
        facts = []
        for raw_path, raw in found:
            facts.append({
                "token": _identity(key, account, adapter.service, rule_id,
                                   raw_path, "semantic-fact"),
                "value": _safe_value(raw, adapter),
            })
        facts.sort(key=lambda row: row["token"])
        if len({row["token"] for row in facts}) != len(facts):
            raise SnapshotError("Duplicate semantic identity")
        recorded_findings = service_root.get("findings", {}) if isinstance(service_root, dict) else {}
        prior = recorded_findings.get(rule_id) if isinstance(recorded_findings, dict) else None
        prior_status = prior.get("assessment_status") if isinstance(prior, dict) else None
        if prior_status not in SAFE_ASSESSMENT:
            prior_status = "unavailable"
        entries[rule_id] = {
            "source_rule_sha256": digest,
            "scope": "partial" if missing else "observed",
            "source_assessment_status": prior_status,
            "facts": facts,
        }
    return {
        "format": FORMAT,
        "schema_version": VERSION,
        "scanner_version": SCOUT_VERSION,
        "source_results_schema_version": source_version,
        "source_collection_status": _extract_collection(results),
        "replay_contract": "allowlisted_semantic_rule_reevaluation",
        "key_id": hmac.new(key, b"scoutsuite-p4f-key-id", hashlib.sha256).hexdigest()[:20],
        "rules": entries,
    }


def export_semantic_facts(results, key):
    """Return signed bounded semantic facts, never raw IDs/ARNs/names."""
    key = _checked_key(key)
    body = _make_body(results, key)
    data = _canonical(body)
    return {**body, "integrity": {
        "sha256": hashlib.sha256(data).hexdigest(),
        "hmac_sha256": hmac.new(key, b"scoutsuite-p4f2-v1\x00" + data,
                                hashlib.sha256).hexdigest(),
    }}


def _validated_body(snapshot, key):
    key = _checked_key(key)
    if not isinstance(snapshot, dict) or set(snapshot) != {
            "format", "schema_version", "scanner_version", "source_results_schema_version",
            "source_collection_status", "replay_contract", "key_id", "rules", "integrity"}:
        raise SnapshotError("Invalid semantic envelope")
    if snapshot["format"] != FORMAT or snapshot["schema_version"] != VERSION:
        raise SnapshotError("Unsupported semantic snapshot schema")
    if type(snapshot["source_results_schema_version"]) is not int or snapshot[
            "source_results_schema_version"] not in (0, 1):
        raise SnapshotError("Unsupported source schema")
    if (not isinstance(snapshot["scanner_version"], str) or
            len(snapshot["scanner_version"]) > 80 or
            snapshot["source_collection_status"] not in ("incomplete", "observed_complete") or
            snapshot["replay_contract"] != "allowlisted_semantic_rule_reevaluation"):
        raise SnapshotError("Invalid semantic metadata")
    expected_id = hmac.new(key, b"scoutsuite-p4f-key-id", hashlib.sha256).hexdigest()[:20]
    if not isinstance(snapshot["key_id"], str) or not hmac.compare_digest(
            snapshot["key_id"], expected_id):
        raise SnapshotError("Snapshot identity key mismatch")
    integrity = snapshot["integrity"]
    if not isinstance(integrity, dict) or set(integrity) != {"sha256", "hmac_sha256"}:
        raise SnapshotError("Invalid semantic integrity envelope")
    body = {k: v for k, v in snapshot.items() if k != "integrity"}
    data = _canonical(body)
    expected_sha = hashlib.sha256(data).hexdigest()
    expected_mac = hmac.new(key, b"scoutsuite-p4f2-v1\x00" + data, hashlib.sha256).hexdigest()
    for name, expected in (("sha256", expected_sha), ("hmac_sha256", expected_mac)):
        value = integrity.get(name)
        if not isinstance(value, str) or not hmac.compare_digest(value, expected):
            raise SnapshotError("Semantic snapshot integrity mismatch")
    if not isinstance(snapshot["rules"], dict) or set(snapshot["rules"]) != set(ADAPTERS):
        raise SnapshotError("Semantic rule inventory mismatch")
    for rule_id, record in snapshot["rules"].items():
        adapter = ADAPTERS[rule_id]
        if not isinstance(record, dict) or set(record) != {
                "source_rule_sha256", "scope", "source_assessment_status", "facts"}:
            raise SnapshotError("Invalid semantic rule entry")
        digest = record["source_rule_sha256"]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise SnapshotError("Invalid rule origin digest")
        if record["scope"] not in ("observed", "partial") or record[
                "source_assessment_status"] not in SAFE_ASSESSMENT:
            raise SnapshotError("Invalid semantic status")
        facts = record["facts"]
        if not isinstance(facts, list) or len(facts) > LIMIT:
            raise SnapshotError("Invalid semantic fact inventory")
        tokens = []
        for item in facts:
            if not isinstance(item, dict) or set(item) != {"token", "value"}:
                raise SnapshotError("Invalid semantic fact entry")
            if not isinstance(item["token"], str) or not HMAC_RE.fullmatch(item["token"]):
                raise SnapshotError("Invalid pseudonymous token")
            if type(item["value"]) is not str or item["value"] not in adapter.allowed:
                raise SnapshotError("Unknown semantic fact value")
            tokens.append(item["token"])
        if tokens != sorted(set(tokens)):
            raise SnapshotError("Invalid semantic ordering")
    return body


def _safe_condition(definition, adapter):
    """Strict grammar gate before running *current* rule JSON conditions."""
    if definition.get("path") != adapter.path:
        return None
    conditions = definition.get("conditions")
    if not isinstance(conditions, list) or len(conditions) != 2 or conditions[0] != "and":
        return None
    check = conditions[1]
    if (not isinstance(check, list) or len(check) != 3 or
            check[0] != adapter.field or
            check[1] not in ("equal", "notEqual") or
            type(check[2]) is not str or check[2] not in adapter.allowed
            or check[2] == "unknown"):
        return None
    return conditions


def _synthetic_info(adapter, token, value):
    """Only safe enum values and pseudonymous dict keys reach the rule engine."""
    parts = adapter.path.split(".")
    root = {}
    cursor = root
    ids = [i for i, item in enumerate(parts) if item == "id"]
    last_id = ids[-1]
    for i, part in enumerate(parts):
        if part == "id":
            part = token if i == last_id else "scope-" + str(i)
        if i == len(parts) - 1:
            cursor[part] = value if adapter.field == "this" else {adapter.field: value}
        else:
            cursor = cursor.setdefault(part, {})
    return root


def replay_semantic_facts(snapshot, key):
    """Actually rerun allowlisted current JSON predicates; never call AWS."""
    _validated_body(snapshot, key)
    output = {}
    for rule_id, adapter in sorted(ADAPTERS.items()):
        record = snapshot["rules"][rule_id]
        definition, digest = _expected_rule(rule_id)
        grammar = _safe_condition(definition, adapter) if definition else None
        if grammar is None:
            output[rule_id] = {
                "status": "rule_not_replayable",
                "original_definition_sha256": record["source_rule_sha256"],
                "current_definition_sha256": digest,
                "predicate_changed": digest != record["source_rule_sha256"],
                "matched_tokens": [], "checked": 0,
                "unknown": len(record["facts"]), "conditions_reexecuted": False,
            }
            continue
        matched = []
        unknown = 0
        checked = 0
        for fact in record["facts"]:
            if fact["value"] == "unknown":
                unknown += 1
                continue
            observed = _synthetic_info(adapter, fact["token"], fact["value"])
            rule = SimpleNamespace(
                path=adapter.path, conditions=copy.deepcopy(grammar),
                checked_items=0)
            # Exact ScoutSuite condition evaluator; no fake decision function.
            hits = recurse(observed, observed, adapter.path.split("."), [], rule, False)
            checked += 1
            if hits:
                matched.append(fact["token"])
        partial = (
            snapshot["source_collection_status"] != "observed_complete"
            or record["scope"] != "observed" or unknown > 0 or
            record["source_assessment_status"] == "incomplete")
        output[rule_id] = {
            "status": "partial" if partial else "replayed",
            "original_definition_sha256": record["source_rule_sha256"],
            "current_definition_sha256": digest,
            "predicate_changed": digest != record["source_rule_sha256"],
            "matched_tokens": sorted(matched),
            "checked": checked,
            "unknown": unknown,
            "conditions_reexecuted": True,
        }
    return {
        "replay": "semantic_rule_reevaluation",
        "snapshot_verified": True,
        "rules": output,
        "cloud_api_calls": 0,
        "raw_resource_identifiers_available": False,
        "effective_permission_verified": False,
        "compliance_verified": False,
    }
