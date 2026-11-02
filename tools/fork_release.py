"""Fork-only release metadata, endpoint matrix, installed-env SBOM and checksums.

Run only after verified wheel/sdist build and installed-artifact smoke. No cloud APIs.
The endpoint matrix is botocore model metadata, NOT tested regional availability.
"""
import argparse
import hashlib
import importlib.metadata as metadata
import json
from pathlib import Path
import re
import zipfile

VERSION = "5.14.0+romanoff5.m10rc1"
TAG = "fork-v5.14.0-m10-rc1"
REPO = "romanoff5/ScoutSuite"
M10 = {
    "accessanalyzer": "accessanalyzer", "guardduty": "guardduty",
    "securityhub": "securityhub", "organizations": "organizations",
    "inspector2": "inspector2", "ecr": "ecr", "ecs": "ecs", "eks": "eks",
    "wafv2": "wafv2", "backup": "backup", "identitycenter": "sso-admin",
    "networkfirewall": "network-firewall", "macie": "macie2",
    "ssm": "ssm", "bedrock": "bedrock",
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, document):
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def generate(root, dist, sha):
    assert re.fullmatch(r"[0-9a-f]{40}", sha), "Require full reviewed release git SHA"
    assert (root / "ScoutSuite/__init__.py").is_file()
    assert f"__version__ = '{VERSION}'" in (root / "ScoutSuite/__init__.py").read_text()
    assert (root / "docs/releases" / (TAG + ".md")).is_file()

    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    assert len(wheels) == len(sdists) == 1, "One wheel and one sdist are required"
    wheel, sdist = wheels[0], sdists[0]
    assert wheel.name.lower() == f"scoutsuite-{VERSION}-py3-none-any.whl"
    assert sdist.name.lower() == f"scoutsuite-{VERSION}.tar.gz"
    with zipfile.ZipFile(wheel) as zf:
        metadata_names = [name for name in zf.namelist() if name.endswith(".dist-info/METADATA")]
        assert len(metadata_names) == 1
        from email.parser import Parser
        package_info = Parser().parsestr(zf.read(metadata_names[0]).decode("utf-8"))
    assert package_info["Version"] == VERSION

    # Dependency metadata from the built wheel, not unreviewed requirements parsing.
    declared = sorted(package_info.get_all("Requires-Dist", []))
    try:
        import botocore.session
    except ImportError as error:
        raise RuntimeError("botocore is required to record an endpoint model matrix") from error
    session = botocore.session.get_session()
    partitions = session.get_available_partitions()
    regions = {
        service: {
            partition: sorted(session.get_available_regions(sdk_service, partition_name=partition))
            for partition in partitions
        }
        for service, sdk_service in M10.items()
    }
    aws = root / "ScoutSuite/providers/aws"
    default_rules = json.loads((aws / "rules/rulesets/default.json").read_text())["rules"]
    detailed_rules = json.loads((aws / "rules/rulesets/detailed.json").read_text())["rules"]
    catalog = json.loads((root / "tests/data/provider-catalogs.json").read_text())["aws"]
    assert set(M10) <= set(catalog["core_services"])
    assert len(default_rules) >= 150
    report = {
        "results_schema_version": 1,
        "legacy_results_schema": 0,
        "formats": ["JavaScript RESULTS", "SQLite RESULTS", "offline HTML"],
        "other_payloads": "EXCEPTIONS and ERRORS remain unversioned",
        "cis_foundations_7_1_0": "partial opt-in crosswalk, not compliance",
    }
    matrix = {
        "repository": REPO, "version": VERSION, "git_sha": sha,
        "matrix_meaning": "botocore advertised endpoints, not live API tests or assurance",
        "tested_ci": ["Windows 2022 / Python 3.11", "Windows 2022 / Python 3.14",
                      "Ubuntu 24.04 / Python 3.11", "Ubuntu 24.04 / Python 3.14"],
        "partitions": partitions,
        "partitions_validated_live": [],
        "supported_scope": "AWS offline/synthetic verified; no production AWS accounts tested",
        "aws_services": catalog["core_services"],
        "m10_sdk_model_regions": regions,
        "rules": {
            "default_count": len(default_rules),
            "detailed_count": len(detailed_rules),
            "m10_default_parity_missing": sorted(
                key for key in default_rules
                if key.split("-", 1)[0] in set(M10) | {"m10q", "m10s"}
                and key not in detailed_rules
            ),
            "default_rules": sorted(default_rules),
            "detailed_rules": sorted(detailed_rules),
        },
        "report": report,
        "deferred": ["Azure SDK modernization", "GCP SDK modernization",
                     "live coverage validation for each AWS partition/region",
                     "separately validated container image"],
    }
    assert not matrix["rules"]["m10_default_parity_missing"]
    write(dist / "matrix.json", matrix)

    # CycloneDX component inventory of installed candidate runtime; exact versions.
    packages = sorted(
        ((d.metadata["Name"], d.version) for d in metadata.distributions()
         if d.metadata["Name"] and d.metadata["Name"].lower() != "scoutsuite"),
        key=lambda pair: pair[0].lower()
    )
    sbom = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": {
            "type": "application", "name": "ScoutSuite", "version": VERSION,
            "purl": f"pkg:pypi/scoutsuite@{VERSION}"
        },
        "properties": [{"name": "scoutsuite:sbom-scope",
                        "value": "installed release-smoke environment; includes tooling; not complete dependency graph"}]},
        "components": [
            {"type": "library", "name": name, "version": version,
             "purl": f"pkg:pypi/{name.lower().replace('_', '-')}@{version}"}
            for name, version in packages
        ],
    }
    write(dist / "sbom.cdx.json", sbom)
    manifest = {
        "repository": REPO, "version": VERSION, "tag": TAG, "git_sha": sha,
        "wheel": wheel.name, "sdist": sdist.name,
        "wheel_sha256": digest(wheel), "sdist_sha256": digest(sdist),
        "direct_dependency_requirements": declared,
        "sbom_scope": "installed environment including release tooling",
        "container": "not built; no validated container release",
        "real_client_scans": "not run",
    }
    write(dist / "manifest.json", manifest)
    names = sorted(p for p in dist.iterdir() if p.is_file() and p.name != "SHA256SUMS")
    (dist / "SHA256SUMS").write_text(
        "".join(f"{digest(path)}  {path.name}\n" for path in names), encoding="utf-8")
    print(json.dumps({"sha": sha, "tag": TAG, "artifacts": [p.name for p in names]},
                     sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--sha", required=True)
    args = parser.parse_args()
    generate(args.root.resolve(), args.dist.resolve(), args.sha)
