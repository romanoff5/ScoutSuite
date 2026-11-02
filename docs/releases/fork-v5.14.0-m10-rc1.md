# ScoutSuite fork 5.14.0+romanoff5.m10rc1 — release candidate

Repository: romanoff5/ScoutSuite only. Tag: fork-v5.14.0-m10-rc1.
Not an upstream NCC Group or PyPI release. Stable Scout Suite 5.14.0
remains unchanged.

## Changelog since stable 5.14.0

- M01–M04: guarded offline CI, event-loop and local-isolation fixes, incomplete collection status.
- M05–M08: AWS modernization, report/browser offline safety and XSS tests.
- M09: deterministic schema-v1 reports, legacy v0 reader and partial opt-in CIS v7.1.0 crosswalk.
- M10: Inspector2, ECR/ECS/EKS, Access Analyzer, Security Hub, GuardDuty,
  Organizations/SCP, Identity Center, WAFv2, Backup, Network Firewall,
  Systems Manager, Macie and Bedrock in standard scan.
- Advanced S3 (Access Points, MRAP, Access Grants, directory buckets);
  CloudTrail organization account-by-Region coverage.
- M10-Q: EC2/Inspector, ECR/Inspector, S3/Backup, WAF/target correlations;
  ECR per-image scan evidence, bounded Backup history, WAF request metrics.
- M10 consolidation: 35 missing detailed rules restored and regression tests.
- M11: Python 3.11/3.14 and zero-warning compatibility.
- Task 14: fork wheel/sdist, SHA256SUMS, manifest, installed-env CycloneDX,
  regional/service/rule/report matrix and isolated Windows installer.

## Validation and caveats

Publication requires full Offline CI success for a master push on
Ubuntu/Windows Python 3.11/3.14 plus an independent wheel/sdist build,
installed wheel smoke, pip check and help CLI verification.
No real client AWS scanning is performed. Checksums are integrity evidence,
not independently signed provenance. Azure/GCP SDK modernization remains
deferred. Non-commercial AWS partitions and each region are not live tested;
botocore region metadata is not runtime availability. Inspector, Macie,
WAF and Backup operational assurance requires authorized live evidence.
No container image: no independent modernized image build/test gate.

See docs/releases/TASK14_INSTALL.md. Assets: wheel, sdist, SHA256SUMS,
manifest.json, matrix.json, sbom.cdx.json. Stable .venv-scout untouched.
