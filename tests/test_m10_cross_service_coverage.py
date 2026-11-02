"""M10-Q cross-service coverage checks: no SDK, no fabricated compliance PASS."""
import copy
import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock

from ScoutSuite.core.rule_evidence import (
    CLASSIFIERS, classify_m10q_ec2_inspector, classify_m10q_ecr_image_scanning,
    classify_m10q_s3_backup)
from ScoutSuite.providers.aws.resources.coverage_reconciliation import (
    reconcile_m10q_coverage, _enhanced_rules_match)

ROOT = Path(__file__).resolve().parents[1]
REGION = 'eu-central-1'
ACCOUNT = '000000000000'
OTHER = '111111111111'
EC2_ONE = 'i-00000000000000001'
EC2_TWO = 'i-00000000000000002'
EC2_THREE = 'i-00000000000000003'
REPO_ONE = f'arn:aws:ecr:{REGION}:{ACCOUNT}:repository/production'
REPO_TWO = f'arn:aws:ecr:{REGION}:{ACCOUNT}:repository/unknown'
BUCKET = 'company-backup'
BUCKET_ARN = f'arn:aws:s3:::{BUCKET}'
WAF = f'arn:aws:wafv2:{REGION}:{ACCOUNT}:regional/webacl/prod/1111'
ALB = f'arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/prod/123'
CF_ARN = f'arn:aws:cloudfront::{ACCOUNT}:distribution/E123'


def fixture():
    return {
        'ec2': {'regions': {REGION: {'vpcs': {'vpc-1': {'instances': {
            EC2_ONE: {'id': EC2_ONE, 'name': 'covered', 'State': {'Name': 'running'}},
            EC2_TWO: {'id': EC2_TWO, 'name': 'absent', 'State': {'Name': 'running'}},
            EC2_THREE: {'id': EC2_THREE, 'State': {'Name': 'terminated'}}}}}}}},
        'inspector2': {'regions': {REGION: {
            'coverage_summary': {'status': 'complete',
                                 'collected_records': 2, 'inspector_reported_records': 2},
            'coverage': {
                'a': {'id': 'a', 'resource_type': 'AWS_EC2_INSTANCE',
                      'resource_id': EC2_ONE, 'account_id': ACCOUNT,
                      'scan_type': 'PACKAGE', 'scan_status': 'ACTIVE'},
                'b': {'id': 'b', 'resource_type': 'AWS_ECR_REPOSITORY',
                      'resource_id': REPO_ONE, 'account_id': ACCOUNT,
                      'scan_type': 'ENHANCED', 'scan_status': 'INACTIVE'},
            }}}},
        'ecr': {'regions': {REGION: {
            'repositories': {
                'a': {'repository_name': 'production', 'repository_arn': REPO_ONE,
                      'image_scanning_configuration': {'scanOnPush': False}},
                'b': {'repository_name': 'unknown', 'repository_arn': REPO_TWO,
                      'image_scanning_configuration': {'scanOnPush': True}}},
            'registry_scanning': {REGION: {
                'scan_type': 'BASIC', 'registry_id': ACCOUNT, 'rules': []}},
        }}},
        's3': {'buckets': {'bucket-1': {
            'id': 'bucket-1', 'name': BUCKET,
            # Historical formatting from ScoutSuite's S3 parser: NOT a bucket ARN.
            'arn': f'arn:aws:s3:::*/{BUCKET}', 'region': REGION},
            'bucket-2': {
                'id': 'bucket-2', 'name': 'untouched',
                'arn': 'arn:aws:s3:::*/untouched', 'region': 'eu-west-2'}}},
        'backup': {'regions': {REGION: {
            'backup_inventory_status': {
                'protected_resources': 'complete', 'backup_jobs': 'complete'},
            'protected_resources': {}, 'backup_jobs': {},
        }}},
        'wafv2': {'regions': {REGION: {'web_acls': {
            'a': {'web_acl_arn': WAF, 'name': 'active',
                  'scope': 'REGIONAL', 'association_status': 'associated',
                  'association_scope_complete': True,
                  'associated_resources': [{'resource_type': 'ALB', 'resource_arn': ALB}]},
            'b': {'web_acl_arn': WAF+'-unused', 'name': 'unused',
                  'scope': 'REGIONAL', 'association_status': 'unused_candidate',
                  'unused_candidate': True, 'association_scope_complete': True,
                  'associated_resources': []},
        }}}},
        'elbv2': {'regions': {REGION: {'vpcs': {'vpc-1': {'lbs': {
            'alb': {'arn': ALB, 'name': 'prod', 'Type': 'application'},
        }}}}}},
        'cloudfront': {'distributions': {'cf-1': {
            'arn': CF_ARN, 'web_acl_id': WAF,
            'name': 'existing-distribution'}}},
    }


ALL = ['ec2', 'inspector2', 'ecr', 's3', 'backup', 'wafv2', 'elbv2', 'cloudfront']


def test_all_four_service_pairs_and_source_account_scope():
    data = fixture()
    sources = copy.deepcopy(data)
    result = reconcile_m10q_coverage(data, ALL, ACCOUNT)
    assert result['api_calls'] == 0
    assert result['resource_counts'] == {
        'ec2_inspector': 3, 'ecr_scanning': 2, 's3_backup': 2, 'waf_targets': 2}
    instances = data['ec2']['regions'][REGION]['vpcs']['vpc-1']['instances']
    assert instances[EC2_ONE]['m10q_inspector']['state'] == 'active_observed'
    assert instances[EC2_TWO]['m10q_inspector']['state'] == 'not_reported'
    assert instances[EC2_TWO]['m10q_inspector_not_reported'] is True
    assert instances[EC2_THREE]['m10q_inspector']['state'] == 'not_applicable'
    assert classify_m10q_ec2_inspector(instances[EC2_ONE]) == 'secure'
    assert classify_m10q_ec2_inspector(instances[EC2_TWO]) == 'insecure'
    assert classify_m10q_ec2_inspector(instances[EC2_THREE]) == 'not_applicable'
    repos = data['ecr']['regions'][REGION]['repositories']
    assert repos['a']['m10q_repository_scan_gap_candidate'] is True
    assert repos['b']['m10q_repository_scan_gap_candidate'] is False
    assert repos['a']['m10q_image_scanning']['image_level_scan_execution_verified'] is False
    assert repos['b']['m10q_image_scanning']['image_inventory_available'] is False
    assert classify_m10q_ecr_image_scanning(repos['a']) == 'insecure'
    assert classify_m10q_ecr_image_scanning(repos['b']) == 'unknown'
    buckets = data['s3']['buckets']
    assert buckets['bucket-1']['m10q_backup']['canonical_bucket_arn'] == BUCKET_ARN
    assert buckets['bucket-1']['m10q_backup']['state'] == 'not_reported'
    assert buckets['bucket-2']['m10q_backup']['state'] == 'unknown'
    assert classify_m10q_s3_backup(buckets['bucket-1']) == 'insecure'
    assert classify_m10q_s3_backup(buckets['bucket-2']) == 'unknown'
    acls = data['wafv2']['regions'][REGION]['web_acls']
    assert acls['a']['m10q_protected_targets']['state'] == 'independent_target_observed'
    assert acls['a']['m10q_protected_targets']['verified_resource_arns'] == [ALB]
    assert acls['b']['m10q_protected_targets']['state'] == 'no_supported_association_observed'
    assert acls['b']['unused_candidate'] is True  # Existing finding; no duplicate.
    assert acls['b']['m10q_protected_targets']['traffic_routing_through_waf_verified'] is False
    # No source identifiers or other fields rewritten by correlation.
    for service in ('backup', 'elbv2', 'cloudfront'):
        assert data[service] == sources[service]
    assert data['s3']['buckets']['bucket-1']['arn'] == sources['s3']['buckets']['bucket-1']['arn']


def test_backup_recovery_point_and_completed_job_are_evidence_not_schedule_proof():
    data = fixture()
    backup = data['backup']['regions'][REGION]
    backup['protected_resources'] = {'one': {
        'ResourceArn': BUCKET_ARN, 'ResourceName': BUCKET}}
    backup['backup_jobs'] = {'job': {
        'BackupJobId': 'job-1', 'ResourceArn': BUCKET_ARN,
        'State': 'COMPLETED',
        'CompletionDate': datetime(2026, 10, 31, tzinfo=timezone.utc)}}
    reconcile_m10q_coverage(data, ALL, ACCOUNT)
    evidence = data['s3']['buckets']['bucket-1']['m10q_backup']
    assert evidence['state'] == 'recovery_and_job_observed'
    assert evidence['completed_job_ids'] == ['job-1']
    assert evidence['last_completed_job_at'] == '2026-10-31T00:00:00+00:00'
    assert evidence['ongoing_schedule_verified'] is False
    assert data['s3']['buckets']['bucket-1']['m10q_backup_evidence_gap'] is False
    assert classify_m10q_s3_backup(data['s3']['buckets']['bucket-1']) == 'unknown'
    del backup['backup_jobs']['job']
    reconcile_m10q_coverage(data, ALL, ACCOUNT)
    assert data['s3']['buckets']['bucket-1']['m10q_backup']['state'] == 'partial_evidence'
    assert data['s3']['buckets']['bucket-1']['m10q_backup_evidence_gap'] is True


def test_deferred_backup_job_history_requires_verified_empty_current_inventory():
    deferred = 'deferred_no_current_backup_inventory'

    def reconcile(protected_status='complete', protected=None, activity='no_current_resources_observed'):
        data = fixture()
        region = data['backup']['regions'][REGION]
        region['backup_inventory_status'] = {
            'protected_resources': protected_status, 'backup_jobs': deferred}
        region['protected_resources'] = protected or {}
        region['backup_jobs'] = {}
        if activity is not None:
            region['backup_service_activity'] = activity
        reconcile_m10q_coverage(data, ALL, ACCOUNT)
        return data['s3']['buckets']['bucket-1']

    bucket = reconcile()
    assert bucket['m10q_backup']['state'] == 'not_reported'
    assert bucket['m10q_backup']['job_history_status'] == 'not_assessed'
    assert bucket['m10q_backup_evidence_gap'] is True
    assert classify_m10q_s3_backup(bucket) == 'insecure'
    # Fail closed: a deferred marker without the verified-empty census, or
    # alongside contradictory inventory, never becomes a negative finding.
    for kwargs in ({'activity': None}, {'activity': 'not_determined'},
                   {'protected_status': 'partial'},
                   {'protected': {'rp': {'ResourceArn': BUCKET_ARN}}}):
        bucket = reconcile(**kwargs)
        assert bucket['m10q_backup']['state'] == 'unknown', kwargs
        assert bucket['m10q_backup']['reasons'] == ['backup_inventory_incomplete'], kwargs
        assert bucket['m10q_backup_evidence_gap'] is False, kwargs
        assert classify_m10q_s3_backup(bucket) == 'unknown', kwargs


def test_deferred_home_region_still_honours_cross_region_recovery_point():
    data = fixture()
    data['backup']['regions'][REGION].update({
        'backup_inventory_status': {'protected_resources': 'complete',
                                    'backup_jobs': 'deferred_no_current_backup_inventory'},
        'backup_service_activity': 'no_current_resources_observed',
        'plans': {}, 'vaults': {}, 'restore_testing_plans': {}})
    data['backup']['regions']['eu-west-1'] = {
        'backup_inventory_status': {'protected_resources': 'complete', 'backup_jobs': 'complete'},
        'protected_resources': {'rp': {'ResourceArn': BUCKET_ARN}}, 'backup_jobs': {}}
    reconcile_m10q_coverage(data, ALL, ACCOUNT)
    bucket = data['s3']['buckets']['bucket-1']
    assert bucket['m10q_backup']['state'] == 'cross_region_evidence_only'
    assert bucket['m10q_backup']['cross_region_evidence_regions'] == ['eu-west-1']
    assert bucket['m10q_backup_evidence_gap'] is False


def test_complete_backup_job_history_status_is_recorded():
    data = fixture()
    reconcile_m10q_coverage(data, ALL, ACCOUNT)
    assert data['s3']['buckets']['bucket-1']['m10q_backup']['job_history_status'] == 'complete'
    assert data['s3']['buckets']['bucket-2']['m10q_backup']['job_history_status'] == 'unknown'


def test_denied_partial_inspector_or_backup_cannot_create_negative_finding():
    data = fixture()
    data['inspector2']['regions'][REGION]['coverage_summary']['status'] = 'partial'
    data['backup']['regions'][REGION]['backup_inventory_status']['backup_jobs'] = 'partial'
    reconcile_m10q_coverage(data, ALL, ACCOUNT)
    absent = data['ec2']['regions'][REGION]['vpcs']['vpc-1']['instances'][EC2_TWO]
    assert absent['m10q_inspector']['state'] == 'unknown'
    assert not absent['m10q_inspector_not_reported']
    assert data['ecr']['regions'][REGION]['repositories']['a'][
        'm10q_repository_scan_gap_candidate'] is False
    assert data['s3']['buckets']['bucket-1']['m10q_backup']['state'] == 'unknown'
    assert data['s3']['buckets']['bucket-1']['m10q_backup_evidence_gap'] is False
    data = fixture()
    reconcile_m10q_coverage(data, ALL, OTHER)
    assert data['ec2']['regions'][REGION]['vpcs']['vpc-1']['instances'][EC2_ONE][
        'm10q_inspector']['state'] == 'unknown'


def test_scoped_service_selection_and_local_replay_no_api_calls():
    data = fixture()
    sdk = Mock()
    data['inspector2']['client'] = sdk
    original = copy.deepcopy(data['inspector2']['regions'])
    summary = reconcile_m10q_coverage(data, ['ec2'], ACCOUNT)
    assert summary['resource_counts']['ec2_inspector'] == 3
    assert data['ec2']['regions'][REGION]['vpcs']['vpc-1']['instances'][EC2_ONE][
        'm10q_inspector']['state'] == 'unknown'
    assert 'm10q_image_scanning' not in data['ecr']['regions'][REGION]['repositories']['a']
    assert data['inspector2']['regions'] == original
    sdk.assert_not_called()
    assert reconcile_m10q_coverage({}, [], 'local-account-id')['api_calls'] == 0


def test_ecr_enhanced_scanning_rules_are_not_per_image_success():
    cfg = {'scan_type': 'ENHANCED', 'rules': [{
        'repositoryFilters': [{'filterType': 'WILDCARD', 'filter': 'prod*'}]}]}
    assert _enhanced_rules_match(cfg, 'production') is True
    assert _enhanced_rules_match(cfg, 'test') is False
    assert _enhanced_rules_match({'rules': []}, 'production') is None
    assert _enhanced_rules_match({'rules': [{
        'repositoryFilters': [{'filterType': 'UNKNOWN', 'filter': '*'}]}]},
        'production') is None
    data = fixture()
    data['ecr']['regions'][REGION]['registry_scanning'][REGION] = {
        **cfg, 'registry_id': ACCOUNT}
    reconcile_m10q_coverage(data, ALL, ACCOUNT)
    repo = data['ecr']['regions'][REGION]['repositories']['a']
    assert repo['m10q_image_scanning']['enhanced_rule_match'] is True
    assert repo['m10q_image_scanning']['image_level_scan_execution_verified'] is False


def test_waf_association_without_independent_target_inventory_is_not_traffic_proof():
    data = fixture()
    reconcile_m10q_coverage(data, ['wafv2'], ACCOUNT)
    acls = data['wafv2']['regions'][REGION]['web_acls']
    assert acls['a']['m10q_protected_targets']['state'] == 'waf_association_only'
    assert acls['a']['m10q_protected_targets']['verified_resource_arns'] == []
    assert acls['b']['m10q_protected_targets']['state'] == 'no_supported_association_observed'
    assert acls['b']['m10q_protected_targets']['independent_target_inventory_selected'] == {
        'alb': False, 'cloudfront': False, 'api_gateway': False}


def test_offline_default_rules_evidence_policy_and_html_escaping():
    names = (
        'm10q-ec2-not-reported-by-inspector2.json',
        'm10q-ecr-image-scanning-gap.json',
        'm10q-s3-backup-evidence-gap.json')
    rules = json.loads((ROOT / 'ScoutSuite/providers/aws/rules/rulesets/default.json')
                       .read_text(encoding='utf-8'))['rules']
    for name in names:
        assert rules[name][0]['enabled'] is True
        definition = json.loads((
            ROOT / 'ScoutSuite/providers/aws/rules/findings' / name)
            .read_text(encoding='utf-8'))
        assert definition['evidence_policy'] in CLASSIFIERS
    for template in (
        'services.ec2.regions.id.vpcs.id.instances.html',
        'services.ecr.regions.id.repositories.html',
        'services.s3.buckets.html',
        'services.wafv2.regions.id.web_acls.html',
    ):
        value = (ROOT / 'ScoutSuite/output/data/html/partials/aws'
                 / template).read_text(encoding='utf-8')
        assert '<h4>Cross-service coverage (M10-Q)</h4>' in value
        assert 'm10q_' in value
