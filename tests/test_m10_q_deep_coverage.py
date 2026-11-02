"""M10-Q v2 regression: real S3 inventories, cross-region Backup and trust boundaries."""
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from ScoutSuite.core.rule_evidence import (
    CLASSIFIERS, classify_m10q_s3_target_reference)
from ScoutSuite.providers.aws.facade.s3 import S3Facade
from ScoutSuite.providers.aws.facade.s3_advanced import S3AdvancedFacade
from ScoutSuite.providers.aws.facade import s3_advanced as advanced_module
from ScoutSuite.providers.aws.resources.coverage_reconciliation import (
    reconcile_m10q_coverage)
from ScoutSuite.providers.aws.resources.coverage_reconciliation_deep import (
    _selection_for, _bucket_from_scope, _bucket_from_reference)

ROOT = Path(__file__).resolve().parents[1]
REGION = 'eu-central-1'
ACCOUNT = '000000000000'
ARN = 'arn:aws:s3:::alpha'


def fixture():
    return {'s3': {
        'bucket_inventory_status': 'complete',
        'buckets': {'a': {'id': 'a', 'name': 'alpha', 'region': REGION,
                          'arn': 'arn:aws:s3:::*/alpha'}},
        'advanced': {
            'coverage_status': 'complete',
            'regions': {REGION: {
                'coverage_status': 'complete',
                'collection': {'access_points': 'complete',
                               'directory_access_points': 'complete',
                               'directory_buckets': 'complete',
                               'access_grants_locations': 'complete',
                               'access_grants': 'complete'},
                'access_points': {
                    'point': {'Name': 'point', 'Bucket': 'alpha',
                              'BucketAccountId': ACCOUNT,
                              'policy_public': True,
                              'region': REGION},
                    'other': {'Name': 'other', 'Bucket': 'missing',
                              'BucketAccountId': ACCOUNT, 'region': REGION}},
                'directory_buckets': {'dir': {
                    'Name': 'dir--use1-az2--x-s3', 'region': REGION}},
                'directory_access_points': {'dap': {
                    'Name': 'dap', 'Bucket': 'dir--use1-az2--x-s3',
                    'BucketAccountId': ACCOUNT, 'region': REGION}},
                'access_grants_locations': {'loc': {
                    'AccessGrantsLocationId': 'loc-001',
                    'AccessGrantsLocationArn': f'arn:aws:s3:{REGION}:{ACCOUNT}:access-grants/location/loc-001',
                    'LocationScope': 's3://alpha/restricted/',
                    'region': REGION}},
                'access_grants': {'grant': {
                    'AccessGrantArn': f'arn:aws:s3:{REGION}:{ACCOUNT}:access-grants/grant/gr-001',
                    'AccessGrantsLocationId': 'loc-001',
                    'GrantScope': 's3://alpha/restricted/',
                    'Permission': 'READWRITE', 'region': REGION}},
            }},
            'multi_region_access_points': {'mr': {
                'Name': 'multi', 'detail_verified': True,
                'policy_public': False,
                'Regions': [{'Bucket': 'alpha', 'Region': REGION}]}}}},
            'backup': {'regions': {REGION: {
                'backup_inventory_status': {
                    'protected_resources': 'complete', 'backup_jobs': 'complete'},
                'protected_resources': {}, 'backup_jobs': {}, 'plans': {
                    'p1': {'backup_plan_id': 'bp-1',
                           'selection_collection_complete': True,
                           'selections': [{'BackupSelection': {
                               'Resources': [ARN], 'NotResources': []}}]},
                },
                'restore_testing_plans': {},
            }}}}


def test_s3_advanced_six_resource_types_and_safe_relations():
    data = fixture()
    baseline_arn = data['s3']['buckets']['a']['arn']
    results = reconcile_m10q_coverage(data, ['s3', 'backup'], ACCOUNT)
    status = results['deep']['s3_advanced']
    assert status['status'] == 'complete'
    assert status['counts']['access_points'] == 2
    assert status['counts']['directory_access_points'] == 1
    assert status['counts']['directory_buckets'] == 1
    assert status['counts']['multi_region_access_points'] == 1
    assert status['counts']['access_grants'] == 1
    bucket = data['s3']['buckets']['a']
    assert bucket['arn'] == baseline_arn
    assert bucket['m10q_s3_public_access_point_count'] == 1
    assert {'access_points', 'access_grants_location', 'access_grant',
            'multi_region_access_point'} == {
                entry['kind'] for entry in bucket['m10q_s3_entrypoints']}
    region = data['s3']['advanced']['regions'][REGION]
    ap = region['access_points']['point']
    missing = region['access_points']['other']
    assert ap['m10q_bucket_target']['status'] == 'observed_local_bucket'
    assert classify_m10q_s3_target_reference(ap) == 'secure'
    assert missing['m10q_bucket_target_not_reported'] is True
    assert classify_m10q_s3_target_reference(missing) == 'insecure'
    assert region['directory_access_points']['dap']['m10q_bucket_target'][
        'status'] == 'observed_directory_bucket'
    assert region['directory_buckets']['dir']['m10q_backup_coverage_status'] == 'not_evaluated'
    assert data['s3']['advanced']['multi_region_access_points']['mr'][
        'm10q_bucket_targets'][0]['status'] == 'observed_local_bucket'
    grant = region['access_grants']['grant']
    assert grant['m10q_bucket_target']['location_linked'] is True
    assert grant['m10q_bucket_target']['permission'] == 'READWRITE'
    assert bucket['m10q_backup']['plan_selection_status'] == 'explicit_assignment_observed'
    assert bucket['m10q_backup']['selected_plan_ids'] == ['bp-1']
    assert bucket['m10q_backup']['ongoing_schedule_verified'] is False
    assert bucket['m10q_backup']['state'] == 'not_reported'


def test_denied_s3_bucket_list_never_becomes_orphan_and_foreign_bucket_is_not_local():
    data = fixture()
    data['s3']['bucket_inventory_status'] = 'incomplete'
    region = data['s3']['advanced']['regions'][REGION]
    region['access_points']['other']['BucketAccountId'] = ACCOUNT
    region['access_points']['point']['BucketAccountId'] = '111111111111'
    reconcile_m10q_coverage(data, ['s3'], ACCOUNT)
    assert region['access_points']['other']['m10q_bucket_target']['status'] == 'unknown'
    assert not region['access_points']['other']['m10q_bucket_target_not_reported']
    assert region['access_points']['point']['m10q_bucket_target']['status'] == 'foreign_account'
    assert classify_m10q_s3_target_reference(region['access_points']['point']) == 'not_applicable'
    # No invented exposure results for a directory bucket without Backup coverage.
    assert region['directory_buckets']['dir']['m10q_backup_support_verified'] is False


def test_grant_conflicting_location_is_unknown_and_not_misattributed():
    data = fixture()
    grant = data['s3']['advanced']['regions'][REGION]['access_grants']['grant']
    grant['GrantScope'] = 's3://different/prefix'
    reconcile_m10q_coverage(data, ['s3'], ACCOUNT)
    assert grant['m10q_bucket_target']['status'] == 'unknown'
    assert grant['m10q_bucket_target']['reasons'] == [
        'grant_scope_conflicts_with_location']
    assert not any(item['kind'] == 'access_grant' for item in
                   data['s3']['buckets']['a']['m10q_s3_entrypoints'])


def test_backup_selectors_cannot_infer_tag_conditions_or_restore_success():
    unconditional = {'selection_collection_complete': True,
                     'selections': [{'BackupSelection': {
                         'Resources': ['arn:aws:s3:::*'], 'NotResources': [
                             'arn:aws:s3:::excluded']}}]}
    assert _selection_for(ARN, unconditional) == 'explicitly_selected'
    assert _selection_for('arn:aws:s3:::excluded', unconditional) == 'not_explicitly_selected'
    conditional = {'selection_collection_complete': True,
                   'selections': [{'BackupSelection': {
                       'Resources': [ARN], 'NotResources': [],
                       'ListOfTags': [{'ConditionType': 'STRINGEQUALS',
                                      'ConditionKey': 'team',
                                      'ConditionValue': 'finance'}]}}]}
    assert _selection_for(ARN, conditional) == 'conditional_unknown'
    assert _selection_for(ARN, {'selection_collection_complete': False}) == 'unknown'
    data = fixture()
    home = data['backup']['regions'][REGION]
    home['plans']['p1'] = {'backup_plan_id': 'bp-1', **conditional}
    home['restore_testing_plans'] = {'test': {
        'RestoreTestingPlanArn': 'arn:aws:backup:eu-central-1:000000000000:restore-testing-plan:x',
        'observed_restore_jobs': [{'RestoreJobId': 'r1', 'SourceResourceArn': ARN,
                                   'Status': 'COMPLETED', 'ValidationStatus': 'SUCCESSFUL'}]}}
    reconcile_m10q_coverage(data, ['s3', 'backup'], ACCOUNT)
    ev = data['s3']['buckets']['a']['m10q_backup']
    assert ev['plan_selection_status'] == 'conditional_or_incomplete'
    assert ev['selected_plan_ids'] == []
    assert ev['conditional_plan_ids'] == ['bp-1']
    assert ev['restore_test_jobs_observed'][0]['restore_job_id'] == 'r1'
    assert ev['restore_test_success_verified'] is False


def test_cross_region_backup_recovery_prevents_false_local_no_backup_claim():
    data = fixture()
    data['backup']['regions']['eu-west-1'] = {
        'backup_inventory_status': {
            'protected_resources': 'complete', 'backup_jobs': 'complete'},
        'protected_resources': {'cross': {'ResourceArn': ARN}}, 'backup_jobs': {}}
    reconcile_m10q_coverage(data, ['s3', 'backup'], ACCOUNT)
    ev = data['s3']['buckets']['a']['m10q_backup']
    assert ev['state'] == 'cross_region_evidence_only'
    assert ev['cross_region_evidence_regions'] == ['eu-west-1']
    assert data['s3']['buckets']['a']['m10q_backup_evidence_gap'] is False


def test_stopped_ec2_and_disabled_inspector_are_unknown_not_clean_or_gap():
    data = {'ec2': {'regions': {REGION: {'vpcs': {'vpc': {'instances': {
        'i-a': {'id': 'i-a', 'State': {'Name': 'stopped'}},
        'i-b': {'id': 'i-b', 'State': {'Name': 'running'}},
    }}}}}},
        'inspector2': {'regions': {REGION: {
            'accounts': {'own': {'account_id': ACCOUNT, 'status': 'DISABLED'}},
            'coverage_summary': {'status': 'complete'},
            'coverage': {}}}},
    }
    reconcile_m10q_coverage(data, ['ec2', 'inspector2'], ACCOUNT)
    rows = data['ec2']['regions'][REGION]['vpcs']['vpc']['instances']
    assert rows['i-a']['m10q_inspector']['state'] == 'unknown'
    assert not rows['i-a']['m10q_inspector_not_reported']
    assert rows['i-b']['m10q_inspector']['state'] == 'unknown'
    assert 'inspector_account_enrollment_inactive' in rows['i-b'][
        'm10q_inspector']['reasons']


def test_s3_bucket_inventory_empty_requires_completed_list_buckets():
    async def scenario(fail):
        facade = S3Facade(object())
        facade.regions = [REGION]
        with patch('ScoutSuite.providers.aws.facade.s3.AWSFacadeUtils.get_client',
                   return_value=object()), patch.object(
                       S3Facade, '_list_bucket_pages', new_callable=AsyncMock) as pages:
            if fail:
                pages.side_effect = RuntimeError('synthetic denied')
            else:
                pages.return_value = []
            result = await facade.get_buckets()
        assert result == []
        assert facade.bucket_inventory_status == (
            'incomplete' if fail else 'complete')
    asyncio.run(scenario(True))
    asyncio.run(scenario(False))


def test_advanced_s3_bounded_page_and_items_rejects_infinite_listing():
    async def scenario():
        facade = S3AdvancedFacade(object(), ACCOUNT)
        with patch.object(advanced_module, 'MAX_PAGES', 2):
            facade._call = AsyncMock(side_effect=[
                {'AccessPointList': [{'Name': 'a'}], 'NextToken': 'page-2'},
                {'AccessPointList': [{'Name': 'b'}], 'NextToken': 'page-3'}])
            items, complete = await facade._pages(
                None, 'ListAccessPoints', 'AccessPointList', REGION, AccountId=ACCOUNT)
            assert [item['Name'] for item in items] == ['a', 'b']
            assert not complete
            assert facade._call.await_count == 2
        with patch.object(advanced_module, 'MAX_ITEMS', 1):
            facade._call = AsyncMock(return_value={
                'AccessPointList': [{'Name': 'a'}, {'Name': 'b'}]})
            items, complete = await facade._pages(
                None, 'ListAccessPoints', 'AccessPointList', REGION)
            assert len(items) == 1 and not complete
        facade._call = AsyncMock(return_value={'AccessPointList': [None]})
        items, complete = await facade._pages(None, 'ListAccessPoints',
                                               'AccessPointList', REGION)
        assert not items and not complete
    asyncio.run(scenario())


def test_s3_scope_parsing_and_v2_rules_registered():
    assert _bucket_from_scope('s3://example/finance/') == 'example'
    assert _bucket_from_scope('s3://') is None
    assert _bucket_from_scope('s3://*/') is None
    assert _bucket_from_reference('arn:aws:s3:::bucket') is None
    assert _bucket_from_reference('alpha') == 'alpha'
    rules = json.loads((ROOT / 'ScoutSuite/providers/aws/rules/rulesets/default.json')
                       .read_text())['rules']
    for name in ('m10q-s3-access-point-bucket-unresolved.json',
                 'm10q-s3-directory-access-point-target-unresolved.json'):
        assert rules[name][0]['enabled'] is True
        obj = json.loads((ROOT / 'ScoutSuite/providers/aws/rules/findings'
                          / name).read_text())
        assert obj['evidence_policy'] in CLASSIFIERS
        assert obj['conditions'][1][1] == 'true'
