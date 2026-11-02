"""M10-E offline reconciliation with independently selected AWS resource inventories."""
import copy
from types import SimpleNamespace
from unittest.mock import Mock

from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.resources.inspector2.reconciliation import reconcile_inspector_inventory


ACCOUNT = '000000000000'
MEMBER = '111111111111'
MISSING = '222222222222'
REGION = 'eu-central-1'
EC2_ID = 'i-00000000000000001'
EC2_MISSING = 'i-00000000000000002'
LAMBDA_ARN = f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:included'
LAMBDA_MISSING = f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:missing'
ECR_ARN = f'arn:aws:ecr:{REGION}:{ACCOUNT}:repository/included'
ECR_MISSING = f'arn:aws:ecr:{REGION}:{ACCOUNT}:repository/missing'


def fixture():
    region = {
        'accounts': {'only': {'account_id': ACCOUNT}},
        'coverage': {
            'instance': {'resource_type': 'AWS_EC2_INSTANCE', 'resource_id': EC2_ID},
            'lambda': {'resource_type': 'AWS_LAMBDA_FUNCTION', 'resource_id': LAMBDA_ARN},
            'repository': {'resource_type': 'AWS_ECR_REPOSITORY', 'resource_id': ECR_ARN},
        },
        'coverage_summary': {'status': 'complete', 'aws_resource_inventory_compared': False},
        'organization': {
            'role': 'delegated_admin', 'members_complete': True,
            'delegated_admin_account_id': ACCOUNT, 'members': {MEMBER: {'account_id': MEMBER}},
            'organization_roster_verified': False,
        },
    }
    return {
        'inspector2': {'regions': {REGION: region}},
        'ec2': {'regions': {REGION: {'vpcs': {'vpc-1': {'instances': {
            EC2_ID: {'id': EC2_ID}, EC2_MISSING: {'id': EC2_MISSING},
        }}}}}},
        'ecr': {'regions': {REGION: {'repositories': {
            'a': {'repository_arn': ECR_ARN},
            'b': {'repository_arn': ECR_MISSING},
        }}}},
        'awslambda': {'regions': {REGION: {'functions': {
            'a': {'arn': LAMBDA_ARN},
            'b': {'arn': LAMBDA_MISSING},
        }}}},
        'organizations': {
            'collection': {'accounts': 'complete'},
            'accounts': {
                ACCOUNT: {'id': ACCOUNT, 'state': 'ACTIVE'},
                MEMBER: {'id': MEMBER, 'state': 'ACTIVE'},
                MISSING: {'id': MISSING, 'state': 'ACTIVE'},
                '333333333333': {'state': 'CLOSED'},
            },
        },
    }


def test_reconciliation_preserves_resource_ids_and_organization_roster_gaps():
    services = fixture()
    baseline = copy.deepcopy(services)
    ctx = RunContext('aws').setup()
    try:
        reconcile_inspector_inventory(
            services, ['inspector2', 'ec2', 'ecr', 'awslambda', 'organizations'])
        region = services['inspector2']['regions'][REGION]
        outcome = region['resource_reconciliation']
        assert outcome['ec2']['not_seen_in_inspector'] == [EC2_MISSING]
        assert outcome['ecr']['not_seen_in_inspector'] == [ECR_MISSING]
        assert outcome['awslambda']['not_seen_in_inspector'] == [LAMBDA_MISSING]
        assert all(x['comparison_verified'] is False for x in outcome.values())
        assert all(x['source_inventory_complete'] is False for x in outcome.values())
        org = region['organization']
        assert org['organization_roster_compared'] is True
        assert org['organization_roster_verified'] is False
        assert org['aws_org_accounts_missing_from_inspector_members'] == [MISSING]
        assert org['aws_organizations_active_accounts'] == 3
        assert org['inspector_known_active_org_accounts'] == 2
        reasons = {item['reason_code'] for item in ctx.collection_issues}
        assert 'ResourceInventoryGapUnverified' in reasons
        assert 'OrganizationRosterGap' in reasons
        assert services['ec2'] == baseline['ec2']
        assert services['ecr'] == baseline['ecr']
        assert services['awslambda'] == baseline['awslambda']
        assert services['organizations'] == baseline['organizations']
    finally:
        ctx.cleanup()


def test_no_foreign_resource_data_without_explicitly_selected_services():
    services = fixture()
    source = copy.deepcopy(services)
    reconcile_inspector_inventory(services, ['inspector2'])
    region = services['inspector2']['regions'][REGION]
    assert region['resource_reconciliation'] == {}
    assert region['organization']['organization_roster_verified'] is False
    assert 'organization_roster_compared' not in region['organization']
    for name in ['ec2', 'ecr', 'awslambda', 'organizations']:
        assert services[name] == source[name]


def test_organization_roster_incomplete_does_not_claim_verified():
    services = fixture()
    services['organizations']['collection']['accounts'] = 'partial'
    reconcile_inspector_inventory(services, ['inspector2', 'organizations'])
    org = services['inspector2']['regions'][REGION]['organization']
    assert org['organization_roster_compared'] is False
    assert org['organization_roster_verified'] is False


def test_missing_region_sources_stay_unavailable_not_clean():
    services = fixture()
    services['ec2']['regions'] = {}
    reconcile_inspector_inventory(services, ['inspector2', 'ec2'])
    result = services['inspector2']['regions'][REGION]['resource_reconciliation']['ec2']
    assert result['status'] == 'unavailable'
    assert result['comparison_verified'] is False
    assert result['source_inventory_complete'] is False


def test_no_network_calls_or_secret_exposure_during_reconciliation():
    services = fixture()
    sdk = Mock()
    services['ec2']['sdk_client'] = sdk
    reconcile_inspector_inventory(services, ['inspector2', 'ec2'])
    sdk.assert_not_called()
    assert services['inspector2']['regions'][REGION]['resource_reconciliation']['ec2'][
        'not_seen_in_inspector'] == [EC2_MISSING]
