"""M10: strict partial/unknown evidence for SCP, tagged Backup and Macie."""
import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from botocore.exceptions import ClientError

from ScoutSuite.providers.aws.facade.organizations import OrganizationsFacade
from ScoutSuite.providers.aws.facade.backup import BackupPublicFacade
from ScoutSuite.providers.aws.facade.macie import MacieFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.backup.base import _selection_decision
from ScoutSuite.providers.aws.resources.macie.base import MaciePublic


ACCOUNT = '222222222222'
ROOT = 'r-abc1'
OU = 'ou-abc1-22222222'
ARN = 'arn:aws:ec2:us-east-1:222222222222:volume/vol-123'


def test_scp_ancestor_chain_and_documents_are_configuration_not_effective_access():
    async def run():
        client = Mock()
        client.list_parents.side_effect = lambda **kwargs: {
            'Parents': [{'Id': OU, 'Type': 'ORGANIZATIONAL_UNIT'}]
            if kwargs['ChildId'] == ACCOUNT else [{'Id': ROOT, 'Type': 'ROOT'}]}
        client.list_policies_for_target.side_effect = lambda **kwargs: {
            'Policies': [{'Id': 'p-deny', 'Name': 'DenySensitive',
                          'Arn': 'arn:aws:organizations::111111111111:policy/o-org/service_control_policy/p-deny'}]
            if kwargs['TargetId'] == OU else []}
        client.describe_policy.return_value = {
            'Policy': {'Content': json.dumps({'Version': '2012-10-17',
                      'Statement': [{'Effect': 'Deny', 'Action': 'iam:*',
                                     'Resource': '*'}]})}}
        facade = OrganizationsFacade(object(), 'aws')
        with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
            data = await facade.get_scp_context([{'Id': ACCOUNT}], [{'Id': ROOT}])
            again = await facade.get_scp_context([{'Id': ACCOUNT}], [{'Id': ROOT}])
        assert data is again
        assert data['collection_status'] == 'complete'
        account = data['accounts'][ACCOUNT]
        assert account['ancestor_path'] == [ACCOUNT, OU, ROOT]
        assert account['policy_documents']['p-deny']['Statement'][0]['Action'] == 'iam:*'
        assert account['effective_permissions_verified'] is False
        assert client.list_parents.call_count == 2
        assert client.describe_policy.call_count == 1
    asyncio.run(run())


def test_scp_missing_ancestor_is_partial_not_an_empty_policy():
    async def run():
        client = Mock()
        client.list_parents.side_effect = ClientError(
            {'Error': {'Code': 'AccessDeniedException'}}, 'ListParents')
        client.list_policies_for_target.return_value = {'Policies': []}
        facade = OrganizationsFacade(object(), 'aws')
        with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
            data = await facade.get_scp_context([{'Id': ACCOUNT}], [{'Id': ROOT}])
        assert data['collection_status'] == 'partial'
        assert data['accounts'][ACCOUNT]['collection_status'] == 'partial'
        assert data['accounts'][ACCOUNT]['effective_permissions_verified'] is False
    asyncio.run(run())


def test_backup_tag_matching_uses_and_or_and_unknown_without_guessing_absence():
    selection = {'BackupSelection': {
        'Resources': ['arn:aws:ec2:*:*:volume/*'],
        'Conditions': {'StringEquals': [{'ConditionKey': 'aws:ResourceTag/backup',
                                         'ConditionValue': 'daily'}],
                       'StringNotLike': [{'ConditionKey': 'aws:ResourceTag/env',
                                          'ConditionValue': 'test*'}]}}}
    assert _selection_decision(ARN, selection, {'backup': 'daily', 'env': 'prod'}) == 'matched'
    assert _selection_decision(ARN, selection, {'backup': 'daily', 'env': 'testing'}) == 'not_matched'
    assert _selection_decision(ARN, selection) == 'unknown'
    # Resources and ListOfTags form an OR, constrained by Conditions AND.
    mixed = {'BackupSelection': {
        'Resources': ['arn:aws:rds:*:*:db:*'],
        'ListOfTags': [{'ConditionType': 'STRINGEQUALS',
                        'ConditionKey': 'backup', 'ConditionValue': 'daily'}]}}
    assert _selection_decision(ARN, mixed, {'backup': 'daily'}) == 'matched'
    assert _selection_decision(ARN, mixed, {'backup': 'weekly'}) == 'not_matched'
    direct_or_tag = {'BackupSelection': {
        'Resources': [ARN],
        'ListOfTags': [{'ConditionType': 'STRINGEQUALS',
                        'ConditionKey': 'backup', 'ConditionValue': 'weekly'}]}}
    assert _selection_decision(ARN, direct_or_tag) == 'matched'
    assert _selection_decision(ARN, {'BackupSelection': {
        'ListOfTags': [
            {'ConditionType': 'STRINGEQUALS', 'ConditionKey': 'backup',
             'ConditionValue': 'weekly'},
            {'ConditionType': 'STRINGEQUALS', 'ConditionKey': 'backup',
             'ConditionValue': 'daily'}]}}, {'backup': 'daily'}) == 'matched'
    assert _selection_decision(ARN, {'BackupSelection': {
        'NotResources': [ARN], 'Resources': ['*']}}, None) == 'excluded'


def test_backup_tag_api_does_not_infer_missing_resource_untagged():
    async def run():
        client = Mock()
        client.get_resources.return_value = {
            'ResourceTagMappingList': [
                {'ResourceARN': ARN, 'Tags': [{'Key': 'backup', 'Value': 'daily'}]}]}
        facade = BackupPublicFacade(object(), ACCOUNT)
        missing = ARN.replace('vol-123', 'vol-456')
        with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
            data = await facade.get_resource_tags('us-east-1', [ARN, missing])
        assert data['status'] == 'complete'
        assert data['tags'][ARN] == {'backup': 'daily'}
        assert missing in data['unknown_arns']
        assert missing not in data['tags']
        assert client.get_resources.call_count == 1
    asyncio.run(run())


def test_macie_completed_run_evidence_is_not_per_bucket_classification_proof():
    async def run():
        macie = Mock()
        macie.get_macie_session.return_value = {'status': 'ENABLED'}
        macie.get_automated_discovery_configuration.return_value = {'status': 'DISABLED'}
        macie.list_classification_jobs.return_value = {
            'items': [{'jobId': 'job-one'}]}
        macie.describe_classification_job.return_value = {
            'jobId': 'job-one', 'jobType': 'ONE_TIME',
            'jobStatus': 'COMPLETE', 'lastRunTime': '2026-10-30T12:00:00Z',
            'lastRunErrorStatus': {'code': 'NONE'},
            'statistics': {'numberOfRuns': 1}}
        macie.describe_buckets.return_value = {'buckets': [
            {'bucketName': 'bucket-one', 'accountId': ACCOUNT,
             'jobDetails': {'lastJobId': 'job-one',
                            'lastJobRunTime': '2026-10-30T12:00:00Z'}}]}
        with patch.object(AWSFacadeUtils, 'get_client', return_value=macie):
            raw = await MacieFacade(object()).get_region('us-east-1')
        assert raw['jobs'][0]['execution_success_evidence'] is True
        assert raw['jobs'][0]['classification_results_verified'] is False
        public = SimpleNamespace(
            build_region_list=AsyncMock(return_value=['us-east-1']),
            macie=SimpleNamespace(get_region=AsyncMock(return_value=raw)))
        inventory = MaciePublic(public)
        await inventory.fetch_all()
        data = inventory['regions']['us-east-1']
        bucket = next(iter(data['buckets'].values()))
        assert data['verified_job_executions_count'] == 1
        assert data['verified_bucket_classifications_count'] == 0
        assert bucket['job_execution_evidence_status'] == (
            'linked_job_completed_no_reported_access_errors')
        assert bucket['classification_results_verified'] is False
    asyncio.run(run())
