"""M10-E ECR bounded own-registry API, reporting and evidence regression tests."""
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import boto3
from botocore.session import get_session
from botocore.stub import Stubber

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.rule_evidence import classify_ecr_tag_mutability
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.ecr_public import (
    ECRPublicFacade, MAX_PAGES, PAGE_SIZE, MAX_REPOSITORIES)
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.provider import AWSProvider
from ScoutSuite.providers.aws.resources.ecr_public.base import ECRPublic


ROOT = Path(__file__).resolve().parents[1]
REGION = 'us-east-1'
ACCOUNT = '000000000000'


def client():
    return boto3.client('ecr', region_name=REGION, aws_access_key_id='synthetic',
                        aws_secret_access_key='synthetic')


def repository(index=1, mutability='IMMUTABLE'):
    name = 'team/repo-' + str(index)
    return {'repositoryArn': 'arn:aws:ecr:us-east-1:' + ACCOUNT + ':repository/' + name,
            'repositoryName': name, 'repositoryUri':
            ACCOUNT + '.dkr.ecr.us-east-1.amazonaws.com/' + name,
            'registryId': ACCOUNT, 'createdAt': datetime(2026, 10, 1, tzinfo=timezone.utc),
            'imageTagMutability': mutability, 'imageScanningConfiguration': {'scanOnPush': False},
            'encryptionConfiguration': {'encryptionType': 'KMS',
                                        'kmsKey': 'arn:aws:kms:us-east-1:' + ACCOUNT + ':key/example'}}


def test_boto_api_contract_and_expected_scope():
    operation = get_session().get_service_model('ecr').operation_model('DescribeRepositories')
    assert {'registryId', 'maxResults', 'nextToken'} <= set(operation.input_shape.members)
    assert {'repositories', 'nextToken'} <= set(operation.output_shape.members)
    fields = set(operation.output_shape.members['repositories'].member.members)
    assert {'repositoryArn', 'repositoryName', 'registryId', 'repositoryUri',
            'imageTagMutability', 'imageScanningConfiguration',
            'encryptionConfiguration', 'imageTagMutabilityExclusionFilters'} <= fields


def test_two_pages_boto_stubber_with_region_normalization():
    async def scenario():
        sdk = client()
        try:
            with Stubber(sdk) as stub:
                stub.add_response('describe_repositories',
                                  {'repositories': [repository(1)], 'nextToken': 'next'},
                                  {'registryId': ACCOUNT, 'maxResults': PAGE_SIZE})
                stub.add_response('describe_repositories',
                                  {'repositories': [repository(2, 'MUTABLE')]},
                                  {'registryId': ACCOUNT, 'maxResults': PAGE_SIZE,
                                   'nextToken': 'next'})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk) as get_client:
                    facade = ECRPublicFacade(object(), ACCOUNT)
                    rows = await facade.get_repositories(REGION)
                get_client.assert_called_once_with('ecr', facade.session, REGION)
                stub.assert_no_pending_responses()
            assert len(rows) == 2
            assert rows[0]['registryId'] == ACCOUNT
            assert rows[1]['imageTagMutability'] == 'MUTABLE'
            source = SimpleNamespace(
                build_region_list=AsyncMock(return_value=[REGION]),
                ecr=SimpleNamespace(get_repositories=AsyncMock(return_value=rows),
                get_registry_scanning=AsyncMock(return_value=None)))
            resources = ECRPublic(source)
            await resources.fetch_all(regions=[REGION])
            assert resources['regions_count'] == 1
            assert resources['repositories_count'] == 2
            first = next(value for value in resources['regions'][REGION]['repositories'].values()
                         if value['image_tag_mutability'] == 'IMMUTABLE')
            assert first['name'] == 'team/repo-1'
            assert first['repository_arn'] == rows[0]['repositoryArn']
            assert first['registry_id'] == ACCOUNT
            assert first['repository_uri'] == rows[0]['repositoryUri']
            assert first['created_at'].startswith('2026-10-01')
            assert first['encryption_configuration']['kmsKey'] == (
                rows[0]['encryptionConfiguration']['kmsKey'])
            assert first['image_scanning_configuration']['scanOnPush'] is False
            assert all(key.startswith('scoutid-')
                       for key in resources['regions'][REGION]['repositories'])
        finally:
            sdk.close()
    asyncio.run(scenario())


def test_denied_registry_and_invalid_own_account_not_clean():
    async def scenario():
        sdk = client()
        ctx = RunContext('aws').setup()
        try:
            with Stubber(sdk) as stub:
                stub.add_client_error('describe_repositories',
                                      service_error_code='AccessDeniedException', http_status_code=403,
                                      expected_params={'registryId': ACCOUNT, 'maxResults': PAGE_SIZE})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                    assert await ECRPublicFacade(object(), ACCOUNT).get_repositories(REGION) == []
                stub.assert_no_pending_responses()
            assert any(issue['status'] == 'denied' and issue['scope'] == 'ecr'
                       for issue in ctx.collection_issues)
            with patch.object(AWSFacadeUtils, 'get_client') as get_client:
                assert await ECRPublicFacade(object(), 'invalid').get_repositories(REGION) == []
                get_client.assert_not_called()
            assert any(issue['reason_code'] == 'InvalidAccountId'
                       for issue in ctx.collection_issues)
        finally:
            await ctx.aclose()
            sdk.close()
    asyncio.run(scenario())


def test_partial_second_page_denial_retains_proven_resources():
    async def scenario():
        sdk = client()
        ctx = RunContext('aws').setup()
        try:
            with Stubber(sdk) as stub:
                stub.add_response('describe_repositories',
                                  {'repositories': [repository()], 'nextToken': 'second'},
                                  {'registryId': ACCOUNT, 'maxResults': PAGE_SIZE})
                stub.add_client_error('describe_repositories',
                                      service_error_code='AccessDeniedException',
                                      http_status_code=403,
                                      expected_params={'registryId': ACCOUNT,
                                                       'maxResults': PAGE_SIZE,
                                                       'nextToken': 'second'})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                    result = await ECRPublicFacade(object(), ACCOUNT).get_repositories(REGION)
                stub.assert_no_pending_responses()
            assert len(result) == 1
            assert any(issue['status'] == 'partial' for issue in ctx.collection_issues)
        finally:
            await ctx.aclose()
            sdk.close()
    asyncio.run(scenario())


def test_malformed_duplicate_foreign_and_looped_pages_produce_issues():
    async def scenario():
        bad_owner = dict(repository(1), registryId='111111111111')
        cases = [
            ([{}], 'MalformedRepositoryPage'),
            ([{'repositories': [None]}], 'MalformedRepository'),
            ([{'repositories': [repository(1), repository(1)]}], 'DuplicateRepository'),
            ([{'repositories': [bad_owner]}], 'UnexpectedRegistry'),
            ([{'repositories': [], 'nextToken': 'loop'},
              {'repositories': [], 'nextToken': 'loop'}], 'InvalidPaginationToken'),
            ([{'repositories': [], 'nextToken': 'x' * 4097}], 'InvalidPaginationToken'),
            ([{'repositories': [], 'nextToken': str(i)}
              for i in range(MAX_PAGES)], 'PageLimit'),
            ([{'repositories': [repository(i) for i in range(PAGE_SIZE + 1)]}],
             'MalformedRepositoryPage'),
        ]
        for pages, expected_reason in cases:
            sdk = Mock()
            sdk.describe_repositories.side_effect = pages
            ctx = RunContext('aws').setup()
            try:
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                    result = await ECRPublicFacade(object(), ACCOUNT).get_repositories(REGION)
                assert len(result) <= MAX_REPOSITORIES
                assert sdk.describe_repositories.call_count <= MAX_PAGES
                assert any(issue['reason_code'] == expected_reason
                           for issue in ctx.collection_issues)
            finally:
                await ctx.aclose()
    asyncio.run(scenario())


def test_mutability_mixed_mode_unknown_and_rule_engine(tmp_path):
    for mode, expected in [('IMMUTABLE', 'secure'), ('MUTABLE', 'insecure'),
                           ('IMMUTABLE_WITH_EXCLUSION', 'unknown'),
                           ('MUTABLE_WITH_EXCLUSION', 'unknown'),
                           (None, 'unknown')]:
        assert classify_ecr_tag_mutability({'image_tag_mutability': mode}) == expected
    assert classify_ecr_tag_mutability(None) == 'unknown'
    rules = {'about': 'Synthetic ECR rule', 'rules': {
        'ecr-repository-tags-mutable.json': [{'enabled': True, 'level': 'warning'}]}}
    path = tmp_path / 'ecr-rule.json'
    path.write_text(json.dumps(rules), encoding='utf-8')
    repos = {'secure': {'image_tag_mutability': 'IMMUTABLE', 'tag_mutable': False},
             'insecure': {'image_tag_mutability': 'MUTABLE', 'tag_mutable': True},
             'mixed': {'image_tag_mutability': 'MUTABLE_WITH_EXCLUSION',
                       'tag_mutable': False}}
    provider = SimpleNamespace(services={'ecr': {'regions': {REGION: {'repositories': repos}}}},
                               service_list=['ecr'])
    ctx = RunContext('aws').setup()
    try:
        ProcessingEngine(Ruleset('aws', filename=str(path))).run(provider)
        finding = provider.services['ecr']['findings']['ecr-repository-tags-mutable']
        assert finding['flagged_items'] == 1
        assert finding['assessment_status'] == 'incomplete'
        assert finding['evaluation_summary']['counts'] == {
            'secure': 1, 'insecure': 1, 'unknown': 1, 'not_applicable': 0}
    finally:
        ctx.cleanup()


def test_optin_selection_and_html_escaping_and_no_scanning_false_positive():
    config = lambda credentials: SimpleNamespace(
        credentials=credentials, ecr={}, iam={}, securityhub={}, s3={})
    creds = SimpleNamespace(session=object())
    with patch('ScoutSuite.providers.aws.provider.AWSServicesConfig', config), \
         patch('ScoutSuite.providers.aws.provider.get_partition_name', return_value='aws'), \
         patch('ScoutSuite.providers.aws.provider.get_aws_account_id', return_value=ACCOUNT):
        default = AWSProvider(credentials=creds)
        selected = AWSProvider(credentials=creds, services=['ecr'])
    assert 'ecr' in default.service_list
    assert selected.service_list == ['ecr']
    metadata = json.loads((ROOT / 'ScoutSuite/providers/aws/metadata.json').read_text(encoding='utf-8'))
    assert metadata['containers']['ecr']['resources']['repositories']['path'] == (
        'services.ecr.regions.id.repositories')
    template = (ROOT / 'ScoutSuite/output/data/html/partials/aws/'
                'services.ecr.regions.id.repositories.html').read_text(encoding='utf-8')
    assert '{{repository_arn}}' in template and '{{repository_name}}' in template
    assert '{{{' not in template and 'onclick=' not in template
    assert 'javascript:' not in template
    assert classify_ecr_tag_mutability({
        'image_tag_mutability': 'IMMUTABLE', 'image_scanning_configuration': {
            'scanOnPush': False}}) == 'secure'


def test_registry_basic_scanning_real_report_contract_creates_finding():
    """Live RC1 evidence revealed BASIC classified insecure but not flagged.

    A synthetic resource in the same normalized shape must be flagged by the
    regular finding engine; ENHANCED must not, and absent data stays UNKNOWN.
    """
    definition = json.loads((ROOT / 'ScoutSuite/providers/aws/rules/findings/'
                             'ecr-registry-not-enhanced-scanning.json').read_text(encoding='utf-8'))
    assert definition['conditions'] == ['and', ['scan_type', 'equal', 'BASIC']]
    ruleset = Ruleset('aws', filename='default.json')
    ruleset.rules = {
        key: value for key, value in ruleset.rules.items()
        if key == 'ecr-registry-not-enhanced-scanning'
    }
    assert len(ruleset.rules) == 1
    provider = SimpleNamespace(
        service_list=['ecr'],
        services={'ecr': {'regions': {
            'eu-central-1': {'registry_scanning': {
                'basic': {'id': 'basic', 'scan_type': 'BASIC', 'rules': []},
                'enhanced': {'id': 'enhanced', 'scan_type': 'ENHANCED', 'rules': []},
                'unknown': {'id': 'unknown', 'rules': []},
            }},
        }}})
    ctx = RunContext('aws').setup()
    try:
        ProcessingEngine(ruleset).run(provider)
        result = provider.services['ecr']['findings']['ecr-registry-not-enhanced-scanning']
        assert result['checked_items'] == 3
        assert result['flagged_items'] == 1
        assert len(result['items']) == 1
        summary = result['evaluation_summary']
        assert summary['policy'] == 'ecr-registry-scanning-v1'
        assert summary['counts'] == {
            'insecure': 1, 'secure': 1, 'unknown': 1, 'not_applicable': 0}
        assert result['assessment_status'] == 'incomplete'
        assert summary['compliance_verified'] is False
        assert not any(issue['reason_code'] == 'RuleEvaluation' for issue in ctx.collection_issues)
    finally:
        ctx.cleanup()
