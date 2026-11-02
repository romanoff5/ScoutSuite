"""M10 report evidence completeness: synthetic contacts, diagnostics and scale."""
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from sqlitedict import SqliteDict

from ScoutSuite.output.safe_sqlite import decode_sqlite_value
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.organizations import OrganizationsFacade
from ScoutSuite.providers.aws.facade.guardduty import GuardDutyPublicFacade
from ScoutSuite.providers.aws.facade.accessanalyzer import AccessAnalyzerFacade
from ScoutSuite.providers.aws.facade.securityhub import SecurityHubPublicFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.organizations.base import Organizations
from ScoutSuite.providers.aws.resources.guardduty.detectors import Detectors
from ScoutSuite.providers.aws.resources.accessanalyzer.analyzers import Analyzers
from ScoutSuite.providers.aws.resources.securityhub.hubs import Hubs


ROOT = Path(__file__).resolve().parents[1]
REGION = 'us-east-1'
ACCOUNT = '222222222222'


def test_organizations_contact_timestamps_and_policy_types_survive_sqlite(tmp_path):
    source = {
        'organization': {'Id': 'o-example', 'Arn': 'arn:aws:organizations::111111111111:organization/o-example',
                         'FeatureSet': 'ALL', 'MasterAccountId': '111111111111',
                         'MasterAccountEmail': 'management@example.invalid',
                         'MasterAccountArn': 'arn:aws:organizations::111111111111:account/o-example/111111111111'},
        'roots': [{'Id': 'r-example', 'Name': 'Org root', 'PolicyTypes': [
            {'Type': 'SERVICE_CONTROL_POLICY', 'Status': 'ENABLED'},
            {'Type': 'RESOURCE_CONTROL_POLICY', 'Status': 'DISABLED'}]}],
        'accounts': [{'Id': ACCOUNT, 'Name': 'Engineering', 'Email': 'owner@example.invalid',
                      'Arn': 'arn:aws:organizations::111111111111:account/o-example/' + ACCOUNT,
                      'State': 'ACTIVE', 'JoinedMethod': 'INVITED',
                      'JoinedTimestamp': datetime(2026, 9, 21, tzinfo=timezone.utc)}],
        'collection': {'organization': 'complete', 'roots': 'complete', 'accounts': 'complete'},
    }

    async def build():
        resource = Organizations(SimpleNamespace(
            organizations=SimpleNamespace(get_organization_inventory=AsyncMock(return_value=source))))
        await resource.fetch_all()
        return dict(resource)

    report = asyncio.run(build())
    assert report['organizations']['o-example']['management_account_email'] == 'management@example.invalid'
    assert report['organizations']['o-example']['management_account_arn'].endswith('/111111111111')
    assert report['accounts'][ACCOUNT]['email'] == 'owner@example.invalid'
    assert report['accounts'][ACCOUNT]['joined_timestamp'].startswith('2026-09-21')
    assert report['roots']['r-example']['policy_types'] == [
        {'type': 'SERVICE_CONTROL_POLICY', 'status': 'ENABLED'},
        {'type': 'RESOURCE_CONTROL_POLICY', 'status': 'DISABLED'}]
    path = tmp_path / 'results.db'
    with SqliteDict(str(path)) as writer:
        writer['organizations'] = report
        writer.commit()
    with SqliteDict(str(path), flag='r', decode=decode_sqlite_value) as reader:
        restored = reader['organizations']
    assert restored == report
    assert 'owner@example.invalid' in json.dumps(restored)


def test_organizations_inventory_does_not_stop_at_old_5000_account_cap():
    async def scenario():
        pages = []
        for page in range(251):
            start = page * 20
            count = 20 if page < 250 else 1
            rows = [{'Id': str(start + i).zfill(12)} for i in range(count)]
            payload = {'Accounts': rows}
            if page < 250:
                payload['NextToken'] = str(page + 1)
            pages.append(payload)
        fake = Mock()
        fake.list_accounts.side_effect = pages
        ctx = RunContext('aws').setup()
        try:
            records, status = await OrganizationsFacade(object(), 'aws')._list(
                fake, 'list_accounts', 'Accounts', 5000, 100000)
            assert status == 'complete'
            assert len(records) == 5001
            assert fake.list_accounts.call_count == 251
            assert ctx.collection_issues == []
        finally:
            await ctx.aclose()
    asyncio.run(scenario())


def test_access_analyzer_preserves_diagnostics_and_old_2000_limit_is_not_applied():
    raw = {'arn': 'arn:aws:access-analyzer:us-east-1:111111111111:analyzer/example',
           'name': 'example', 'status': 'FAILED', 'type': 'ORGANIZATION',
           'createdAt': datetime(2026, 2, 1, tzinfo=timezone.utc),
           'lastResourceAnalyzed': 'arn:aws:s3:::synthetic-bucket',
           'lastResourceAnalyzedAt': datetime(2026, 3, 1, tzinfo=timezone.utc),
           'statusReason': {'code': 'SERVICE_LINKED_ROLE_CREATION_FAILED'},
           'tags': {'team': 'secops'}, 'configuration': {'unusedAccess': {'unusedAccessAge': 90}}}
    parser = Analyzers.__new__(Analyzers)
    parser.region = REGION
    _, record = parser._parse_analyzer(raw)
    assert record['status_reason'] == 'SERVICE_LINKED_ROLE_CREATION_FAILED'
    assert record['created_at'].startswith('2026-02')
    assert record['last_resource_analyzed'].endswith('synthetic-bucket')
    assert record['tags'] == {'team': 'secops'}
    assert record['configuration'] == {'unusedAccess': {'unusedAccessAge': 90}}

    async def scenario():
        pages = []
        for page in range(21):
            rows = [{'arn': 'arn:aws:access-analyzer:us-east-1:111111111111:analyzer/' +
                     str(page * 100 + i), 'name': 'sample', 'status': 'ACTIVE', 'type': 'ACCOUNT'}
                    for i in range(100)]
            payload = {'analyzers': rows}
            if page < 20:
                payload['nextToken'] = str(page + 1)
            pages.append(payload)
        sdk = Mock()
        sdk.list_analyzers.side_effect = pages
        ctx = RunContext('aws').setup()
        try:
            with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                values = await AccessAnalyzerFacade(object()).get_analyzers(REGION)
            assert len(values) == 2100
            assert sdk.list_analyzers.call_count == 21
            assert ctx.collection_issues == []
        finally:
            await ctx.aclose()
    asyncio.run(scenario())


def test_guardduty_preserves_features_service_role_and_more_than_100_detectors():
    async def scenario():
        responses = []
        for n, length in enumerate((50, 50, 1)):
            packet = {'DetectorIds': [str(i + n * 50).zfill(10) for i in range(length)]}
            if n < 2:
                packet['NextToken'] = str(n + 1)
            responses.append(packet)
        sdk = Mock()
        sdk.list_detectors.side_effect = responses
        sdk.get_detector.return_value = {
            'Status': 'DISABLED', 'FindingPublishingFrequency': 'SIX_HOURS',
            'ServiceRole': 'arn:aws:iam::111111111111:role/GuardDutyService',
            'CreatedAt': '2026-01-01T01:00:00Z', 'UpdatedAt': '2026-02-01T01:00:00Z',
            'Features': [{'Name': 'S3_DATA_EVENTS', 'Status': 'ENABLED'}],
            'DataSources': {'S3Logs': {'Status': 'ENABLED'}},
            'Tags': {'owner': 'Security Engineering'},
        }
        ctx = RunContext('aws').setup()
        try:
            with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                values = await GuardDutyPublicFacade(object()).get_detectors(REGION)
            assert len(values) == 101
            assert sdk.get_detector.call_count == 101
            assert values[0]['service_role'].endswith('GuardDutyService')
            parser = Detectors.__new__(Detectors)
            parser.region = REGION
            _, normalized = parser._parse_detector(values[0])
            assert normalized['features'][0]['Name'] == 'S3_DATA_EVENTS'
            assert normalized['data_sources']['S3Logs']['Status'] == 'ENABLED'
            assert normalized['tags']['owner'] == 'Security Engineering'
            assert normalized['created_at'].startswith('2026-01')
            assert ctx.collection_issues == []
        finally:
            await ctx.aclose()
    asyncio.run(scenario())


def test_securityhub_preserves_remediation_status_and_old_500_cap_is_not_applied():
    hub_arn = 'arn:aws:securityhub:us-east-1:111111111111:hub/default'
    standard = 'arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0'
    sdk = Mock()
    sdk.describe_hub.return_value = {'HubArn': hub_arn, 'AutoEnableControls': False}
    pages = []
    for i in range(11):
        batch = [
            {'StandardsSubscriptionArn': hub_arn + '/subscription/' + str(i * 50 + j),
             'StandardsArn': standard, 'StandardsStatus': 'INCOMPLETE',
             'StandardsStatusReason': {'StatusReasonCode': 'NO_AVAILABLE_CONFIGURATION_RECORDER'},
             'StandardsControlsUpdatable': 'READY_FOR_UPDATES', 'Provider': 'AWS'}
            for j in range(50)]
        p = {'StandardsSubscriptions': batch}
        if i < 10:
            p['NextToken'] = str(i + 1)
        pages.append(p)
    sdk.get_enabled_standards.side_effect = pages

    async def scenario():
        ctx = RunContext('aws').setup()
        try:
            with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                result = await SecurityHubPublicFacade(object()).get_hub(REGION)
            assert result['standards_inventory_complete'] is True
            assert len(result['standards']) == 550
            assert result['standards'][0]['status_reason'] == 'NO_AVAILABLE_CONFIGURATION_RECORDER'
            assert result['standards'][0]['standards_controls_updatable'] == 'READY_FOR_UPDATES'
            assert result['standards'][0]['provider'] == 'AWS'
            upstream = SimpleNamespace(securityhub=SimpleNamespace(get_hub=AsyncMock(return_value=result)))
            resources = Hubs(upstream, REGION)
            await resources.fetch_all()
            rows = next(iter(resources.values()))['standards']
            assert len(rows) == 550
            assert next(iter(rows.values()))['status_reason_details']['StatusReasonCode'] == (
                'NO_AVAILABLE_CONFIGURATION_RECORDER')
            assert ctx.collection_issues == []
        finally:
            await ctx.aclose()
    asyncio.run(scenario())


def test_escaped_html_exposes_identifiers_contacts_and_diagnostic_fields():
    fragments = {
        'services.organizations.accounts.id.html': ('{{email}}', '{{joined_timestamp}}'),
        'services.organizations.organizations.id.html': ('{{management_account_email}}',
                                                         '{{management_account_arn}}'),
        'services.organizations.roots.id.html': ('{{#each policy_types}}', '{{scp_status}}'),
        'services.guardduty.regions.id.detectors.html': ('{{service_role}}', '{{#each features}}'),
        'services.accessanalyzer.regions.id.analyzers.html': ('{{created_at}}',
                                                              '{{last_resource_analyzed}}'),
        'services.securityhub.regions.id.hubs.html': ('{{subscription_arn}}', '{{status_reason}}'),
    }
    for name, fields in fragments.items():
        html = (ROOT / 'ScoutSuite/output/data/html/partials/aws' / name).read_text(encoding='utf8')
        for field in fields:
            assert field in html
        assert '{{{' not in html
        assert 'onclick=' not in html
    rules = (ROOT / 'AGENTS.md').read_text(encoding='utf8')
    assert 'Reports are actionable security evidence' in rules
    assert 'Do not silently truncate inventories' in rules
