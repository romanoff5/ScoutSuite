"""Real collectors/normalizers, unchanged rules and reports; synthetic SDK responses."""

import asyncio
import copy
import datetime
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from asyncio_throttle import Throttler
import boto3
from botocore.stub import Stubber
import pytest
from sqlitedict import SqliteDict

# Use the existing CLI bootstrap, including its legacy httplib2shim compatibility
# workaround. Standalone provider imports are a separate M03/M07 limitation.
from ScoutSuite import ERRORS_LIST, __main__ as cli_bootstrap
from ScoutSuite.core.exceptions import RuleExceptions
from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.output.html import ScoutReport
from ScoutSuite.output.result_encoder import ScoutResultEncoder
from ScoutSuite.output.utils import get_filename
from ScoutSuite.providers.aws.facade.ec2 import EC2Facade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.ec2.regional_settings import RegionalSettings
from ScoutSuite.providers.azure.facade.storageaccounts import StorageAccountsFacade
from ScoutSuite.providers.azure.resources.storageaccounts.storage_accounts import StorageAccounts
from ScoutSuite.providers.gcp.facade.cloudstorage import CloudStorageFacade
from ScoutSuite.providers.gcp.resources.cloudstorage.buckets import Buckets
from tests.fixtures import DATA, ROOT, case_key, load_fixture, read_manifest


CASES = [case for case in read_manifest()['cases'] if case['kind'] == 'characterization']
SUBSCRIPTION = '00000000-0000-0000-0000-000000000000'


def namespace(data):
    return SimpleNamespace(**{key: namespace(value) if isinstance(value, dict) else value
                              for key, value in data.items()})


async def collect_aws(response):
    client = boto3.client('ec2', region_name='us-east-1', aws_access_key_id='testing', aws_secret_access_key='testing')
    session = object()  # Client construction/authentication is outside this collector contract.
    facade = EC2Facade(session, owner_id='000000000000')
    resources = RegionalSettings(SimpleNamespace(ec2=facade, partition='aws'), region='us-east-1')
    try:
        with Stubber(client) as stub, patch.object(AWSFacadeUtils, 'get_client', return_value=client) as get_client:
            stub.add_response('get_ebs_encryption_by_default',
                              {'EbsEncryptionByDefault': response[0]['EbsEncryptionByDefault']}, {})
            stub.add_response('get_ebs_default_kms_key_id', {'KmsKeyId': response[0]['KmsKeyId']}, {})
            await resources.fetch_all()
            stub.assert_no_pending_responses()
            assert get_client.call_count == 2
            get_client.assert_called_with('ec2', session, 'us-east-1')
        normalized = ScoutResultEncoder.to_dict(resources)
        return normalized, {'ec2': {'regions': {'us-east-1': {'regional_settings': normalized}}}}
    finally:
        client.close()


async def collect_azure(response):
    client = Mock(spec_set=['storage_accounts', 'blob_containers', 'blob_services'])
    for group in ('storage_accounts', 'blob_containers', 'blob_services'):
        setattr(client, group, Mock(spec_set=['list']))
    client.storage_accounts.list.return_value = [namespace(raw) for raw in response]
    client.blob_containers.list.return_value = []
    client.blob_services.list.return_value = []
    monitor = Mock(spec_set=['activity_logs'])
    monitor.activity_logs = Mock(spec_set=['list'])
    monitor.activity_logs.list.return_value = []
    credentials = Mock(spec_set=['get_credentials'])
    credentials.get_credentials.return_value = object()
    facade = StorageAccountsFacade(credentials)
    resources = StorageAccounts(SimpleNamespace(storageaccounts=facade), subscription_id=SUBSCRIPTION)
    with patch('ScoutSuite.providers.azure.facade.storageaccounts.StorageManagementClient', return_value=client):
        with patch('ScoutSuite.providers.azure.facade.storageaccounts.MonitorManagementClient', return_value=monitor):
            await resources.fetch_all()
    client.storage_accounts.list.assert_called_once_with()
    client.blob_containers.list.assert_called_once_with('fixture-rg', 'fixture-storage')
    client.blob_services.list.assert_called_once_with('fixture-rg', 'fixture-storage')
    monitor.activity_logs.list.assert_called_once()
    normalized = ScoutResultEncoder.to_dict(resources)
    return normalized, {'storageaccounts': {'subscriptions': {SUBSCRIPTION: {'storage_accounts': normalized}}}}


class IAMConfiguration(dict):
    @property
    def public_access_prevention(self):
        return self['publicAccessPrevention']


async def collect_gcp(response):
    raw_buckets = []
    for data in response:
        raw = SimpleNamespace(**data)
        raw.time_created = datetime.datetime.fromisoformat(raw.time_created)
        raw.iam_configuration = IAMConfiguration(raw.iam_configuration)
        raw.get_logging = Mock(spec_set=[], return_value=None)
        raw.get_iam_policy = Mock(spec_set=[], return_value=SimpleNamespace(_bindings=[]))
        raw_buckets.append(raw)
    client = Mock(spec_set=['list_buckets'])
    client.list_buckets.return_value = raw_buckets
    facade = CloudStorageFacade()
    resources = Buckets(SimpleNamespace(cloudstorage=facade), project_id='offline-project')
    with patch.object(facade, 'get_client', return_value=client) as get_client:
        await resources.fetch_all()
    get_client.assert_called_once_with('offline-project')
    client.list_buckets.assert_called_once_with()
    for raw in raw_buckets:
        raw.get_logging.assert_called_once_with()
        raw.get_iam_policy.assert_called_once_with()
    normalized = ScoutResultEncoder.to_dict(resources)
    return normalized, {'cloudstorage': {'projects': {'offline-project': {'buckets': normalized}}}}


async def collect(provider, response):
    asyncio.get_running_loop().throttler = Throttler(rate_limit=1000)
    return await {'aws': collect_aws, 'azure': collect_azure, 'gcp': collect_gcp}[provider](response)


@pytest.mark.parametrize('case', CASES, ids=case_key)
def test_collection_rule_exceptions_and_report(case, tmp_path, record_property):
    assert callable(cli_bootstrap.run_from_cli)
    record_property('rule_case', case_key(case))
    fixture = load_fixture(DATA / case['input'])['cases'][case['source_case']]
    expected = fixture['expected']
    normalized, services = asyncio.run(collect(case['provider'], copy.deepcopy(fixture['response'])))
    assert not ERRORS_LIST, 'Collector errors must not masquerade as successful characterization'
    assert normalized == expected['resources']
    default = json.loads((ROOT / 'ScoutSuite/providers' / case['provider'] / 'rules/rulesets/default.json').read_text())
    rules_path = tmp_path / 'rules.json'
    rules_path.write_text(json.dumps({'rules': {case['rule']: default['rules'][case['rule']]}}))
    ruleset = Ruleset(cloud_provider=case['provider'], filename=str(rules_path))
    service = next(iter(services))
    provider = SimpleNamespace(provider_code=case['provider'], services=services, service_list=[service])
    ProcessingEngine(ruleset).run(provider)
    assert not ERRORS_LIST, 'Failed rule evaluation must not pass as zero findings'
    findings = services[service]['findings']
    assert len(findings) == 1
    rule_key, finding = next(iter(findings.items()))
    assert finding['items'] == expected['items']
    assert finding['checked_items'] == expected['checked_items']
    assert finding['flagged_items'] == len(expected['items'])
    assert finding['level'] == expected['level']
    exceptions = {service: {rule_key: expected['items']}}
    exceptions_file = tmp_path / 'exceptions.js'
    exceptions_file.write_text('exceptions =\n' + json.dumps(exceptions))
    RuleExceptions(str(exceptions_file)).process(provider)
    assert finding['items'] == []
    assert finding['flagged_items'] == 0
    report = ScoutReport(case['provider'], report_name='offline', report_dir=str(tmp_path), result_format=case['format'])
    filename = Path(report.save(provider, exceptions, force_write=True))
    assert filename.is_file()
    html = filename.read_text()
    assert '<!-- RESULTS PLACEHOLDER -->' not in html
    assert 'services.id.findings.details.template' in html
    if case['format'] == 'json':
        saved = report.encoder.load_from_file('RESULTS')
    else:
        database, _ = get_filename('RESULTS', 'offline', str(tmp_path), file_extension='db')
        with SqliteDict(database) as data:
            saved = dict(data)
    assert saved['services'] == services
    assert report.exceptions_encoder.load_from_file('EXCEPTIONS') == exceptions
    assert (tmp_path / 'inc-jquery/jquery-3.3.1.min.js').is_file()
    assert not ERRORS_LIST, 'Serialization errors must fail the characterization'
