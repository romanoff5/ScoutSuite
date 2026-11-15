"""P5-D cross-account KMS: denied grants are not a verified empty list."""
import asyncio
from types import SimpleNamespace
from unittest.mock import patch

from botocore.exceptions import ClientError

from ScoutSuite.providers.aws.facade.kms import KMSFacade
from ScoutSuite.providers.aws.resources.kms.grants import Grants
from tests.test_p5d_attack_paths import ACCOUNT, scan

REGION = 'eu-central-1'


def census(client):
    with patch('ScoutSuite.providers.aws.facade.kms.AWSFacadeUtils.get_client',
               return_value=client):
        facade = KMSFacade(SimpleNamespace())
        return asyncio.run(facade.get_grants_with_status(REGION, 'key-1'))


def sample_grant(ident):
    return {
        'GrantId': ident, 'IssuingAccount': ACCOUNT,
        'GranteePrincipal': 'arn:aws:iam::999999999999:role/Reader',
        'Operations': ['Decrypt'], 'Constraints': {},
    }


def test_kms_list_grants_paginates_successfully_and_is_complete():
    class Client:
        def __init__(self):
            self.calls = []
        def list_grants(self, **kwargs):
            self.calls.append(kwargs)
            if kwargs.get('Marker') is None:
                return {'Grants': [sample_grant('g1')],
                        'Truncated': True, 'NextMarker': 'second'}
            return {'Grants': [sample_grant('g2')], 'Truncated': False}
    client = Client()
    grants, status = census(client)
    assert status == 'complete'
    assert [grant['GrantId'] for grant in grants] == ['g1', 'g2']
    assert client.calls == [
        {'KeyId': 'key-1', 'Limit': 100},
        {'KeyId': 'key-1', 'Limit': 100, 'Marker': 'second'}]


def test_kms_list_grants_access_denied_never_means_empty_success():
    class Client:
        def list_grants(self, **kwargs):
            raise ClientError(
                {'Error': {'Code': 'AccessDeniedException', 'Message': 'Denied'}},
                'ListGrants')
    records, status = census(Client())
    assert records == [] and status == 'partial'


def test_kms_list_grants_denied_on_second_page_retains_partial_witnesses():
    class Client:
        def list_grants(self, **kwargs):
            if kwargs.get('Marker') is None:
                return {'Grants': [sample_grant('g1')],
                        'Truncated': True, 'NextMarker': 'second'}
            raise PermissionError('AccessDenied')
    records, status = census(Client())
    assert [record['GrantId'] for record in records] == ['g1']
    assert status == 'partial'


def test_kms_grant_malformed_and_duplicate_pagination_fail_closed():
    class Client:
        def list_grants(self, **kwargs):
            if kwargs.get('Marker'):
                return {'Grants': [sample_grant('g1')], 'Truncated': False}
            return {'Grants': [sample_grant('g1')],
                    'Truncated': True, 'NextMarker': 'second'}
    records, status = census(Client())
    assert len(records) == 1 and status == 'partial'
    class Malformed:
        def list_grants(self, **kwargs):
            return {'Grants': 'not-a-list', 'Truncated': False}
    records, status = census(Malformed())
    assert records == [] and status == 'partial'


def test_grant_parser_never_crashes_on_missing_issuing_account():
    fake = SimpleNamespace(partition='aws', kms=SimpleNamespace())
    grants = Grants(fake, REGION, 'key-1')
    ident, row = grants._parse_grant({'GrantId': 'g1',
        'RetiringPrincipal': 'arn:aws:iam::999999999999:role/Retire'})
    assert ident == 'g1' and row['arn'] is None
    assert row['retiring_principal'].endswith('/Retire')


def test_kms_graph_marks_denied_or_truncated_key_grants_partial():
    key = {
        'arn': f'arn:aws:kms:{REGION}:{ACCOUNT}:key/uuid',
        'key_enabled': True, 'key_manager': 'CUSTOMER',
        'policy': {'Statement': []}, 'policy_collection_status': 'complete',
        'grants': {}, 'grants_collection_status': 'complete',
    }
    kms = {'regions': {REGION: {'keys': {'k': key}}}}
    graph, _ = scan(kms=kms)
    assert graph['status'] == 'complete'
    assert graph['collection']['kms_inventory'] == 'observed_bounded'
    key['grants_collection_status'] = 'partial'
    graph, _ = scan(kms=kms)
    assert graph['status'] == 'partial'
    assert graph['collection']['kms_inventory'] == 'partial'
    key['grants_collection_status'] = 'complete'
    key['policy_collection_status'] = 'failed'
    graph, _ = scan(kms=kms)
    assert graph['status'] == 'partial'


def test_kms_collection_status_is_visible_without_raw_grants():
    from pathlib import Path
    template = (Path(__file__).resolve().parents[1] /
        'ScoutSuite/output/data/html/partials/aws/services.kms.regions.id.keys.html').read_text()
    assert '{{policy_collection_status}}' in template
    assert '{{grants_collection_status}}' in template
    assert '{{{' not in template
