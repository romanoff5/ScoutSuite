"""P2 source-to-rule tests for new read-only AWS services and SSM sharing."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ScoutSuite.core.utils import recurse
from ScoutSuite.core.rule_evidence import evaluate_rule_evidence
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils

RULES = Path(__file__).resolve().parents[1] / 'ScoutSuite/providers/aws/rules/findings'
REGION = 'eu-central-1'


def check_rule(name, services):
    rule = json.loads((RULES / name).read_text(encoding='utf-8'))
    cfg = SimpleNamespace(filename=name, path=rule['path'],
                          conditions=rule['conditions'],
                          evidence_policy=rule['evidence_policy'],
                          id_suffix=rule.get('id_suffix'), checked_items=0)
    hits = recurse(services, services, cfg.path.split('.'), [], cfg, True)
    evidence = evaluate_rule_evidence(cfg, services)
    return hits, evidence

from ScoutSuite.providers.aws.facade.ssm_public import SSMPublicFacade
from ScoutSuite.providers.aws.resources.ssm.base import SSMPublic


def _ssm_client():
    names = [{'Name': 'PublicDoc'}, {'Name': 'PrivateDoc'}]

    def perm(**kwargs):
        return {'AccountIds': ['all'] if kwargs['Name'] == 'PublicDoc' else ['123456789012']}

    return SimpleNamespace(list_documents=lambda **kw: {'DocumentIdentifiers': names},
                           describe_document_permission=perm)


def test_ssm_owned_public_documents_only_and_actual_rule():
    facade = SSMPublicFacade(object())
    with patch.object(AWSFacadeUtils, 'get_client', return_value=_ssm_client()):
        result = asyncio.run(facade.get_document_shares(REGION))
    assert result['status'] == 'complete'
    assert sorted(x['public_sharing_status'] for x in result['documents']) == [
        'private', 'public']

    async def regions(*args, **kwargs):
        return [REGION]

    async def inventory(region):
        return {}

    async def sharing(region):
        return result

    resource = SSMPublic.__new__(SSMPublic)
    resource.service = 'ssm'
    resource.facade = SimpleNamespace(build_region_list=regions, ssm=SimpleNamespace(
        inventory=inventory, get_document_shares=sharing))
    asyncio.run(resource.fetch_all())
    assert resource['documents_count'] == 2
    services = {'ssm': {'regions': resource['regions']}}
    hits, evidence = check_rule('ssm-document-publicly-shared.json', services)
    assert len(hits) == 1 and evidence['counts']['insecure'] == 1
    assert evidence['counts']['secure'] == 1


def test_ssm_denied_list_does_not_claim_private_documents():
    client = SimpleNamespace(list_documents=lambda **kw: (_ for _ in ()).throw(
        PermissionError('denied')))
    facade = SSMPublicFacade(object())
    with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
        result = asyncio.run(facade.get_document_shares(REGION))
    assert result['status'] == 'unknown' and result['documents'] == []


def test_ssm_partial_document_permissions_remain_unknown():
    cli = _ssm_client()
    original = cli.describe_document_permission
    def permissions(**kw):
        if kw['Name'] == 'PrivateDoc':
            raise PermissionError('denied')
        return original(**kw)
    cli.describe_document_permission = permissions
    facade = SSMPublicFacade(object())
    with patch.object(AWSFacadeUtils, 'get_client', return_value=cli):
        result = asyncio.run(facade.get_document_shares(REGION))
    assert result['status'] == 'partial'
    statuses = {r['name']: r['public_sharing_status'] for r in result['documents']}
    assert statuses['PublicDoc'] == 'public'
    assert statuses['PrivateDoc'] == 'unknown'


def test_ssm_no_client_unknown():
    facade = SSMPublicFacade(object())
    with patch.object(AWSFacadeUtils, 'get_client', return_value=None):
        result = asyncio.run(facade.get_document_shares(REGION))
    assert result['status'] == 'unknown'
