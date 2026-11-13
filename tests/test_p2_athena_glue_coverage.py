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

from ScoutSuite.providers.aws.facade.athena_audit import AthenaAuditFacade
from ScoutSuite.providers.aws.facade.glue_audit import GlueAuditFacade
from ScoutSuite.providers.aws.resources.athena_audit import AthenaAudit
from ScoutSuite.providers.aws.resources.glue_audit import GlueAudit


def _athena_client():
    def list_groups(**kwargs):
        return {'WorkGroups': [
            {'Name': 'prod', 'State': 'ENABLED'},
            {'Name': 'secure', 'State': 'ENABLED'},
            {'Name': 'archived', 'State': 'DISABLED'}]}

    def get_group(WorkGroup):
        encrypted = WorkGroup == 'secure'
        return {'WorkGroup': {'Configuration': {
            'EnforceWorkGroupConfiguration': encrypted,
            'ResultConfiguration': {'EncryptionConfiguration': {
                'EncryptionOption': 'SSE_KMS' if encrypted else 'SSE_S3',
                'KmsKey': 'arn:aws:kms:eu-central-1:123:key/test'
            }}}}}
    return SimpleNamespace(list_work_groups=list_groups, get_work_group=get_group)


def test_athena_workgroup_inventory_and_both_real_findings():
    facade = AthenaAuditFacade(object())
    with patch.object(AWSFacadeUtils, 'get_client', return_value=_athena_client()):
        result = asyncio.run(facade.inventory_workgroups(REGION))
    assert result['status'] == 'complete'
    assert len(result['work_groups']) == 3
    assert next(x for x in result['work_groups'] if x['name'] == 'archived')[
        'enforcement_status'] == 'not_applicable'

    async def regions(*args, **kwargs):
        return [REGION]

    async def inventory(region):
        return result

    service = AthenaAudit.__new__(AthenaAudit)
    service.facade = SimpleNamespace(build_region_list=regions, athena=SimpleNamespace(
        inventory_workgroups=inventory))
    service.service = 'athena'
    asyncio.run(service.fetch_all())
    assert service['work_groups_count'] == 3
    services = {'athena': {'regions': service['regions']}}
    for key in ('athena-workgroup-settings-not-enforced.json',
                'athena-workgroup-results-kms-not-enforced.json'):
        hits, evidence = check_rule(key, services)
        assert len(hits) == 1
        assert evidence['counts']['insecure'] == 1
        assert evidence['counts']['not_applicable'] == 1


def test_athena_denied_list_is_unknown_not_clean():
    client = SimpleNamespace(list_work_groups=lambda **kw: (_ for _ in ()).throw(
        PermissionError('denied')))
    facade = AthenaAuditFacade(object())
    with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
        result = asyncio.run(facade.inventory_workgroups(REGION))
    assert result['status'] == 'unknown' and result['work_groups'] == []


def test_athena_partial_get_workgroup_preserves_unknown():
    client = SimpleNamespace(
        list_work_groups=lambda **kw: {'WorkGroups': [
            {'Name': 'a', 'State': 'ENABLED'}]},
        get_work_group=lambda **kw: (_ for _ in ()).throw(PermissionError('denied')))
    facade = AthenaAuditFacade(object())
    with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
        result = asyncio.run(facade.inventory_workgroups(REGION))
    assert result['status'] == 'partial'
    assert result['work_groups'][0]['enforcement_status'] == 'unknown'


def _glue_client(databases=True, connections=True, mode='DISABLED', password=False):
    return SimpleNamespace(
        get_databases=lambda **kw: {'DatabaseList': [{'Name': 'db'}] if databases else []},
        get_connections=lambda **kw: {'ConnectionList': [
            {'Name': 'secret'}] if connections else []},
        get_data_catalog_encryption_settings=lambda **kw: {
            'DataCatalogEncryptionSettings': {
                'EncryptionAtRest': {'CatalogEncryptionMode': mode},
                'ConnectionPasswordEncryption': {
                    'ReturnConnectionPasswordEncrypted': password}}})


def test_glue_usage_guard_prevents_unused_region_false_positive():
    facade = GlueAuditFacade(object())
    with patch.object(AWSFacadeUtils, 'get_client',
                      return_value=_glue_client(databases=False, connections=False)):
        result = asyncio.run(facade.inventory_catalog(REGION))
    assert result['status'] == 'complete'
    assert result['catalog_encryption_status'] == 'not_applicable'
    assert result['connection_password_status'] == 'not_applicable'


def test_glue_catalog_and_connection_password_security_rules():
    facade = GlueAuditFacade(object())
    with patch.object(AWSFacadeUtils, 'get_client', return_value=_glue_client()):
        result = asyncio.run(facade.inventory_catalog(REGION))
    assert result['status'] == 'complete'
    assert result['catalog_encryption_status'] == 'kms_not_configured'
    assert result['connection_password_status'] == 'unencrypted_response'

    async def regions(*args, **kwargs):
        return [REGION]

    async def inventory(region):
        return result

    service = GlueAudit.__new__(GlueAudit)
    service.facade = SimpleNamespace(build_region_list=regions,
                                     glue=SimpleNamespace(inventory_catalog=inventory))
    service.service = 'glue'
    asyncio.run(service.fetch_all())
    services = {'glue': {'regions': service['regions']}}
    for name in ('glue-catalog-kms-not-configured.json',
                 'glue-connection-password-encrypted-response-disabled.json'):
        hits, evidence = check_rule(name, services)
        assert len(hits) == 1 and evidence['counts']['insecure'] == 1


def test_glue_kms_and_password_encryption_configured():
    facade = GlueAuditFacade(object())
    with patch.object(AWSFacadeUtils, 'get_client', return_value=_glue_client(
        mode='SSE-KMS', password=True)):
        result = asyncio.run(facade.inventory_catalog(REGION))
    assert result['catalog_encryption_status'] == 'kms_configured'
    assert result['connection_password_status'] == 'encrypted_response'


def test_glue_denied_database_inventory_never_asserts_catalog_compliance():
    client = _glue_client()
    client.get_databases = lambda **kw: (_ for _ in ()).throw(PermissionError('denied'))
    facade = GlueAuditFacade(object())
    with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
        result = asyncio.run(facade.inventory_catalog(REGION))
    assert result['status'] == 'partial'
    assert result['catalog_encryption_status'] == 'unknown'


def test_glue_no_client_returns_unknown():
    facade = GlueAuditFacade(object())
    with patch.object(AWSFacadeUtils, 'get_client', return_value=None):
        assert asyncio.run(facade.inventory_catalog(REGION))['status'] == 'unknown'
