"""P2 integration: real AWS rule JSON traversal with read-only synthetic inventories."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ScoutSuite.core.utils import recurse
from ScoutSuite.core.rule_evidence import evaluate_rule_evidence

RULES = Path(__file__).resolve().parents[1] / 'ScoutSuite/providers/aws/rules/findings'
REGION = 'eu-central-1'


def check_rule(name, services):
    data = json.loads((RULES / name).read_text(encoding='utf-8'))
    cfg = SimpleNamespace(filename=name, path=data['path'], conditions=data['conditions'],
                          evidence_policy=data['evidence_policy'],
                          id_suffix=data.get('id_suffix'), checked_items=0)
    matches = recurse(services, services, cfg.path.split('.'), [], cfg, True)
    summary = evaluate_rule_evidence(cfg, services)
    return matches, summary

from ScoutSuite.providers.aws.facade.ec2 import EC2Facade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.ec2.p2_checks import (
    assess_account_imds_defaults, annotate_egress, annotate_ssh_key_reuse)
from ScoutSuite.providers.aws.resources.ec2.regional_settings import RegionalSettings


def test_account_imdsv2_policy_differentiates_default_enforcement_unknown():
    assert assess_account_imds_defaults({
        'HttpTokens': 'optional', 'HttpTokensEnforced': 'disabled'}) == 'not_required'
    assert assess_account_imds_defaults({
        'HttpTokens': 'no-preference', 'HttpTokensEnforced': 'disabled'}) == 'not_required'
    assert assess_account_imds_defaults({
        'HttpTokens': 'required', 'HttpTokensEnforced': 'disabled'}) == 'required_default'
    assert assess_account_imds_defaults({
        'HttpTokens': 'no-preference', 'HttpTokensEnforced': 'enabled'}) == 'required'
    assert assess_account_imds_defaults({
        'HttpTokens': 'optional'}) == 'unknown'
    assert assess_account_imds_defaults(None) == 'unknown'


def test_imds_account_region_setting_collected_and_flags_actual_rule():
    async def ebs(region):
        return {'EbsEncryptionByDefault': True}

    async def ebs_key(region):
        return {'KmsKeyId': 'arn:aws:kms:eu-central-1:123:key/test'}

    async def imds(region):
        return {'HttpTokens': 'optional', 'HttpTokensEnforced': 'disabled'}

    settings = RegionalSettings.__new__(RegionalSettings)
    settings.facade = SimpleNamespace(ec2=SimpleNamespace(
        get_ebs_encryption=ebs, get_ebs_default_encryption_key=ebs_key,
        get_instance_metadata_defaults=imds))
    settings.region = REGION
    asyncio.run(settings.fetch_all())
    services = {'ec2': {'regions': {REGION: {'regional_settings': {'0': settings[0]}}}}}
    matches, summary = check_rule('ec2-account-imdsv2-not-required-default.json', services)
    assert len(matches) == 1
    assert summary['counts']['insecure'] == 1
    settings[0]['account_imds_default_status'] = 'unknown'
    matches, summary = check_rule('ec2-account-imdsv2-not-required-default.json', services)
    assert matches == []
    assert summary['counts']['unknown'] == 1


def test_imds_denied_api_does_not_claim_account_default_is_secure():
    cli = SimpleNamespace(get_instance_metadata_defaults=lambda: (_ for _ in ()).throw(
        PermissionError('denied')))
    facade = EC2Facade(object(), '123456789012')
    with patch.object(AWSFacadeUtils, 'get_client', return_value=cli):
        assert asyncio.run(facade.get_instance_metadata_defaults(REGION)) is None


def _instance(key, groups, state='running'):
    return {'State': {'Name': state}, 'KeyName': key,
            'network_interfaces': {'eni0': {'Groups': [{'GroupId': g} for g in groups]}}}


def _sg(world=True):
    cidr = '0.0.0.0/0' if world else '10.0.0.0/8'
    return {'rules': {'egress': {'protocols': {'ALL': {
        'ports': {'1-65535': {'cidrs': [{'CIDR': cidr}]}}}}}}}


def test_ec2_broad_egress_and_keypair_reuse_through_actual_rules():
    vpcs = {'vpc1': {
        'security_groups': {'sg-public': _sg(), 'sg-restricted': _sg(False)},
        'instances': {
            'i1': _instance('shared', ['sg-public']),
            'i2': _instance('shared', ['sg-restricted']),
            'i3': _instance('unique', ['sg-public'], 'stopped'),
        }}}
    annotate_egress(vpcs)
    annotate_ssh_key_reuse(vpcs)
    services = {'ec2': {'regions': {REGION: {'vpcs': vpcs}}}}
    assert vpcs['vpc1']['security_groups']['sg-public'][
        'egress_world_all_protocols_status'] == 'unrestricted'
    assert vpcs['vpc1']['security_groups']['sg-restricted'][
        'egress_world_all_protocols_status'] == 'restricted'
    hits, summary = check_rule('ec2-security-group-all-egress-to-world.json', services)
    assert len(hits) == 1
    assert summary['counts']['insecure'] == 1
    hits, summary = check_rule('ec2-running-instances-share-ssh-key-name.json', services)
    assert len(hits) == 2
    assert summary['counts']['insecure'] == 2
    assert summary['counts']['not_applicable'] == 1


def test_ec2_unattached_group_and_missing_eni_never_false_positive():
    vpcs = {'vpc1': {'security_groups': {'sg1': _sg()},
                     'instances': {'i1': _instance('one', [], 'stopped')}}}
    annotate_egress(vpcs)
    assert vpcs['vpc1']['security_groups']['sg1'][
        'egress_world_all_protocols_status'] == 'not_applicable'
    vpcs['vpc1']['instances']['i1'] = {'State': {'Name': 'running'},
                                       'network_interfaces': None}
    annotate_egress(vpcs)
    assert vpcs['vpc1']['security_groups']['sg1'][
        'egress_world_all_protocols_status'] == 'unknown'
