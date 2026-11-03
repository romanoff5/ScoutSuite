"""RC9: Secrets Manager metadata, rotation/unused/policy rules, and UNKNOWN on denial.

Synthetic identifiers only. The strict Stubber fails on any operation that was
not queued, so GetSecretValue can never be called unnoticed.
"""
import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import boto3
from botocore.stub import Stubber

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.rule_evidence import (classify_secret_policy_cross_account, classify_secret_policy_public,
                                           classify_secret_rotation, classify_secret_unused)
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.secretsmanager import SecretsManagerFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.secretsmanager.secrets import Secrets, analyze_policy

ROOT = Path(__file__).resolve().parents[1]
REGION = 'eu-central-1'
ACCOUNT = '000000000000'
OTHER = '111111111111'
NOW = datetime(2026, 11, 3, 12, tzinfo=timezone.utc)
LIST = {'MaxResults': 100, 'IncludePlannedDeletion': True}


def arn(name):
    return 'arn:aws:secretsmanager:%s:%s:secret:%s-AbCdEf' % (REGION, ACCOUNT, name)


def sdk():
    return boto3.client('secretsmanager', region_name=REGION, aws_access_key_id='synthetic',
                        aws_secret_access_key='synthetic')


def collect(add):
    async def scenario():
        client = sdk()
        try:
            with Stubber(client) as stub:
                add(stub)
                with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                    result = await SecretsManagerFacade(object()).get_secrets(REGION)
                stub.assert_no_pending_responses()
        finally:
            client.close()
        return result

    async def wrapper():
        ctx = RunContext('aws').setup()
        try:
            return await scenario(), list(ctx.collection_issues)
        finally:
            await ctx.aclose()
    return asyncio.run(wrapper())


def entry(name, **extra):
    return dict({'ARN': arn(name), 'Name': name, 'CreatedDate': NOW - timedelta(days=400)}, **extra)


def test_collects_metadata_and_policy_only():
    policy = {'Version': '2012-10-17', 'Statement': [
        {'Effect': 'Allow', 'Principal': {'AWS': 'arn:aws:iam::%s:root' % OTHER}, 'Action': 'secretsmanager:*',
         'Resource': '*'}]}

    def add(stub):
        stub.add_response('list_secrets', {'SecretList': [entry('db')]}, LIST)
        stub.add_response('describe_secret', {
            'ARN': arn('db'), 'Name': 'db', 'RotationEnabled': True, 'RotationLambdaARN': 'arn:aws:lambda:x',
            'RotationRules': {'AutomaticallyAfterDays': 30}, 'LastAccessedDate': NOW - timedelta(days=2),
            'Tags': [{'Key': 'owner', 'Value': 'team-a'}], 'CreatedDate': NOW - timedelta(days=400)},
            {'SecretId': arn('db')})
        stub.add_response('get_resource_policy', {'ARN': arn('db'), 'Name': 'db',
                                                  'ResourcePolicy': json.dumps(policy)}, {'SecretId': arn('db')})
    result, issues = collect(add)
    assert issues == []
    [raw] = result
    assert raw['_details_status'] == 'complete' and raw['_policy_status'] == 'present'
    _, secret = Secrets(SimpleNamespace(), REGION)._parse_secret(raw, NOW)
    assert secret['rotation_status'] == 'enabled' and secret['rotation_interval'] == 30
    assert secret['unused_status'] == 'in_use' and secret['days_since_last_access'] == 2
    assert secret['policy_exposure'] == 'cross_account'
    assert secret['policy_external_principals'] == ['arn:aws:iam::%s:root' % OTHER]
    assert secret['tags'] == [{'Key': 'owner', 'Value': 'team-a'}] and secret['arn'] == arn('db')
    assert 'SecretString' not in json.dumps(secret, default=str)
    source = (ROOT / 'ScoutSuite/providers/aws/facade/secretsmanager.py').read_text(encoding='utf-8')
    assert 'get_secret_value' not in source and 'batch_get_secret_value' not in source


def test_pagination_continues_until_backend_signals_completion():
    def add(stub):
        stub.add_response('list_secrets', {'SecretList': [entry('s%03d' % i) for i in range(100)],
                                           'NextToken': 'page-2'}, LIST)
        stub.add_response('list_secrets', {'SecretList': [entry('s100')]}, dict(LIST, NextToken='page-2'))
        for _ in range(101):
            stub.add_response('describe_secret', {}, None)
        for _ in range(101):
            stub.add_response('get_resource_policy', {}, None)
    result, issues = collect(add)
    assert len(result) == 101 and issues == []
    assert all(raw['_policy_status'] == 'none' for raw in result)


def test_denials_leave_evidence_unknown_and_are_recorded():
    def add(stub):
        stub.add_response('list_secrets', {'SecretList': [entry('db')]}, LIST)
        stub.add_client_error('describe_secret', service_error_code='AccessDeniedException', http_status_code=400)
        stub.add_client_error('get_resource_policy', service_error_code='AccessDeniedException', http_status_code=400)
    result, issues = collect(add)
    statuses = {(i['status'], i['reason_code']) for i in issues}
    assert statuses == {('denied', 'DescribeSecretAccessDenied'), ('denied', 'GetResourcePolicyAccessDenied')}
    _, secret = Secrets(SimpleNamespace(), REGION)._parse_secret(result[0], NOW)
    # Listing omits RotationEnabled for never-configured rotation, so it is not proof of "disabled".
    assert secret['rotation_status'] == 'unknown' and classify_secret_rotation(secret) == 'unknown'
    assert secret['unused_status'] == 'unknown' and classify_secret_unused(secret) == 'unknown'
    assert secret['policy_exposure'] == 'unknown' and classify_secret_policy_public(secret) == 'unknown'

    result, issues = collect(lambda s: s.add_client_error(
        'list_secrets', service_error_code='AccessDeniedException', http_status_code=400, expected_params=LIST))
    assert result == [] and issues == [{'status': 'denied', 'scope': 'secretsmanager',
                                        'reason_code': 'ListSecretsAccessDenied'}]


def test_rotation_and_unused_statuses():
    parse = Secrets(SimpleNamespace(), REGION)._parse_secret
    cases = [
        ({'RotationEnabled': False, '_details_status': 'complete'}, 'disabled'),
        ({'_details_status': 'complete'}, 'disabled'),  # DescribeSecret omits it when never configured.
        ({}, 'unknown'),
        ({'RotationEnabled': True, '_details_status': 'complete'}, 'enabled'),
        ({'RotationEnabled': False, 'DeletedDate': NOW, '_details_status': 'complete'}, 'scheduled_for_deletion'),
    ]
    for extra, expected in cases:
        assert parse(entry('x', **extra), NOW)[1]['rotation_status'] == expected, extra
    unused = [
        ({'LastAccessedDate': NOW - timedelta(days=91)}, 'unused', 'insecure'),
        ({'LastAccessedDate': NOW - timedelta(days=90)}, 'in_use', 'secure'),
        ({'_details_status': 'complete'}, 'unused', 'insecure'),  # Never retrieved, 400 days old.
        ({'_details_status': 'complete', 'CreatedDate': NOW - timedelta(days=10)}, 'recently_created', 'secure'),
        ({'_details_status': 'complete', 'CreatedDate': None}, 'unknown', 'unknown'),
        ({'LastAccessedDate': NOW - timedelta(days=200), 'DeletedDate': NOW}, 'scheduled_for_deletion',
         'not_applicable'),
    ]
    for extra, status, verdict in unused:
        secret = parse(entry('x', **extra), NOW)[1]
        assert secret['unused_status'] == status and classify_secret_unused(secret) == verdict, extra


def test_policy_exposure_analysis():
    def statement(principal, **extra):
        return dict({'Effect': 'Allow', 'Principal': principal, 'Action': 'secretsmanager:GetSecretValue'}, **extra)

    def exposure(*statements):
        return analyze_policy({'Statement': list(statements)}, 'present', ACCOUNT)[0]

    assert exposure(statement('*')) == 'public'
    assert exposure(statement({'AWS': ['*']})) == 'public'
    assert exposure(dict(statement({'AWS': 'arn:aws:iam::%s:root' % ACCOUNT}), Effect='Deny'),
                    {'Effect': 'Allow', 'NotPrincipal': {'AWS': ACCOUNT}, 'Action': '*'}) == 'public'
    assert exposure(statement('*', Condition={'StringEquals': {'aws:PrincipalOrgID': 'o-synthetic'}})) == 'conditional'
    assert exposure(statement('*', Condition={'Bool': {'aws:SecureTransport': 'true'}})) == 'public'
    assert exposure(statement({'AWS': 'arn:aws:iam::%s:role/app' % ACCOUNT})) == 'private'
    assert exposure(statement({'AWS': OTHER})) == 'cross_account'
    assert exposure(statement({'Service': 'lambda.amazonaws.com'})) == 'private'
    assert exposure(statement({'AWS': 'AROASYNTHETICUNIQUEID'})) == 'unknown'
    assert analyze_policy({}, 'none', ACCOUNT) == ('none', [])
    assert analyze_policy({}, 'unknown', ACCOUNT) == ('unknown', [])
    assert analyze_policy({'Statement': 'bad'}, 'present', ACCOUNT) == ('unknown', [])
    secret = {'policy_exposure': 'public'}
    assert classify_secret_policy_public(secret) == 'insecure'
    assert classify_secret_policy_cross_account(secret) == 'not_applicable'


RULES = ('secretsmanager-secret-rotation-disabled', 'secretsmanager-secret-unused',
         'secretsmanager-secret-policy-public', 'secretsmanager-secret-policy-cross-account')


def test_rules_flag_only_verified_insecure_secrets(tmp_path):
    rules = tmp_path / 'rules.json'
    rules.write_text(json.dumps({'about': 'Synthetic RC9', 'rules': {
        name + '.json': [{'enabled': True, 'level': 'warning'}] for name in RULES}}), encoding='utf-8')
    parse = Secrets(SimpleNamespace(), REGION)._parse_secret
    raw = {
        'bad': entry('bad', _details_status='complete', LastAccessedDate=NOW - timedelta(days=200),
                     _policy_status='present', policy={'Statement': [
                         {'Effect': 'Allow', 'Principal': '*', 'Action': '*'}]}),
        'good': entry('good', _details_status='complete', RotationEnabled=True,
                      LastAccessedDate=NOW - timedelta(days=1), _policy_status='none'),
        'shared': entry('shared', _details_status='complete', RotationEnabled=True,
                        LastAccessedDate=NOW - timedelta(days=1), _policy_status='present', policy={'Statement': [
                            {'Effect': 'Allow', 'Principal': {'AWS': OTHER}, 'Action': '*'}]}),
        'denied': entry('denied'),
    }
    secrets = {}
    for name, item in raw.items():
        secret = parse(item, NOW)[1]
        secrets[name] = secret
    provider = SimpleNamespace(services={'secretsmanager': {'regions': {REGION: {'secrets': secrets}}}},
                               service_list=['secretsmanager'])
    context = RunContext('aws').setup()
    try:
        ProcessingEngine(Ruleset('aws', filename=str(rules))).run(provider)
    finally:
        context.cleanup()
    findings = provider.services['secretsmanager']['findings']
    prefix = 'secretsmanager.regions.%s.secrets.' % REGION
    assert findings[RULES[0]]['items'] == [prefix + 'bad.rotation_status']
    assert findings[RULES[1]]['items'] == [prefix + 'bad.unused_status']
    assert findings[RULES[2]]['items'] == [prefix + 'bad.policy_exposure']
    assert findings[RULES[3]]['items'] == [prefix + 'shared.policy_exposure']
    for name in RULES:
        assert findings[name]['assessment_status'] == 'incomplete', name  # 'denied' is UNKNOWN everywhere.
        assert findings[name]['evaluation_summary']['counts']['unknown'] == 1, name


def test_rules_enabled_and_partial_shows_evidence():
    for ruleset in ('default.json', 'detailed.json'):
        rules = json.loads((ROOT / 'ScoutSuite/providers/aws/rules/rulesets' / ruleset).read_text())['rules']
        for name in RULES:
            assert rules[name + '.json'][0]['enabled'] is True
    text = (ROOT / 'ScoutSuite/output/data/html/partials/aws/services.secretsmanager.regions.id.secrets.html'
            ).read_text(encoding='utf-8')
    assert '{{{' not in text and 'onclick' not in text
    for field in ('rotation_status', 'unused_status', 'policy_exposure', 'policy_status'):
        assert '<samp>{{%s}}</samp>' % field in text
