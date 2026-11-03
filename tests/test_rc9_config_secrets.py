"""RC9: secrets in EC2 user data, Lambda and ECS environments are detected, never stored.

All "secrets" are synthetic strings built at runtime. Each test asserts that the
planted value does not appear anywhere in the serialized resource.
"""
import asyncio
import base64
import gzip
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import boto3
from botocore.stub import Stubber

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.rule_evidence import (classify_ec2_user_data_secrets, classify_ecs_environment_secrets,
                                           classify_lambda_environment_secrets)
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.ec2 import EC2Facade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.awslambda.functions import Functions
from ScoutSuite.providers.aws.resources.ec2.instances import EC2Instances
from ScoutSuite.providers.aws.resources.ecs_public.task_definitions import TaskDefinitions
from ScoutSuite.providers.aws.resources.secret_detection import detect_in_text, detect_in_variables

ROOT = Path(__file__).resolve().parents[1]
REGION = 'eu-central-1'
KEY_ID = 'AKIA' + 'SYNTHETIC0000001'
SECRET_KEY = 'Sy' + 'nThEtIc/0123456789abcdefABCDEF+wxyz012'
assert len(SECRET_KEY) == 40
PASSWORD = 'Synthetic-Passw0rd-Value'
PEM_BODY = 'MIIBOgIBAAJBAKsyntheticbodyonly'
SCRIPT = '\n'.join([
    '#!/bin/bash',
    'export AWS_ACCESS_KEY_ID=%s' % KEY_ID,
    'export AWS_SECRET_ACCESS_KEY=%s' % SECRET_KEY,
    'DB_URL=postgres://app:%s@db.internal.example:5432/app' % PASSWORD,
    'password=%s' % PASSWORD,
    'other=$DB_PASS',
    'sha1sum=da39a3ee5e6b4b0d3255bfef95601890afd80709',
    '-----BEGIN RSA PRIVATE KEY-----', PEM_BODY, '-----END RSA PRIVATE KEY-----',
])
PLANTED = (SECRET_KEY, PASSWORD, PEM_BODY)


def no_planted_values(value):
    text = json.dumps(value, default=str)
    return not any(secret in text for secret in PLANTED)


def test_text_detector_reports_location_and_masked_preview_only():
    found = detect_in_text(SCRIPT)
    kinds = {(row['type'], row['location']) for row in found}
    assert ('AWS access key ID', 'line 2') in kinds
    assert ('Possible AWS secret access key', 'line 3') in kinds
    assert ('Credentials in URL', 'line 4') in kinds
    assert ('Secret assignment (password)', 'line 5') in kinds
    assert ('Private key', 'line 8') in kinds
    assert not any(row['location'] in ('line 6', 'line 7') for row in found)  # $VAR and SHA-1 hex.
    assert {'type': 'AWS access key ID', 'location': 'line 2', 'preview': KEY_ID} in found  # Identifier kept.
    assert any(row['preview'] == 'postgres://app:[redacted: %d chars]@db.internal.example' % len(PASSWORD)
               for row in found)
    assert no_planted_values(found)
    assert detect_in_text('') == [] and detect_in_text(None) == []


def test_variable_detector_ignores_references_and_non_secret_names():
    found = detect_in_variables([
        ('DB_PASSWORD', PASSWORD),
        ('DB_PASSWORD_ARN', 'arn:aws:secretsmanager:eu-central-1:000000000000:secret:db-AbCdEf'),
        ('API_TOKEN', 'arn:aws:ssm:eu-central-1:000000000000:parameter/app/token'),
        ('PASSWORD_PARAMETER_NAME', '/app/db/password'),
        ('TABLE_NAME', 'orders'), ('LOG_LEVEL', 'debug'), ('SECRET_ROTATION_ENABLED', 'true'),
        ('SESSION_TOKEN', 'changeme'), ('UPSTREAM', 'https://svc:%s@api.example' % PASSWORD),
        ('ACCESS', KEY_ID)])
    assert [(row['type'], row['location']) for row in found] == [
        ('Sensitive variable name with literal value', 'environment: DB_PASSWORD'),
        ('Credentials in URL', 'environment: UPSTREAM'),
        ('AWS access key ID', 'environment: ACCESS')]
    assert no_planted_values(found)


def ec2_user_data(add):
    async def scenario():
        client = boto3.client('ec2', region_name=REGION, aws_access_key_id='synthetic',
                              aws_secret_access_key='synthetic')
        try:
            with Stubber(client) as stub:
                add(stub)
                with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                    result = await EC2Facade(object(), '000000000000').get_instance_user_data_evidence(
                        REGION, 'i-0123456789abcdef0')
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


PARAMS = {'Attribute': 'userData', 'InstanceId': 'i-0123456789abcdef0'}


def respond(value):
    body = {'InstanceId': 'i-0123456789abcdef0', 'UserData': {} if value is None else {'Value': value}}
    return lambda stub: stub.add_response('describe_instance_attribute', body, PARAMS)


def test_user_data_evidence_states_and_decoding():
    encoded = base64.b64encode(SCRIPT.encode()).decode()
    for value in (encoded, base64.b64encode(gzip.compress(SCRIPT.encode())).decode(),
                  base64.b64encode(encoded.encode()).decode()):
        (status, text), issues = ec2_user_data(respond(value))
        assert status == 'present' and text == SCRIPT and issues == []
    plain = '#!/bin/bash\necho ready\n'
    (status, text), _ = ec2_user_data(respond(base64.b64encode(plain.encode()).decode()))
    assert text == plain  # Plain scripts are not mangled by a second, lenient base64 pass.
    assert ec2_user_data(respond(None))[0] == ('absent', None)
    result, issues = ec2_user_data(lambda s: s.add_client_error(
        'describe_instance_attribute', service_error_code='UnauthorizedOperation', http_status_code=403,
        expected_params=PARAMS))
    assert result == ('unknown', None)
    assert issues == [{'status': 'denied', 'scope': 'ec2',
                       'reason_code': 'DescribeInstanceAttributeUserDataUnauthorizedOperation'}]


def test_instance_keeps_masked_evidence_not_user_data():
    evidence = EC2Instances._user_data_evidence('present', SCRIPT)
    assert 'user_data' not in evidence and no_planted_values(evidence)
    assert evidence['user_data_secret_status'] == 'detected' and evidence['user_data_format'] == 'shell-script'
    assert evidence['user_data_line_count'] == 10 and evidence['user_data_size_bytes'] == len(SCRIPT)
    assert classify_ec2_user_data_secrets(evidence) == 'insecure'
    clean = EC2Instances._user_data_evidence('present', '#cloud-config\npackages: [nginx]\n')
    assert clean['user_data_secret_status'] == 'none' and classify_ec2_user_data_secrets(clean) == 'secure'
    for status, expected, verdict in (('absent', 'no_user_data', 'not_applicable'), ('unknown', 'unknown', 'unknown'),
                                      ('undecodable', 'unknown', 'unknown'), ('present', 'unknown', 'unknown')):
        row = EC2Instances._user_data_evidence(status, None)
        assert row['user_data_secret_status'] == expected and classify_ec2_user_data_secrets(row) == verdict


def lambda_function(environment):
    function = {}

    async def scenario():
        ctx = RunContext('aws').setup()
        try:
            Functions._add_env_variables(function, environment)
            return list(ctx.collection_issues)
        finally:
            await ctx.aclose()
    return function, asyncio.run(scenario())


def test_lambda_environment_keeps_names_references_and_detections_only():
    reference = 'arn:aws:secretsmanager:eu-central-1:000000000000:secret:db-AbCdEf'
    function, issues = lambda_function({'Variables': {'DB_PASSWORD': PASSWORD, 'DB_SECRET_ARN': reference,
                                                      'STAGE': 'prod'}})
    assert issues == [] and no_planted_values(function)
    assert 'env_variable_values' not in function
    assert function['env_variable_names'] == ['DB_PASSWORD', 'DB_SECRET_ARN', 'STAGE']
    assert function['env_variables'] == {'DB_PASSWORD': '[redacted: %d chars]' % len(PASSWORD),
                                         'DB_SECRET_ARN': reference, 'STAGE': '[redacted: 4 chars]'}
    assert function['env_secret_status'] == 'detected' and classify_lambda_environment_secrets(function) == 'insecure'
    assert lambda_function(None)[0]['env_secret_status'] == 'no_variables'
    assert lambda_function({'Variables': {'STAGE': 'prod'}})[0]['env_secret_status'] == 'none'
    function, issues = lambda_function({'Error': {'ErrorCode': 'KMSAccessDeniedException', 'Message': 'synthetic'}})
    assert function['env_secret_status'] == 'unknown' and classify_lambda_environment_secrets(function) == 'unknown'
    assert function['env_variables_error_code'] == 'KMSAccessDeniedException'
    assert issues == [{'status': 'partial', 'scope': 'lambda', 'reason_code': 'EnvironmentVariablesUnreadable'}]


def ecs_task(containers):
    async def scenario():
        ctx = RunContext('aws').setup()
        try:
            item = {'taskDefinitionArn': 'arn:aws:ecs:eu-central-1:000000000000:task-definition/app:1',
                    'family': 'app', 'revision': 1, 'status': 'ACTIVE', 'containerDefinitions': containers}
            resources = TaskDefinitions(SimpleNamespace(ecs=SimpleNamespace(
                get_task_definitions=AsyncMock(return_value=[item]))), REGION)
            await resources.fetch_all()
            return list(resources.values())[0]
        finally:
            await ctx.aclose()
    return asyncio.run(scenario())


def test_ecs_environment_detection_without_serializing_values():
    task = ecs_task([{'name': 'web', 'image': 'nginx', 'environment': [
        {'name': 'API_KEY', 'value': PASSWORD}, {'name': 'PORT', 'value': '8080'}],
        'secrets': [{'name': 'DB_PASSWORD', 'valueFrom': 'arn:aws:ssm:eu-central-1:000000000000:parameter/db'}]}])
    assert no_planted_values(task) and task['environment_secret_status'] == 'detected'
    assert task['containers'][0]['environment_secret_detections'][0]['location'] == 'environment: API_KEY'
    assert classify_ecs_environment_secrets(task) == 'insecure'
    clean = ecs_task([{'name': 'web', 'secrets': [{'name': 'DB_PASSWORD', 'valueFrom': 'arn:aws:ssm:x'}],
                       'environment': [{'name': 'PORT', 'value': '8080'}]}])
    assert clean['environment_secret_status'] == 'none'
    assert ecs_task([{'name': 'web'}])['environment_secret_status'] == 'no_variables'
    broken = ecs_task([{'name': 'web', 'environment': 'not-a-list'}])
    assert broken['environment_secret_status'] == 'unknown' and classify_ecs_environment_secrets(broken) == 'unknown'


def test_secret_rules_flag_detected_and_mark_unreadable_incomplete(tmp_path):
    rules = tmp_path / 'rules.json'
    rules.write_text(json.dumps({'about': 'Synthetic RC9', 'rules': {name: [{'enabled': True, 'level': 'danger'}]
                     for name in ('ec2-instance-with-user-data-secrets.json', 'awslambda-function-env-secrets.json',
                                  'ecs-task-definition-environment-secrets.json')}}), encoding='utf-8')
    instances = {'i-bad': EC2Instances._user_data_evidence('present', SCRIPT),
                 'i-none': EC2Instances._user_data_evidence('absent', None),
                 'i-denied': EC2Instances._user_data_evidence('unknown', None)}
    functions = {'bad': lambda_function({'Variables': {'DB_PASSWORD': PASSWORD}})[0],
                 'ok': lambda_function({'Variables': {'STAGE': 'prod'}})[0]}
    tasks = {'bad': dict(ecs_task([{'name': 'web', 'environment': [{'name': 'TOKEN', 'value': PASSWORD}]}]))}
    provider = SimpleNamespace(services={
        'ec2': {'regions': {REGION: {'vpcs': {'vpc-1': {'instances': instances}}}}},
        'awslambda': {'regions': {REGION: {'functions': functions}}},
        'ecs': {'regions': {REGION: {'task_definitions': tasks}}}}, service_list=['ec2', 'awslambda', 'ecs'])
    context = RunContext('aws').setup()
    try:
        ProcessingEngine(Ruleset('aws', filename=str(rules))).run(provider)
    finally:
        context.cleanup()
    ec2 = provider.services['ec2']['findings']['ec2-instance-with-user-data-secrets']
    assert ec2['items'] == ['ec2.regions.%s.vpcs.vpc-1.instances.i-bad.potential_secrets' % REGION]
    assert ec2['assessment_status'] == 'incomplete'
    assert ec2['evaluation_summary']['counts'] == {'secure': 0, 'insecure': 1, 'unknown': 1, 'not_applicable': 1}
    lam = provider.services['awslambda']['findings']['awslambda-function-env-secrets']
    assert lam['items'] == ['awslambda.regions.%s.functions.bad.env_secret_status' % REGION]
    assert lam['flagged_items'] == 1 and lam['checked_items'] == 2
    ecs = provider.services['ecs']['findings']['ecs-task-definition-environment-secrets']
    assert ecs['items'] == ['ecs.regions.%s.task_definitions.%s.EnvironmentSecrets' % (REGION, list(tasks)[0])]


def test_partials_show_masked_evidence_and_never_raw_values():
    partials = ROOT / 'ScoutSuite/output/data/html/partials/aws'
    ec2 = (partials / 'services.ec2.regions.id.vpcs.id.instances.html').read_text(encoding='utf-8')
    lam = (partials / 'services.awslambda.regions.id.functions.html').read_text(encoding='utf-8')
    for text in (ec2, lam):
        assert '{{{' not in text and '<code>{{preview}}</code>' in text
    assert 'split_lines user_data' not in ec2 and '<samp>{{user_data_secret_status}}</samp>' in ec2
    assert "document = env_variables" not in lam and '<samp>{{env_secret_status}}</samp>' in lam
    for ruleset in ('default.json', 'detailed.json'):
        rules = json.loads((ROOT / 'ScoutSuite/providers/aws/rules/rulesets' / ruleset).read_text())['rules']
        for name in ('awslambda-function-env-secrets.json', 'ecs-task-definition-environment-secrets.json'):
            assert rules[name] == [{'enabled': True, 'level': 'danger'}]
