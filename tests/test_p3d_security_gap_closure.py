"""P3-D: synthetic AWS source-to-finding, denied API and semantic regression."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from ScoutSuite.core.rule_evidence import evaluate_rule_evidence
from ScoutSuite.core.utils import recurse
from ScoutSuite.providers.aws.facade.elbv2 import ELBv2Facade
from ScoutSuite.providers.aws.facade.rds import RDSFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.elbv2.p3d_health import annotate_alb_health
from ScoutSuite.providers.aws.resources.iam.p3d_s3_grants import (
    _inspect_policy, annotate_instance_s3_grants)
from ScoutSuite.providers.aws.resources.rds.p3d_monitoring import correlate_rds_monitoring

REGION = 'eu-central-1'
RULES = Path(__file__).resolve().parents[1] / 'ScoutSuite/providers/aws/rules/findings'


def actual(name, services):
    doc = json.loads((RULES / name).read_text(encoding='utf-8'))
    rule = SimpleNamespace(
        filename=name, path=doc['path'], conditions=doc['conditions'],
        evidence_policy=doc['evidence_policy'], id_suffix=doc.get('id_suffix'),
        checked_items=0)
    hits = recurse(services, services, rule.path.split('.'), [], rule, True)
    return hits, evaluate_rule_evidence(rule, services)['counts']


def alb_inventory(state='unhealthy', reason='Target.ResponseCodeMismatch', complete='complete'):
    lb = {'Type': 'application', 'target_group_inventory_status': complete,
          'target_groups': [{
              'arn': 'arn:aws:elasticloadbalancing:eu-central-1:111:targetgroup/app/1',
              'name': 'app', 'protocol': 'HTTP', 'port': 8080, 'target_type': 'instance',
              'health_check': {'HealthCheckPath': '/health', 'HealthCheckProtocol': 'HTTP',
                               'HealthCheckPort': 'traffic-port', 'Matcher': {'HttpCode': '200'}},
              'registered_targets': [{'id': 'i-123', 'port': 8080, 'health_state': state,
                                      'health_reason': reason,
                                      'health_description': 'Health checks returned HTTP 302'}]
          }]}
    return {'elbv2': {'regions': {REGION: {'vpcs': {'vpc-a': {'lbs': {'alb': lb}}}}}}}, lb


def test_alb_response_code_mismatch_reports_actual_reason_and_health_settings():
    services, lb = alb_inventory()
    annotate_alb_health(services)
    assert lb['p3d_health_mismatch_status'] == 'response_mismatch'
    evidence = lb['p3d_health_mismatch_evidence'][0]
    assert evidence['reason'] == 'Target.ResponseCodeMismatch'
    assert evidence['health_check']['HealthCheckPath'] == '/health'
    flagged, counts = actual('elbv2-alb-health-check-response-mismatch.json', services)
    assert len(flagged) == 1 and counts['insecure'] == 1


@pytest.mark.parametrize('state,reason,mismatch,unhealthy', [
    ('healthy', None, 'not_observed', 'not_observed'),
    ('unhealthy', 'Target.Timeout', 'not_observed', 'other_unhealthy'),
    ('initial', 'Elb.InitialHealthChecking', 'unknown', 'unknown'),
    ('unused', 'Target.NotInUse', 'unknown', 'unknown')
])
def test_alb_other_states_do_not_invent_healthcheck_config_mismatch(state, reason, mismatch, unhealthy):
    services, lb = alb_inventory(state, reason)
    annotate_alb_health(services)
    assert lb['p3d_health_mismatch_status'] == mismatch
    assert lb['p3d_unhealthy_status'] == unhealthy
    flagged, counts = actual('elbv2-alb-other-unhealthy-targets.json', services)
    assert bool(flagged) == (state == 'unhealthy')
    assert counts['insecure'] == (1 if state == 'unhealthy' else 0)


def test_alb_denied_and_incomplete_target_data_are_unknown_not_pass():
    services, lb = alb_inventory(complete='unknown')
    annotate_alb_health(services)
    assert lb['p3d_health_mismatch_status'] == 'unknown'
    flagged, counts = actual('elbv2-alb-health-check-response-mismatch.json', services)
    assert not flagged and counts['unknown'] == 1
    lb['target_group_inventory_status'] = 'complete'
    lb['target_groups'][0]['registered_targets'][0]['health_state'] = None
    annotate_alb_health(services)
    assert lb['p3d_health_mismatch_status'] == 'unknown'


def test_elbv2_collector_retains_health_check_and_target_reason():
    client = SimpleNamespace(
        describe_target_groups=lambda **kw: {'TargetGroups': [{
            'TargetGroupArn': 'arn:synthetic:tg', 'TargetGroupName': 'svc',
            'TargetType': 'instance', 'Protocol': 'HTTP', 'Port': 8080,
            'HealthCheckPath': '/status', 'HealthCheckPort': 'traffic-port',
            'HealthCheckProtocol': 'HTTP', 'Matcher': {'HttpCode': '200'}}]},
        describe_target_health=lambda **kw: {'TargetHealthDescriptions': [{
            'Target': {'Id': 'i-123', 'Port': 8080},
            'TargetHealth': {'State': 'unhealthy', 'Reason': 'Target.ResponseCodeMismatch',
                             'Description': 'Health checks returned 302'}}]})
    facade = ELBv2Facade(object())
    with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
        status, rows = asyncio.run(facade.get_target_group_inventory(REGION, 'arn:synthetic:lb'))
    assert status == 'complete'
    assert rows[0]['health_check']['HealthCheckPath'] == '/status'
    assert rows[0]['registered_targets'][0]['health_reason'] == 'Target.ResponseCodeMismatch'


def _iam_inventory(actions=('s3:Get*', 's3:List*'), resource='*', condition=None):
    statement = {'Effect': 'Allow', 'Action': list(actions), 'Resource': resource}
    if condition:
        statement['Condition'] = condition
    role = {'arn': 'arn:aws:iam::111111111111:role/service',
            'instance_profiles': {'AIP-SYNTH': {'arn': 'arn:synthetic:profile'}},
            'inline_policies': {}, 'policies': ['POL-SYNTH']}
    instance = {'State': {'Name': 'running'}, 'iam_instance_profile_id': 'AIP-SYNTH'}
    services = {
        'iam': {'roles': {'ARO-SYNTH': role},
                'policies': {'POL-SYNTH': {'arn': 'arn:synthetic:policy',
                                          'PolicyDocument': {'Statement': [statement]}}}},
        'ec2': {'regions': {REGION: {'vpcs': {'vpc-a': {'instances': {'i-123': instance}}}}}}
    }
    return services, instance


def test_s3_wildcard_get_list_policies_reach_the_actual_ec2_finding():
    services, instance = _iam_inventory()
    annotate_instance_s3_grants(services, ('ec2', 'iam'))
    assert instance['s3_wildcard_read_status'] == 'broad_grant_candidate'
    assert len(instance['s3_wildcard_read_evidence']) == 2
    assert instance['s3_wildcard_read_role_arns'][0].endswith(':role/service')
    flagged, counts = actual('ec2-running-instance-role-broad-s3-read-candidate.json', services)
    assert len(flagged) == 1 and counts['insecure'] == 1


@pytest.mark.parametrize('actions,resource', [
    (('s3:ListAllMyBuckets',), '*'),
    (('s3:GetObject',), 'arn:aws:s3:::approved/*')
])
def test_scoped_read_and_required_account_list_are_not_broad_candidates(actions, resource):
    services, instance = _iam_inventory(actions, resource)
    annotate_instance_s3_grants(services, ('ec2', 'iam'))
    assert instance['s3_wildcard_read_status'] == 'no_broad_grant_observed'


def test_condition_unsupported_document_and_missing_iam_are_unknown():
    services, instance = _iam_inventory(condition={'StringEquals': {'s3:prefix': 'approved/'}})
    annotate_instance_s3_grants(services, ('ec2', 'iam'))
    assert instance['s3_wildcard_read_status'] == 'unknown'
    del services['iam']['policies']['POL-SYNTH']
    annotate_instance_s3_grants(services, ('ec2', 'iam'))
    assert instance['s3_wildcard_read_status'] == 'unknown'
    annotate_instance_s3_grants(services, ('ec2',))
    assert instance['s3_wildcard_read_status'] == 'unknown'
    flagged, counts = actual('ec2-running-instance-role-broad-s3-read-candidate.json', services)
    assert not flagged and counts['unknown'] == 1


def test_profile_not_role_name_and_stopped_instance_not_applicable():
    services, instance = _iam_inventory()
    instance['State']['Name'] = 'stopped'
    annotate_instance_s3_grants(services, ('ec2', 'iam'))
    assert instance['s3_wildcard_read_status'] == 'not_applicable'
    instance['State']['Name'] = 'running'
    instance['iam_instance_profile_id'] = 'unexpected-profile'
    annotate_instance_s3_grants(services, ('ec2', 'iam'))
    assert instance['s3_wildcard_read_status'] == 'unknown'


def test_notaction_and_notresource_do_not_return_secure_evidence():
    for condition in ({'NotAction': ['s3:DeleteObject'], 'Resource': '*'},
                      {'Action': ['s3:Get*'], 'NotResource': ['arn:aws:s3:::public/*']}):
        document = {'Statement': [{'Effect': 'Allow', **condition}]}
        hits, incomplete = _inspect_policy(document, 'synthetic', 'inline')
        assert not hits and incomplete


def _db_inventory(alarm=True, subscription=True, complete=True):
    rds = {'instances': {'standalone': {'name': 'db-standalone', 'DBClusterIdentifier': None}}}
    cluster = {'name': 'cluster-one', 'DBClusterIdentifier': 'cluster-one',
               'DBClusterMembers': ['member-1']}
    db_region = {'vpcs': {'vpc-a': rds}, 'clusters': {'cluster-one': cluster},
                 'event_subscriptions_inventory_status': 'complete' if complete else 'partial',
                 'event_subscriptions': []}
    if subscription:
        for kind, identifier in [('db-instance', 'db-standalone'), ('db-cluster', 'cluster-one')]:
            db_region['event_subscriptions'].append({
                'SourceType': kind, 'SourceIds': [identifier], 'Enabled': True,
                'Status': 'active', 'CustSubscriptionId': 'events-' + kind,
                'SnsTopicArn': 'arn:synthetic:topic'})
    alarms = {}
    if alarm:
        for kind, identifier in [('DBInstanceIdentifier', 'db-standalone'),
                                 ('DBClusterIdentifier', 'cluster-one')]:
            alarms[identifier] = {
                'name': 'alarm-' + identifier, 'arn': 'arn:synthetic:alarm',
                'Namespace': 'AWS/RDS', 'MetricName': 'CPUUtilization',
                'Dimensions': [{'Name': kind, 'Value': identifier}],
                'ActionsEnabled': True, 'AlarmActions': ['arn:synthetic:notify']}
    return {'rds': {'regions': {REGION: db_region}},
            'cloudwatch': {'regions': {REGION: {
                'alarms': alarms, 'metric_alarms_collection_status': 'complete' if complete else 'unknown'
            }}}}, rds['instances']['standalone'], cluster


def test_rds_instance_cluster_actionable_alarms_and_active_events():
    services, instance, cluster = _db_inventory()
    correlate_rds_monitoring(services, ('rds', 'cloudwatch'))
    for item in (instance, cluster):
        assert item['rds_alarm_status'] == 'actionable'
        assert item['rds_event_subscription_status'] == 'active'
    for rule in ('rds-db-instance-no-actionable-alarm.json',
                 'rds-db-instance-event-subscription-missing.json',
                 'rds-db-cluster-no-actionable-alarm.json',
                 'rds-db-cluster-event-subscription-missing.json'):
        flagged, counts = actual(rule, services)
        assert not flagged and counts['secure'] == 1


def test_rds_missing_metric_alarms_and_event_subscriptions_flag_both_scopes():
    services, instance, cluster = _db_inventory(alarm=False, subscription=False)
    correlate_rds_monitoring(services, ('rds', 'cloudwatch'))
    for item in (instance, cluster):
        assert item['rds_alarm_status'] == 'missing'
        assert item['rds_event_subscription_status'] == 'missing'
    for rule in ('rds-db-instance-no-actionable-alarm.json',
                 'rds-db-instance-event-subscription-missing.json',
                 'rds-db-cluster-no-actionable-alarm.json',
                 'rds-db-cluster-event-subscription-missing.json'):
        flagged, counts = actual(rule, services)
        assert len(flagged) == 1 and counts['insecure'] == 1


def test_rds_partial_census_and_missing_cloudwatch_do_not_mean_no_alerts():
    services, instance, cluster = _db_inventory(alarm=False, subscription=False, complete=False)
    correlate_rds_monitoring(services, ('rds', 'cloudwatch'))
    assert instance['rds_alarm_status'] == 'unknown'
    assert cluster['rds_event_subscription_status'] == 'unknown'
    services['cloudwatch']['regions'].clear()
    correlate_rds_monitoring(services, ('rds',))
    assert instance['rds_alarm_status'] == 'unknown'
    flagged, counts = actual('rds-db-instance-no-actionable-alarm.json', services)
    assert not flagged and counts['unknown'] == 1


def test_rds_global_enabled_subscription_counts_for_every_matching_source():
    services, instance, _ = _db_inventory(alarm=False, subscription=True)
    subscriptions = services['rds']['regions'][REGION]['event_subscriptions']
    subscriptions[0]['SourceIds'] = []  # applies to all DB instances
    correlate_rds_monitoring(services, ('rds', 'cloudwatch'))
    assert instance['rds_event_subscription_status'] == 'active'


def test_rds_disabled_alarm_or_subscription_is_not_actionable():
    services, instance, _ = _db_inventory()
    alarms = services['cloudwatch']['regions'][REGION]['alarms']
    alarms['db-standalone']['ActionsEnabled'] = False
    subscriptions = services['rds']['regions'][REGION]['event_subscriptions']
    subscriptions[0]['Enabled'] = False
    correlate_rds_monitoring(services, ('rds', 'cloudwatch'))
    assert instance['rds_alarm_status'] == 'no_action'
    assert instance['rds_event_subscription_status'] == 'inactive'


def test_rds_metric_expression_uncertainty_is_not_a_pass():
    services, instance, _ = _db_inventory(alarm=False, subscription=False)
    services['cloudwatch']['regions'][REGION]['alarms']['expr'] = {
        'name': 'metric-math', 'Metrics': [{'Expression': "SEARCH('{AWS/RDS} CPUUtilization', Average, 60)"}],
        'ActionsEnabled': True, 'AlarmActions': ['arn:synthetic:notify']}
    correlate_rds_monitoring(services, ('rds', 'cloudwatch'))
    assert instance['rds_alarm_status'] == 'unknown'


def test_rds_subscription_collector_pagination_and_access_denied_are_not_empty():
    calls = []
    def pages(**kwargs):
        calls.append(kwargs)
        if 'Marker' not in kwargs:
            return {'EventSubscriptionsList': [{'CustSubscriptionId': 'one'}], 'Marker': 'next'}
        return {'EventSubscriptionsList': [{'CustSubscriptionId': 'two'}]}
    client = SimpleNamespace(describe_event_subscriptions=pages)
    facade = RDSFacade(object())
    with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
        status, rows = asyncio.run(facade.get_event_subscriptions(REGION))
    assert status == 'complete' and len(rows) == 2 and calls[1]['Marker'] == 'next'
    def denial(**kwargs):
        if 'Marker' in kwargs:
            raise PermissionError('denied')
        return {'EventSubscriptionsList': [{'CustSubscriptionId': 'one'}], 'Marker': 'next'}
    client.describe_event_subscriptions = denial
    with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
        status, rows = asyncio.run(facade.get_event_subscriptions(REGION))
    assert status == 'partial' and len(rows) == 1
    with patch.object(AWSFacadeUtils, 'get_client', return_value=None):
        status, rows = asyncio.run(facade.get_event_subscriptions(REGION))
    assert status == 'unknown' and rows == []
