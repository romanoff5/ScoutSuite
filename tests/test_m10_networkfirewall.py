"""M10-M: Network Firewall SDK, collection, routing and rule-evidence contracts."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, AsyncMock

import boto3
from botocore.session import get_session
from botocore.stub import Stubber

from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.networkfirewall import (
    NetworkFirewallFacade, PAGE_SIZE, broad_pass)
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.networkfirewall.base import NetworkFirewallPublic

REGION = 'us-east-1'
ACCOUNT = '000000000000'
FW = 'arn:aws:network-firewall:us-east-1:000000000000:firewall/fw'
POLICY = 'arn:aws:network-firewall:us-east-1:000000000000:firewall-policy/policy'
GROUP = 'arn:aws:network-firewall:us-east-1:000000000000:stateful-rulegroup/rules'
ROOT = Path(__file__).resolve().parents[1]


def sdk(service):
    return boto3.client(service, region_name=REGION,
                        aws_access_key_id='dummy', aws_secret_access_key='dummy')


def test_sdk_contract_is_read_only_and_paginated():
    model = get_session().get_service_model('network-firewall')
    for name in ('ListFirewalls', 'ListFirewallPolicies', 'ListRuleGroups'):
        assert {'MaxResults', 'NextToken'} <= set(model.operation_model(name).input_shape.members)
    for name in ('DescribeFirewall', 'DescribeFirewallPolicy',
                 'DescribeRuleGroup', 'DescribeLoggingConfiguration'):
        assert name in model.operation_names
    ec2 = get_session().get_service_model('ec2')
    assert 'Filters' in ec2.operation_model('DescribeRouteTables').input_shape.members


def test_broad_pass_flags_only_universal_pass_without_constraints():
    stateless = {'RulesSource': {'StatelessRulesAndCustomActions': {
        'StatelessRules': [{
            'RuleDefinition': {
                'Actions': ['aws:pass'],
                'MatchAttributes': {'Sources': [{'AddressDefinition': '0.0.0.0/0'}],
                                    'Destinations': [{'AddressDefinition': '0.0.0.0/0'}]}}}]}}}
    assert broad_pass(stateless, 'STATELESS')
    stateless['RulesSource']['StatelessRulesAndCustomActions']['StatelessRules'][0][
        'RuleDefinition']['MatchAttributes']['DestinationPorts'] = [{'FromPort': 443, 'ToPort': 443}]
    assert not broad_pass(stateless, 'STATELESS')
    rule = {'RulesSource': {'StatefulRules': [{
        'Action': 'PASS', 'Header': {'Protocol': 'IP', 'Source': 'ANY',
                                  'Destination': 'ANY', 'SourcePort': 'ANY',
                                  'DestinationPort': 'ANY', 'Direction': 'ANY'}}]}}
    assert broad_pass(rule, 'STATEFUL')
    rule['RulesSource']['StatefulRules'][0]['Header']['Source'] = '10.0.0.0/8'
    assert not broad_pass(rule, 'STATEFUL')
    assert broad_pass({'RulesSource': {'RulesString':
                      'pass ip any any -> any any (sid:123; rev:1;)'}}, 'STATEFUL')
    assert not broad_pass({'RulesSource': {'RulesString':
                          '# pass ip any any -> any any (sid:123;)'}}, 'STATEFUL')


def test_full_stubber_inventory_unknown_vs_referenced_routing():
    async def scenario(route_present):
        nf, ec2 = sdk('network-firewall'), sdk('ec2')
        try:
            with Stubber(nf) as n, Stubber(ec2) as e:
                n.add_response('list_firewalls', {
                    'Firewalls': [{'FirewallName': 'fw', 'FirewallArn': FW}],
                    'NextToken': 'second'}, {'MaxResults': PAGE_SIZE})
                n.add_response('list_firewalls', {'Firewalls': []},
                               {'MaxResults': PAGE_SIZE, 'NextToken': 'second'})
                n.add_response('list_firewall_policies', {'FirewallPolicies': [
                    {'Name': 'policy', 'Arn': POLICY}]}, {'MaxResults': PAGE_SIZE})
                n.add_response('list_rule_groups', {'RuleGroups': [
                    {'Name': 'rules', 'Arn': GROUP}]}, {'MaxResults': PAGE_SIZE})
                n.add_response('describe_firewall_policy', {
                    'UpdateToken': 'token',
                    'FirewallPolicyResponse': {'FirewallPolicyArn': POLICY,
                                               'FirewallPolicyName': 'policy',
                                               'FirewallPolicyId': '11111111-1111-4111-8111-111111111111'},
                    'FirewallPolicy': {
                        'StatelessDefaultActions': ['aws:pass'],
                        'StatelessFragmentDefaultActions': ['aws:forward_to_sfe'],
                        'StatefulRuleGroupReferences': [{'ResourceArn': GROUP}],
                    }}, {'FirewallPolicyArn': POLICY})
                n.add_response('describe_rule_group', {
                    'UpdateToken': 'token',
                    'RuleGroupResponse': {'RuleGroupArn': GROUP, 'RuleGroupName': 'rules',
                                          'RuleGroupId': '11111111-1111-4111-8111-111111111111', 'Type': 'STATEFUL'},
                    'RuleGroup': {'RulesSource': {'StatefulRules': [{
                        'Action': 'PASS',
                        'Header': {'Protocol': 'IP', 'Source': 'ANY', 'Destination': 'ANY',
                                   'SourcePort': 'ANY', 'DestinationPort': 'ANY',
                                   'Direction': 'ANY'}, 'RuleOptions': []}]}}}, {'RuleGroupArn': GROUP})
                n.add_response('describe_firewall', {
                    'Firewall': {'FirewallId': '11111111-1111-4111-8111-111111111111', 'FirewallName': 'fw', 'FirewallArn': FW,
                                 'FirewallPolicyArn': POLICY, 'VpcId': 'vpc-123',
                                 'SubnetMappings': [{'SubnetId': 'subnet-123'}]},
                    'FirewallStatus': {
                        'Status': 'READY', 'ConfigurationSyncStateSummary': 'IN_SYNC',
                        'SyncStates': {
                            'us-east-1a': {'Attachment': {
                                'SubnetId': 'subnet-123',
                                'EndpointId': 'vpce-123', 'Status': 'READY'}}}}},
                    {'FirewallArn': FW})
                n.add_response('describe_logging_configuration', {
                    'FirewallArn': FW,
                    'LoggingConfiguration': {'LogDestinationConfigs': []}},
                    {'FirewallArn': FW})
                routes = ([{'GatewayId': 'vpce-123', 'State': 'active',
                            'DestinationCidrBlock': '0.0.0.0/0'}]
                          if route_present else
                          [{'GatewayId': 'igw-123', 'State': 'active',
                            'DestinationCidrBlock': '0.0.0.0/0'}])
                e.add_response('describe_route_tables', {'RouteTables': [{
                    'VpcId': 'vpc-123', 'RouteTableId': 'rtb-123',
                    'Associations': [{'SubnetId': 'subnet-workload',
                                      'RouteTableAssociationId': 'rtbassoc-123',
                                      'RouteTableId': 'rtb-123'}],
                    'Routes': routes}]}, {'MaxResults': PAGE_SIZE,
                        'Filters': [{'Name': 'vpc-id', 'Values': ['vpc-123']}]})
                def clients(service, session, region):
                    return {'network-firewall': nf, 'ec2': ec2}[service]
                with patch.object(AWSFacadeUtils, 'get_client', side_effect=clients):
                    facade = NetworkFirewallFacade(object(), ACCOUNT)
                    inv = await facade.inventory(REGION)
                n.assert_no_pending_responses()
                e.assert_no_pending_responses()
        finally:
            nf.close()
            ec2.close()
        assert inv['collection']['firewalls'] is True
        assert inv['collection']['policies'] is True
        assert inv['collection']['rule_groups'] is True
        assert inv['collection']['routing'] is True
        assert len(inv['firewalls']) == len(inv['policies']) == len(inv['rule_groups']) == 1
        firewall = inv['firewalls'][0]
        assert firewall['logging_disabled'] is True
        assert inv['policies'][0]['stateless_default_pass'] is True
        assert inv['rule_groups'][0]['broad_pass'] is True
        assert firewall['route_reference_count'] == int(route_present)
        assert firewall['routing_status'] == (
            'endpoint_referenced' if route_present else 'no_endpoint_routes')
        assert firewall['no_endpoint_routes'] is not route_present
        assert firewall['traffic_inspection_verified'] is False
        assert firewall['bidirectional_flow_verified'] is False
        source = SimpleNamespace(
            build_region_list=AsyncMock(return_value=[REGION]),
            networkfirewall=SimpleNamespace(inventory=AsyncMock(return_value=inv)))
        parsed = NetworkFirewallPublic(source)
        await parsed.fetch_all(regions=[REGION])
        assert parsed['firewalls_count'] == 1
        assert parsed['policies_count'] == 1
        assert parsed['rule_groups_count'] == 1
        assert next(iter(parsed['regions'][REGION]['firewalls'].values()))['arn'] == FW
        assert 'vpce-123' in json.dumps(parsed)
    asyncio.run(scenario(False))
    asyncio.run(scenario(True))


def test_denial_is_incomplete_not_empty_success():
    async def scenario():
        client = sdk('network-firewall')
        try:
            with Stubber(client) as stub:
                stub.add_client_error('list_firewalls',
                    service_error_code='AccessDeniedException', http_status_code=403,
                    expected_params={'MaxResults': PAGE_SIZE})
                stub.add_response('list_firewall_policies', {'FirewallPolicies': []},
                                  {'MaxResults': PAGE_SIZE})
                stub.add_response('list_rule_groups', {'RuleGroups': []},
                                  {'MaxResults': PAGE_SIZE})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                    facade = NetworkFirewallFacade(object(), ACCOUNT)
                    inv = await facade.inventory(REGION)
                stub.assert_no_pending_responses()
            assert inv['collection']['firewalls'] is False
            assert not inv['collection']['routing']
            assert inv['firewalls'] == []
        finally:
            client.close()
    asyncio.run(scenario())


def test_repeated_token_and_bad_page_are_not_complete():
    async def scenario():
        class Duplicate:
            def list_firewalls(self, **kwargs):
                return {'Firewalls': [], 'NextToken': 'repeat'}
        f = NetworkFirewallFacade(object(), ACCOUNT)
        rows, complete = await f.pages(Duplicate(), 'list_firewalls', 'Firewalls')
        assert rows == [] and complete is False
        class Malformed:
            def list_firewalls(self, **kwargs):
                return {'Firewalls': 'not-a-list'}
        rows, complete = await f.pages(Malformed(), 'list_firewalls', 'Firewalls')
        assert rows == [] and complete is False
    asyncio.run(scenario())


def test_unknown_routing_never_emits_no_routes_finding():
    route = NetworkFirewallFacade.routing(
        {'VpcId': 'vpc-1'}, {}, [], False)
    assert route['routing_status'] == 'unknown'
    assert route['no_endpoint_routes'] is False
    assert route['traffic_inspection_verified'] is False
    proxy = NetworkFirewallFacade.routing(
        {'VpcId': 'vpc-1', 'NoSourcePreservation': True},
        {'SyncStates': {'az': {'Attachment': {
            'EndpointId': 'vpce-1', 'Status': 'READY'}}}}, [], True)
    assert proxy['routing_status'] == 'unknown'


def test_default_rules_present_and_scoped_to_collected_resources():
    config = json.loads((ROOT / 'ScoutSuite/providers/aws/rules/rulesets/default.json').read_text())
    for slug in ('logging-disabled', 'stateless-default-pass',
                 'fragment-default-pass', 'broad-pass-rule',
                 'no-route-references', 'routes-not-ready'):
        filename = 'networkfirewall-' + slug + '.json'
        assert config['rules'][filename] == [{'enabled': True,
            'level': 'danger' if slug in ('stateless-default-pass', 'broad-pass-rule')
            else 'warning'}]
        finding = json.loads((ROOT / 'ScoutSuite/providers/aws/rules/findings' / filename).read_text())
        assert finding['path'].startswith('networkfirewall.regions.id.')
        assert finding['conditions'][1][1] == 'true'
