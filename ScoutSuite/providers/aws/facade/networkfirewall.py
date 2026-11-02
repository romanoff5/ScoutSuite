"""M10-M: read-only Network Firewall collector; unknown is never PASS."""
import re
from botocore.exceptions import ClientError
from ScoutSuite.core.run_context import get_current_run_context, safe_collection_issue_code
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently

PAGE_SIZE, MAX_PAGES, MAX_ITEMS = 100, 1000, 100000
DENIED = {'AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation'}
WILDCARD = {'ANY', '0.0.0.0/0', '::/0'}


def broad_pass(group, kind):
    source = group.get('RulesSource') or {}
    if kind == 'STATELESS':
        rules = (source.get('StatelessRulesAndCustomActions') or {}).get('StatelessRules') or []
        for rule in rules:
            definition = rule.get('RuleDefinition') or {}
            matches = definition.get('MatchAttributes') or {}
            def broad_addresses(field):
                values = matches.get(field) or []
                return not values or all(
                    isinstance(x, dict) and x.get('AddressDefinition', '').upper() in WILDCARD
                    for x in values)
            if ('aws:pass' in (definition.get('Actions') or [])
                    and broad_addresses('Sources') and broad_addresses('Destinations')
                    and not any(matches.get(k) for k in (
                        'Protocols', 'SourcePorts', 'DestinationPorts', 'TCPFlags'))):
                return True
    if kind in ('STATEFUL', 'STATEFUL_DOMAIN'):
        for rule in source.get('StatefulRules') or []:
            h = rule.get('Header') or {}
            if (rule.get('Action') == 'PASS' and h.get('Protocol') == 'IP'
                    and all(h.get(k, '').upper() in WILDCARD for k in (
                        'Source', 'SourcePort', 'Destination', 'DestinationPort'))
                    and h.get('Direction') in ('ANY', 'FORWARD')):
                return True
        for line in (source.get('RulesString') or '').splitlines():
            if re.match(r'^\s*pass\s+ip\s+any\s+any\s*->\s*any\s+any\s*\(', line, re.I):
                return True
    return False



def reconcile_group_references(policies, groups):
    """Record managed/foreign/missing group references instead of claiming full coverage."""
    known = {group['arn'] for group in groups}
    complete = True
    for policy in policies:
        references = (policy.get('stateful_group_refs') or []) + (
            policy.get('stateless_group_refs') or [])
        missing = sorted({item.get('ResourceArn') for item in references
                          if isinstance(item, dict) and
                          isinstance(item.get('ResourceArn'), str) and
                          item['ResourceArn'] not in known})
        policy['unresolved_rule_group_arns'] = missing
        policy['group_reference_coverage_complete'] = (
            policy.get('detail_complete') is True and not missing)
        complete = complete and policy['group_reference_coverage_complete']
    return complete


class NetworkFirewallFacade(AWSBaseFacade):
    def __init__(self, session, account_id):
        super().__init__(session)
        self.account_id = account_id

    @staticmethod
    def issue(status, reason):
        ctx = get_current_run_context()
        if ctx is not None:
            ctx.record_collection_issue(status, 'networkfirewall', safe_collection_issue_code(reason))

    def failure(self, operation, exc):
        code = (exc.response.get('Error', {}).get('Code') if isinstance(exc, ClientError)
                else None)
        self.issue('denied' if code in DENIED else 'failed',
                   operation + ':' + (code or type(exc).__name__))

    async def one(self, client, operation, **kwargs):
        try:
            return await run_concurrently(lambda: getattr(client, operation)(**kwargs))
        except Exception as e:
            self.failure(operation, e)
            return None

    async def pages(self, client, operation, key, **filters):
        records, token, seen = [], None, set()
        for _ in range(MAX_PAGES):
            params = {'MaxResults': PAGE_SIZE, **filters}
            if token is not None:
                params['NextToken'] = token
            page = await self.one(client, operation, **params)
            if page is None:
                return records, False
            batch = page.get(key) if isinstance(page, dict) else None
            if (not isinstance(batch, list) or len(batch) > PAGE_SIZE
                    or any(not isinstance(x, dict) for x in batch)):
                self.issue('partial', operation + ':MalformedPage')
                return records, False
            if len(records) + len(batch) > MAX_ITEMS:
                records.extend(batch[:MAX_ITEMS - len(records)])
                self.issue('partial', operation + ':ItemLimit')
                return records, False
            records.extend(batch)
            upcoming = page.get('NextToken')
            if upcoming in ('', None):
                return records, True
            if (not isinstance(upcoming, str) or len(upcoming) > 4096
                    or upcoming in seen):
                self.issue('partial', operation + ':InvalidToken')
                return records, False
            seen.add(upcoming)
            token = upcoming
        self.issue('partial', operation + ':PageLimit')
        return records, False

    def valid_arn(self, arn, region, kind):
        if not isinstance(arn, str) or not isinstance(self.account_id, str):
            return False
        fields = arn.split(':', 5)
        return (len(fields) == 6 and fields[0] == 'arn'
                and fields[2] == 'network-firewall' and fields[3] == region
                and fields[4] == self.account_id and
                any(fields[5].startswith(x + '/') for x in kind))

    async def indexed(self, client, operation, key, arnkey, region, kinds):
        data, complete = await self.pages(client, operation, key)
        seen, filtered = set(), []
        for row in data:
            arn = row.get(arnkey)
            if not self.valid_arn(arn, region, kinds) or arn in seen:
                self.issue('partial', operation + ':InvalidOrDuplicateARN')
                complete = False
                continue
            seen.add(arn)
            filtered.append(row)
        return filtered, complete

    @staticmethod
    def routing(firewall, status, tables, complete):
        sync = status.get('SyncStates') or {}
        endpoints = []
        for az, entry in sync.items() if isinstance(sync, dict) else []:
            attachment = entry.get('Attachment') if isinstance(entry, dict) else None
            if isinstance(attachment, dict):
                endpoints.append({'availability_zone': az,
                                  'subnet_id': attachment.get('SubnetId'),
                                  'endpoint_id': attachment.get('EndpointId'),
                                  'status': attachment.get('Status')})
        ids = {e['endpoint_id'] for e in endpoints if e.get('endpoint_id')}
        ready = {e['endpoint_id'] for e in endpoints if e.get('status') == 'READY'}
        matches = []
        for table in tables:
            for route in table.get('Routes') or []:
                if route.get('GatewayId') in ids:
                    matches.append({
                        'route_table_id': table.get('RouteTableId'),
                        'associations': table.get('Associations') or [],
                        'endpoint_id': route.get('GatewayId'),
                        'destination_ipv4': route.get('DestinationCidrBlock'),
                        'destination_ipv6': route.get('DestinationIpv6CidrBlock'),
                        'destination_prefix_list_id': route.get('DestinationPrefixListId'),
                        'state': route.get('State')})
        active = sum(x['endpoint_id'] in ready and x['state'] == 'active' for x in matches)
        if (not complete or not ids or not firewall.get('VpcId')
                or firewall.get('NoSourcePreservation') is True):
            result = 'unknown'
        elif active:
            result = 'endpoint_referenced'
        elif matches:
            result = 'inactive_or_unready'
        else:
            result = 'no_endpoint_routes'
        return {
            'routing_status': result, 'routing_scope': 'own_account_vpc_tables_only',
            'route_table_inventory_complete': complete,
            'endpoint_attachments': endpoints, 'endpoint_ids': sorted(ids),
            'route_references': matches, 'route_reference_count': len(matches),
            'active_route_reference_count': active,
            'traffic_inspection_verified': False, 'bidirectional_flow_verified': False,
            'routing_coverage_unknown': result == 'unknown',
            'no_endpoint_routes': result == 'no_endpoint_routes',
            'routing_not_ready': result == 'inactive_or_unready',
        }

    async def inventory(self, region):
        result = {'firewalls': [], 'policies': [], 'rule_groups': [],
                  'collection': {'firewalls': False, 'policies': False,
                                 'rule_groups': False, 'routing': False}}
        client = AWSFacadeUtils.get_client('network-firewall', self.session, region)
        if client is None:
            self.issue('failed', 'NetworkFirewallClientConstruction')
            return result
        frows, fc = await self.indexed(client, 'list_firewalls', 'Firewalls',
                                       'FirewallArn', region, ['firewall'])
        prows, pc = await self.indexed(client, 'list_firewall_policies',
                                       'FirewallPolicies', 'Arn', region, ['firewall-policy'])
        grows, gc = await self.indexed(client, 'list_rule_groups', 'RuleGroups',
                                       'Arn', region, ['stateful-rulegroup', 'stateless-rulegroup'])
        for item in prows:
            arn = item['Arn']
            reply = await self.one(client, 'describe_firewall_policy', FirewallPolicyArn=arn)
            raw = reply.get('FirewallPolicy') if isinstance(reply, dict) else None
            meta = reply.get('FirewallPolicyResponse') if isinstance(reply, dict) else None
            valid = isinstance(raw, dict) and isinstance(meta, dict) and (
                meta.get('FirewallPolicyArn') == arn)
            if not valid:
                pc = False
                self.issue('partial', 'DescribeFirewallPolicy:Incomplete')
                raw = {}
            defaults, fragments = raw.get('StatelessDefaultActions'), raw.get('StatelessFragmentDefaultActions')
            result['policies'].append({
                'arn': arn, 'name': item.get('Name'), 'detail_complete': valid,
                'policy': raw if valid else None, 'stateless_default_actions': defaults,
                'stateless_fragment_default_actions': fragments,
                'stateful_default_actions': raw.get('StatefulDefaultActions'),
                'stateless_default_pass': isinstance(defaults, list) and 'aws:pass' in defaults,
                'stateless_fragment_default_pass':
                    isinstance(fragments, list) and 'aws:pass' in fragments,
                'stateful_group_refs': raw.get('StatefulRuleGroupReferences') if valid else None,
                'stateless_group_refs': raw.get('StatelessRuleGroupReferences') if valid else None,
            })
        for item in grows:
            arn = item['Arn']
            reply = await self.one(client, 'describe_rule_group', RuleGroupArn=arn)
            raw = reply.get('RuleGroup') if isinstance(reply, dict) else None
            meta = reply.get('RuleGroupResponse') if isinstance(reply, dict) else None
            valid = isinstance(raw, dict) and isinstance(meta, dict) and (
                meta.get('RuleGroupArn') == arn)
            if not valid:
                gc = False
                self.issue('partial', 'DescribeRuleGroup:Incomplete')
                raw = {}
            kind = meta.get('Type') if isinstance(meta, dict) else None
            result['rule_groups'].append({
                'arn': arn, 'name': item.get('Name'), 'type': kind,
                'detail_complete': valid, 'rule_group': raw if valid else None,
                'metadata': meta if valid else None,
                'broad_pass': bool(valid and broad_pass(raw, kind))})
        references_complete = reconcile_group_references(
            result['policies'], result['rule_groups'])
        if not references_complete:
            self.issue('partial', 'FirewallPolicy:RuleGroupReferencesUnresolved')
        for item in frows:
            arn = item['FirewallArn']
            reply = await self.one(client, 'describe_firewall', FirewallArn=arn)
            raw = reply.get('Firewall') if isinstance(reply, dict) else None
            status = reply.get('FirewallStatus') if isinstance(reply, dict) else None
            valid = isinstance(raw, dict) and isinstance(status, dict) and (
                raw.get('FirewallArn') == arn)
            if not valid:
                fc = False
                self.issue('partial', 'DescribeFirewall:Incomplete')
                raw, status = {}, {}
            reply_log = await self.one(client, 'describe_logging_configuration', FirewallArn=arn)
            log = reply_log.get('LoggingConfiguration') if isinstance(reply_log, dict) else None
            log_ok = isinstance(log, dict) and isinstance(log.get('LogDestinationConfigs'), list)
            if not log_ok:
                fc = False
                self.issue('partial', 'DescribeLoggingConfiguration:Unknown')
            destinations = log['LogDestinationConfigs'] if log_ok else None
            result['firewalls'].append({
                'arn': arn, 'name': item.get('FirewallName'),
                'detail_complete': valid, 'logging_complete': log_ok,
                'firewall': raw if valid else None,
                'firewall_status': status if valid else None,
                'vpc_id': raw.get('VpcId'), 'policy_arn': raw.get('FirewallPolicyArn'),
                'subnet_mappings': raw.get('SubnetMappings') if valid else None,
                'endpoint_status': status.get('Status'),
                'configuration_sync_status': status.get('ConfigurationSyncStateSummary'),
                'logging_config': log if log_ok else None,
                'logging_destinations': destinations,
                'logging_types': [x.get('LogType') for x in destinations] if log_ok else None,
                'logging_disabled': log_ok and not destinations,
            })
        vpcs = sorted({x['vpc_id'] for x in result['firewalls'] if x.get('vpc_id')})
        ec2 = AWSFacadeUtils.get_client('ec2', self.session, region) if vpcs else None
        route_data, route_complete = {}, True
        if vpcs and ec2 is None:
            route_complete = False
            self.issue('failed', 'RouteTableClientConstruction')
        elif ec2 is not None:
            for vpc in vpcs:
                rows, complete = await self.pages(
                    ec2, 'describe_route_tables', 'RouteTables',
                    Filters=[{'Name': 'vpc-id', 'Values': [vpc]}])
                route_data[vpc] = rows
                route_complete = route_complete and complete
        for item in result['firewalls']:
            item.update(self.routing(item['firewall'] or {}, item['firewall_status'] or {},
                                     route_data.get(item['vpc_id'], []),
                                     route_complete and item['detail_complete']))
        result['collection'] = {
            'firewalls': fc, 'policies': pc, 'rule_groups': gc,
            'rule_group_references_resolved': references_complete and pc,
            'managed_rule_groups_enumerated': False,
            'routing': route_complete and fc,
            'inspection_verified': False,
            'scope': 'account_region_vpc_routes_only',
        }
        return result
