"""Normalized Web ACL metadata without request bodies or raw rule statements."""
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id


class WebACLs(AWSResources):
    def __init__(self, facade, region):
        super().__init__(facade)
        self.region = region

    @staticmethod
    def issue(reason):
        ctx = get_current_run_context()
        if ctx is not None:
            ctx.record_collection_issue('partial', 'wafv2', reason)

    async def fetch_all(self):
        for row in await self.facade.wafv2.get_web_acls(self.region):
            result = self._normalize(row)
            if result is None:
                self.issue('MalformedWebACLResource')
                continue
            key, item = result
            if key in self:
                self.issue('DuplicateWebACLResource')
                continue
            self[key] = item

    @staticmethod
    def _explicit_rate_statement(statement, depth=0):
        """Inspect only directly retrieved ACL statements, not opaque rule groups."""
        if not isinstance(statement, dict) or depth > 16:
            return None
        if 'RateBasedStatement' in statement:
            rate = statement['RateBasedStatement']
            return True if isinstance(rate, dict) and isinstance(rate.get('Limit'), int) else None
        for op in ('AndStatement', 'OrStatement'):
            if op in statement:
                body = statement[op]
                children = body.get('Statements') if isinstance(body, dict) else None
                if not isinstance(children, list) or not children:
                    return None
                results = [WebACLs._explicit_rate_statement(s, depth + 1) for s in children]
                return True if True in results else None if None in results else False
        if 'NotStatement' in statement:
            body = statement['NotStatement']
            return WebACLs._explicit_rate_statement(
                body.get('Statement') if isinstance(body, dict) else None, depth + 1)
        return False if statement else None

    def _normalize(self, raw):
        if not isinstance(raw, dict):
            return None
        arn, name, scope = raw.get('arn'), raw.get('name'), raw.get('scope')
        if (not isinstance(arn, str) or not arn.startswith('arn:')
                or not isinstance(name, str) or not name
                or scope not in ('REGIONAL', 'CLOUDFRONT')):
            return None
        action = raw.get('default_action')
        default = None
        if isinstance(action, dict):
            if ('Allow' in action) != ('Block' in action):
                default = 'ALLOW' if 'Allow' in action else 'BLOCK'
        rules = raw.get('rules')
        if not isinstance(rules, list):
            self.issue('InvalidWebACLRuleSet')
            rules = None
        rule_summary = []
        if rules is not None:
            for rule in rules:
                if not isinstance(rule, dict) or not isinstance(rule.get('Name'), str):
                    self.issue('InvalidWebACLRule')
                    rules = None
                    break
                statement = rule.get('Statement')
                statement_types = (sorted(statement)
                                   if isinstance(statement, dict) else [])
                info = {'name': rule['Name'], 'priority': rule.get('Priority'),
                        'statement_types': statement_types,
                        'action_types': sorted(rule['Action'])
                        if isinstance(rule.get('Action'), dict) else [],
                        'override_action_types': sorted(rule['OverrideAction'])
                        if isinstance(rule.get('OverrideAction'), dict) else []}
                if isinstance(statement, dict):
                    managed = statement.get('ManagedRuleGroupStatement')
                    if isinstance(managed, dict):
                        info['managed_group_vendor'] = managed.get('VendorName')
                        info['managed_group_name'] = managed.get('Name')
                    group = statement.get('RuleGroupReferenceStatement')
                    if isinstance(group, dict):
                        info['rule_group_arn'] = group.get('ARN')
                rule_summary.append(info)
        rate_results = ([self._explicit_rate_statement(x.get('Statement'))
                         for x in rules] if rules is not None else None)
        rate_status = ('unknown' if rate_results is None or None in rate_results else
                       'present' if True in rate_results else 'not_present')
        fms = raw.get('managed_by_firewall_manager')
        before = raw.get('pre_process_rule_groups')
        after = raw.get('post_process_rule_groups')
        if before is not None and not isinstance(before, list):
            self.issue('MalformedFirewallManagerPreRules')
            before = None
        if after is not None and not isinstance(after, list):
            self.issue('MalformedFirewallManagerPostRules')
            after = None
        associations = raw.get('associated_resources')
        completeness = raw.get('association_scope_complete')
        if (not isinstance(associations, list)
                or any(not isinstance(row, dict) or
                       not isinstance(row.get('resource_arn'), str)
                       for row in associations)):
            self.issue('MalformedAssociationResource')
            associations = []
            completeness = False
        status = raw.get('association_status')
        if status not in ('associated', 'unused_candidate', 'unknown'):
            status = 'unknown'
        if status == 'unused_candidate' and (completeness is not True or associations):
            self.issue('ConflictingAssociationStatus')
            status = 'unknown'
        if status == 'associated' and not associations:
            self.issue('ConflictingAssociationStatus')
            status = 'unknown'
        key = get_non_provider_id(arn)
        return key, {
            'id': key, 'name': name, 'web_acl_id': raw.get('id'),
            'web_acl_arn': arn, 'region': self.region, 'scope': scope,
            'default_action': default,
            'rule_count': len(rules) if rules is not None else None,
            'explicit_rate_based_rule_status': rate_status,
            'rules': rule_summary,
            'managed_by_firewall_manager': fms,
            'firewall_manager_pre_rules_count':
            len(before) if isinstance(before, list) else None,
            'firewall_manager_post_rules_count':
            len(after) if isinstance(after, list) else None,
            'unprotected_allow_all': (
                default == 'ALLOW' and rules == []
                and fms is False and before in (None, []) and after in (None, [])),
            'association_status': status,
            'association_scope_complete': completeness is True,
            'unused_candidate': status == 'unused_candidate',
            'associated_resource_count': len(associations),
            'associated_resources': associations,
            'checked_resource_types': raw.get('checked_resource_types') or [],
            'unknown_resource_types': raw.get('unknown_resource_types') or [],
            'capacity': raw.get('capacity'),
            'visibility_config': raw.get('visibility_config') or {},
            'logging_status': raw.get('logging_status'),
            'log_destinations': raw.get('log_destinations') or [],
            'operational_traffic': raw.get('operational_traffic') or {
                'status': 'unknown', 'requests_observed': False},
        }
