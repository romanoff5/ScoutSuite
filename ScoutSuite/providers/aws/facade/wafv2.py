"""Bounded, read-only WAFv2 Web ACL inventory for Regional and CloudFront scopes."""
from botocore.exceptions import ClientError

from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.facade.wafv2_associations import discover_associations
from ScoutSuite.providers.utils import run_concurrently

MAX_PAGES = 20
PAGE_SIZE = 100
MAX_WEB_ACLS_PER_SCOPE = MAX_PAGES * PAGE_SIZE
MAX_RULE_SUMMARIES = 1500
DENIED = frozenset(('AccessDeniedException', 'AccessDenied', 'UnauthorizedOperation',
                    'WAFInvalidPermissionException'))
UNSUPPORTED = frozenset(('UnknownOperationException', 'UnsupportedOperationException'))


class WAFv2PublicFacade(AWSBaseFacade):
    def __init__(self, session, owner_id):
        super().__init__(session)
        self.owner_id = owner_id

    @staticmethod
    def issue(status, reason):
        ctx = get_current_run_context()
        if ctx is not None:
            ctx.record_collection_issue(status, 'wafv2', reason)

    @classmethod
    def failure(cls, operation, error, partial=False):
        if isinstance(error, ClientError):
            code = error.response.get('Error', {}).get('Code', '')
            state = 'denied' if code in DENIED else (
                'unsupported' if code in UNSUPPORTED else 'failed')
        else:
            state = 'failed'
        cls.issue('partial' if partial else state, operation + state.capitalize())

    @staticmethod
    def _valid_arn(arn, region, owner_id, scope):
        if not isinstance(arn, str):
            return False
        pieces = arn.split(':', 5)
        expected = 'global' if scope == 'CLOUDFRONT' else 'regional'
        return (len(pieces) == 6 and pieces[0] == 'arn'
                and pieces[2] == 'wafv2' and pieces[3] == region
                and pieces[4] == owner_id
                and pieces[5].startswith(expected + '/webacl/')
                and len(pieces[5].split('/')) == 4)

    async def get_traffic_evidence(self, region, acl):
        from ScoutSuite.providers.aws.facade.operational_evidence import collect_waf_traffic
        return await collect_waf_traffic(self, region, acl)

    async def get_web_acls(self, region):
        """List exact Web ACLs; missing detail/logging data is never inferred clean."""
        if not isinstance(self.owner_id, str) or not (
                len(self.owner_id) == 12 and self.owner_id.isascii()
                and self.owner_id.isdigit()):
            self.issue('failed', 'InvalidAccountId')
            return []
        client = AWSFacadeUtils.get_client('wafv2', self.session, region)
        if client is None:
            self.issue('failed', 'ClientConstruction')
            return []
        scopes = ('REGIONAL', 'CLOUDFRONT') if region == 'us-east-1' else ('REGIONAL',)
        collected = []
        for scope in scopes:
            identifiers = []
            seen_arns, seen_tokens = set(), set()
            marker = None
            for _ in range(MAX_PAGES):
                params = {'Scope': scope, 'Limit': PAGE_SIZE}
                if marker is not None:
                    params['NextMarker'] = marker
                try:
                    page = await run_concurrently(
                        lambda params=params: client.list_web_acls(**params))
                except Exception as error:
                    self.failure('ListWebACLs', error, partial=bool(identifiers))
                    break
                rows = page.get('WebACLs') if isinstance(page, dict) else None
                if not isinstance(rows, list) or len(rows) > PAGE_SIZE:
                    self.issue('partial', 'MalformedWebACLPage')
                    break
                stop = False
                for raw in rows:
                    if not isinstance(raw, dict):
                        self.issue('partial', 'MalformedWebACLSummary')
                        continue
                    arn, name, identifier = (raw.get('ARN'), raw.get('Name'), raw.get('Id'))
                    if (not self._valid_arn(arn, region, self.owner_id, scope)
                            or not isinstance(name, str) or not name
                            or not isinstance(identifier, str) or not identifier):
                        self.issue('partial', 'InvalidWebACLIdentity')
                        continue
                    if arn in seen_arns:
                        self.issue('partial', 'DuplicateWebACL')
                        continue
                    if len(identifiers) >= MAX_WEB_ACLS_PER_SCOPE:
                        self.issue('partial', 'WebACLLimit')
                        stop = True
                        break
                    seen_arns.add(arn)
                    identifiers.append((name, identifier, arn))
                if stop:
                    break
                following = page.get('NextMarker')
                if following in (None, ''):
                    break
                if (not isinstance(following, str) or len(following) > 4096
                        or following in seen_tokens):
                    self.issue('partial', 'InvalidPaginationToken')
                    break
                seen_tokens.add(following)
                marker = following
            else:
                self.issue('partial', 'WebACLPageLimit')
            for name, identifier, arn in identifiers:
                try:
                    result = await run_concurrently(
                        lambda name=name, identifier=identifier, scope=scope:
                        client.get_web_acl(Name=name, Id=identifier, Scope=scope))
                except Exception as error:
                    self.failure('GetWebACL', error, partial=True)
                    continue
                web_acl = result.get('WebACL') if isinstance(result, dict) else None
                if (not isinstance(web_acl, dict) or web_acl.get('ARN') != arn
                        or web_acl.get('Id') != identifier
                        or web_acl.get('Name') != name):
                    self.issue('partial', 'UnexpectedWebACLDetail')
                    continue
                rules = web_acl.get('Rules', [])
                if (not isinstance(rules, list) or len(rules) > MAX_RULE_SUMMARIES
                        or any(not isinstance(rule, dict) for rule in rules)):
                    self.issue('partial', 'MalformedWebACLRules')
                    continue
                logging_status = 'unknown'
                destinations = []
                try:
                    logging = await run_concurrently(
                        lambda arn=arn: client.get_logging_configuration(ResourceArn=arn))
                    config = (logging.get('LoggingConfiguration')
                              if isinstance(logging, dict) else None)
                    destination_list = (config.get('LogDestinationConfigs')
                                        if isinstance(config, dict) else None)
                    if (not isinstance(config, dict) or config.get('ResourceArn') != arn
                            or not isinstance(destination_list, list)
                            or any(not isinstance(dest, str) for dest in destination_list)):
                        self.issue('partial', 'MalformedLoggingConfiguration')
                    else:
                        logging_status = 'configured'
                        destinations = destination_list
                except ClientError as error:
                    code = error.response.get('Error', {}).get('Code', '')
                    # A deleted Web ACL and an unconfigured logging destination
                    # may both raise WAFNonexistentItemException. Never claim off.
                    if code == 'WAFNonexistentItemException':
                        self.issue('partial', 'LoggingConfigurationNotFound')
                    else:
                        self.failure('GetLoggingConfiguration', error, partial=True)
                except Exception as error:
                    self.failure('GetLoggingConfiguration', error, partial=True)
                associations = await discover_associations(
                    self, client, region, scope, arn)
                traffic = await self.get_traffic_evidence(region, {
                    'scope': scope, 'visibility_config': web_acl.get('VisibilityConfig')})
                collected.append({
                    'operational_traffic': traffic,
                    **associations,
                    'name': name, 'id': identifier, 'arn': arn, 'scope': scope,
                    'region': region, 'default_action': web_acl.get('DefaultAction'),
                    'rules': rules, 'managed_by_firewall_manager':
                    web_acl.get('ManagedByFirewallManager'),
                    'pre_process_rule_groups': web_acl.get(
                        'PreProcessFirewallManagerRuleGroups'),
                    'post_process_rule_groups': web_acl.get(
                        'PostProcessFirewallManagerRuleGroups'),
                    'capacity': web_acl.get('Capacity'),
                    'visibility_config': web_acl.get('VisibilityConfig'),
                    'logging_status': logging_status,
                    'log_destinations': destinations,
                })
        return collected
