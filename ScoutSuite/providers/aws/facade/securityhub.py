"""Bounded, read-only regional Security Hub hub/standards inventory."""
from botocore.exceptions import ClientError

from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently


MAX_PAGES = 500
MAX_STANDARDS = 25000
PAGE_SIZE = 50
DENIED_CODES = frozenset(('AccessDeniedException', 'AccessDenied', 'UnauthorizedOperation',
                          'InvalidAccessException'))
UNSUPPORTED_CODES = frozenset(('UnsupportedOperationException', 'UnknownOperationException'))


class SecurityHubPublicFacade(AWSBaseFacade):
    async def get_hub(self, region):
        """Return one visible hub with subscriptions and explicit completeness.

        An unavailable hub or an inaccessible subscription listing is never
        converted to a verified empty/secure subscriptions inventory.
        """
        context = get_current_run_context()
        if not hasattr(self, 'hub_states'):
            self.hub_states = {}
        self.hub_states[region] = 'unknown'

        def issue(state, reason):
            if context is not None:
                context.record_collection_issue(state, 'securityhub', reason)

        client = AWSFacadeUtils.get_client('securityhub', self.session, region)
        if client is None:
            issue('failed', 'ClientConstruction')
            return None
        try:
            hub = await run_concurrently(client.describe_hub)
        except ClientError as error:
            code = error.response.get('Error', {}).get('Code', '')
            if code == 'ResourceNotFoundException':
                self.hub_states[region] = 'not_subscribed'
                issue('not_applicable', 'HubNotSubscribed')
            elif code in DENIED_CODES:
                issue('denied', 'DescribeHubDenied')
            elif code in UNSUPPORTED_CODES:
                issue('unsupported', 'DescribeHubUnsupported')
            else:
                issue('failed', 'DescribeHubError')
            return None
        except Exception:
            issue('failed', 'DescribeHubError')
            return None

        arn = hub.get('HubArn') if isinstance(hub, dict) else None
        if not isinstance(arn, str) or not arn.startswith('arn:'):
            issue('failed', 'MalformedHub')
            return None
        self.hub_states[region] = 'enabled'
        result = {
            'hub_arn': arn,
            'auto_enable_controls': hub.get('AutoEnableControls'),
            'control_finding_generator': hub.get('ControlFindingGenerator'),
            'standards': [],
            'standards_inventory_complete': False,
        }
        seen_arns = set()
        seen_tokens = set()
        token = None
        for _ in range(MAX_PAGES):
            params = {'MaxResults': PAGE_SIZE}
            if token is not None:
                params['NextToken'] = token
            try:
                page = await run_concurrently(
                    lambda params=params: client.get_enabled_standards(**params))
            except ClientError as error:
                code = error.response.get('Error', {}).get('Code', '')
                issue('partial', 'GetStandardsDenied' if code in DENIED_CODES
                      else 'GetStandardsUnsupported' if code in UNSUPPORTED_CODES
                      else 'GetStandardsError')
                break
            except Exception:
                issue('partial', 'GetStandardsError')
                break
            rows = page.get('StandardsSubscriptions') if isinstance(page, dict) else None
            if not isinstance(rows, list):
                issue('partial', 'MalformedStandardsList')
                break
            stop = False
            for row in rows:
                if not isinstance(row, dict):
                    issue('partial', 'MalformedStandard')
                    stop = True
                    break
                subscription = row.get('StandardsSubscriptionArn')
                standard = row.get('StandardsArn')
                if (not isinstance(subscription, str) or not subscription.startswith('arn:')
                        or not isinstance(standard, str) or not standard.startswith('arn:')):
                    issue('partial', 'MalformedStandard')
                    stop = True
                    break
                if subscription in seen_arns:
                    issue('partial', 'DuplicateSubscription')
                    stop = True
                    break
                if len(result['standards']) >= MAX_STANDARDS:
                    issue('partial', 'StandardsLimit')
                    stop = True
                    break
                seen_arns.add(subscription)
                result['standards'].append({
                    'subscription_arn': subscription,
                    'standards_arn': standard,
                    'status': row.get('StandardsStatus'),
                    'status_reason': (row.get('StandardsStatusReason') or {}).get('StatusReasonCode')
                    if isinstance(row.get('StandardsStatusReason'), dict) else None,
                    'standards_controls_updatable': row.get('StandardsControlsUpdatable'),
                    'provider': row.get('Provider'),
                    'status_reason_details': row.get('StandardsStatusReason') or {},
                })
            if stop:
                break
            following = page.get('NextToken')
            if following is None or following == '':
                result['standards_inventory_complete'] = True
                break
            if not isinstance(following, str) or following in seen_tokens:
                issue('partial', 'InvalidPaginationToken')
                break
            seen_tokens.add(following)
            token = following
        else:
            issue('partial', 'PageLimit')
        return result
