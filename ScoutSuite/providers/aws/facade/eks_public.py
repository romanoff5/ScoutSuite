"""M10-G: bounded read-only EKS regional cluster inventory."""
import re

from botocore.exceptions import ClientError

from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently


MAX_PAGES = 20
PAGE_SIZE = 100
MAX_CLUSTERS = 1000
DENIED = ('AccessDeniedException', 'AccessDenied', 'UnauthorizedOperation')
UNSUPPORTED = ('UnsupportedOperationException', 'UnknownOperationException')


class EKSPublicFacade(AWSBaseFacade):
    def __init__(self, session, owner_id):
        super().__init__(session)
        self.owner_id = owner_id

    @staticmethod
    def issue(status, reason):
        context = get_current_run_context()
        if context is not None:
            context.record_collection_issue(status, 'eks', reason)

    def error(self, operation, error, partial=False):
        if isinstance(error, ClientError):
            code = error.response.get('Error', {}).get('Code', '')
            state = 'denied' if code in DENIED else (
                'unsupported' if code in UNSUPPORTED else 'failed')
        else:
            state = 'failed'
        self.issue('partial' if partial else state, operation + state.capitalize())

    async def get_clusters(self, region):
        if (not isinstance(self.owner_id, str)
                or re.fullmatch(r'[0-9]{12}', self.owner_id) is None):
            self.issue('failed', 'InvalidAccountId')
            return []
        client = AWSFacadeUtils.get_client('eks', self.session, region)
        if client is None:
            self.issue('failed', 'ClientConstruction')
            return []
        names, seen, tokens = [], set(), set()
        token = None
        for _ in range(MAX_PAGES):
            params = {'maxResults': PAGE_SIZE}
            if token is not None:
                params['nextToken'] = token
            try:
                page = await run_concurrently(
                    lambda params=params: client.list_clusters(**params))
            except Exception as error:
                self.error('ListClusters', error, partial=bool(names))
                break
            rows = page.get('clusters') if isinstance(page, dict) else None
            if not isinstance(rows, list) or len(rows) > PAGE_SIZE:
                self.issue('partial' if names else 'failed', 'MalformedClusterList')
                break
            stopped = False
            for name in rows:
                if not isinstance(name, str) or not name:
                    self.issue('partial', 'MalformedClusterName')
                    continue
                if name in seen:
                    self.issue('partial', 'DuplicateClusterName')
                    continue
                if len(names) >= MAX_CLUSTERS:
                    self.issue('partial', 'ClusterLimit')
                    stopped = True
                    break
                seen.add(name)
                names.append(name)
            if stopped:
                break
            following = page.get('nextToken')
            if following is None or following == '':
                break
            if (not isinstance(following, str) or len(following) > 4096
                    or following in tokens):
                self.issue('partial', 'InvalidPaginationToken')
                break
            tokens.add(following)
            token = following
        else:
            self.issue('partial', 'PageLimit')
        results = []
        for name in names:
            try:
                response = await run_concurrently(
                    lambda name=name: client.describe_cluster(name=name))
            except Exception as error:
                self.error('DescribeCluster', error, partial=True)
                continue
            cluster = response.get('cluster') if isinstance(response, dict) else None
            arn = cluster.get('arn') if isinstance(cluster, dict) else None
            if not isinstance(cluster, dict) or cluster.get('name') != name or not isinstance(arn, str):
                self.issue('partial', 'MalformedClusterDetail')
                continue
            parts = arn.split(':', 5)
            if (len(parts) != 6 or parts[2] != 'eks'
                    or parts[3] != region or parts[4] != self.owner_id):
                self.issue('partial', 'UnexpectedClusterAccount')
                continue
            results.append(cluster)
        return results

    async def get_access_entries(self, region, cluster_name, auth_mode):
        """Read-only EKS API access policies; legacy Kubernetes RBAC is out of scope."""
        if auth_mode == 'CONFIG_MAP':
            return {'status': 'not_applicable', 'entries': []}
        if auth_mode not in ('API', 'API_AND_CONFIG_MAP'):
            self.issue('partial', 'UnknownEKSAuthenticationMode')
            return {'status': 'unknown', 'entries': []}
        if not isinstance(cluster_name, str) or not cluster_name:
            self.issue('partial', 'MissingEKSClusterName')
            return {'status': 'unknown', 'entries': []}
        client = AWSFacadeUtils.get_client('eks', self.session, region)
        if client is None:
            self.issue('failed', 'EKSAccessEntriesClientUnavailable')
            return {'status': 'unknown', 'entries': []}
        seen_tokens, next_token, seen_principals, entries = set(), None, set(), []
        complete = True
        for _ in range(20):
            args = {'clusterName': cluster_name, 'maxResults': 100}
            if next_token:
                args['nextToken'] = next_token
            try:
                response = await run_concurrently(
                    lambda args=args: client.list_access_entries(**args))
            except Exception as error:
                self.error('ListAccessEntries', error, partial=bool(entries))
                complete = False
                break
            rows = response.get('accessEntries') if isinstance(response, dict) else None
            if not isinstance(rows, list) or len(rows) > 100:
                self.issue('partial', 'MalformedAccessEntryList')
                complete = False
                break
            for principal in rows:
                if (not isinstance(principal, str) or not principal.startswith('arn:')
                        or principal in seen_principals or len(entries) >= 1000):
                    self.issue('partial', 'InvalidOrDuplicateAccessPrincipal')
                    complete = False
                    continue
                seen_principals.add(principal)
                entries.append({'principal_arn': principal, 'policies': [],
                                'policy_collection_status': 'unknown'})
            token = response.get('nextToken')
            if token in (None, ''):
                break
            if not isinstance(token, str) or len(token) > 4096 or token in seen_tokens:
                self.issue('partial', 'InvalidEKSAccessEntryToken')
                complete = False
                break
            seen_tokens.add(token)
            next_token = token
        else:
            self.issue('partial', 'EKSAccessEntryPageCap')
            complete = False

        # Do not fan out without bound or store request/response bodies beyond policy identifiers.
        for entry in entries:
            principal = entry['principal_arn']
            policy_token, policy_seen, policies = None, set(), []
            valid = True
            for _ in range(20):
                args = {'clusterName': cluster_name, 'principalArn': principal,
                        'maxResults': 100}
                if policy_token:
                    args['nextToken'] = policy_token
                try:
                    response = await run_concurrently(
                        lambda args=args: client.list_associated_access_policies(**args))
                except Exception as error:
                    self.error('ListAssociatedAccessPolicies', error, partial=True)
                    valid = False
                    break
                batch = response.get('associatedAccessPolicies') if isinstance(response, dict) else None
                if (not isinstance(batch, list) or len(batch) > 100
                        or any(not isinstance(p, dict) for p in batch)):
                    self.issue('partial', 'MalformedAccessPolicyList')
                    valid = False
                    break
                for item in batch:
                    policy = item.get('policyArn')
                    scope = item.get('accessScope')
                    kind = scope.get('type') if isinstance(scope, dict) else None
                    if (not isinstance(policy, str) or not policy.startswith('arn:')
                            or kind not in ('cluster', 'namespace')):
                        self.issue('partial', 'MalformedEKSAccessPolicy')
                        valid = False
                        continue
                    policies.append({'policy_arn': policy, 'scope': kind})
                token = response.get('nextToken')
                if token in (None, ''):
                    break
                if (not isinstance(token, str) or len(token) > 4096
                        or token in policy_seen):
                    self.issue('partial', 'InvalidEKSAccessPolicyToken')
                    valid = False
                    break
                policy_seen.add(token)
                policy_token = token
            else:
                self.issue('partial', 'EKSAccessPolicyPageCap')
                valid = False
            entry['policies'] = policies
            entry['policy_collection_status'] = 'complete' if valid else 'partial'
            if not valid:
                complete = False
        return {'status': 'complete' if complete else 'partial',
                'entries': entries}


    async def get_pod_identity_associations(self, region, cluster_name):
        """P5-D2: bounded List->Describe Pod Identity census.

        List summaries deliberately contain NO roleArn. Never infer roles from
        that response; only accept role/target role from verified Describe.
        Restrictive session-policy bodies are not written into the report.
        """
        import asyncio

        client = AWSFacadeUtils.get_client('eks', self.session, region)
        if client is None:
            self.issue('failed', 'PodIdentityClientUnavailable')
            return {'status': 'unknown', 'associations': []}
        seen_tokens, seen_ids, token, summaries = set(), set(), None, []
        complete = True
        for _ in range(MAX_PAGES):
            args = {'clusterName': cluster_name, 'maxResults': PAGE_SIZE}
            if token:
                args['nextToken'] = token
            try:
                page = await run_concurrently(
                    lambda args=args: client.list_pod_identity_associations(**args))
            except Exception as error:
                self.error('ListPodIdentityAssociations', error, partial=bool(summaries))
                complete = False
                break
            items = page.get('associations') if isinstance(page, dict) else None
            if not isinstance(items, list) or len(items) > PAGE_SIZE:
                self.issue('partial', 'MalformedPodIdentityAssociations')
                complete = False
                break
            for item in items:
                if not isinstance(item, dict):
                    self.issue('partial', 'MalformedPodIdentitySummary')
                    complete = False
                    continue
                ident = item.get('associationId')
                namespace = item.get('namespace')
                account_name = item.get('serviceAccount')
                association_arn = item.get('associationArn')
                if (not isinstance(ident, str) or not ident or ident in seen_ids
                        or item.get('clusterName', cluster_name) != cluster_name
                        or not all(isinstance(x, str) and x for x in
                                   (namespace, account_name, association_arn))
                        or len(summaries) >= MAX_CLUSTERS):
                    self.issue('partial', 'InvalidPodIdentitySummary')
                    complete = False
                    continue
                seen_ids.add(ident)
                summaries.append({
                    'id': ident, 'namespace': namespace, 'service_account': account_name,
                    'association_arn': association_arn,
                    'owner_arn': item.get('ownerArn') if isinstance(item.get('ownerArn'), str) else None,
                })
            following = page.get('nextToken') if isinstance(page, dict) else None
            if following in (None, ''):
                break
            if (not isinstance(following, str) or len(following) > 4096
                    or following in seen_tokens):
                self.issue('partial', 'InvalidPodIdentityPagination')
                complete = False
                break
            seen_tokens.add(following)
            token = following
        else:
            self.issue('partial', 'PodIdentityPageLimit')
            complete = False

        gate = asyncio.Semaphore(8)

        async def describe(summary):
            ident = summary['id']
            async with gate:
                try:
                    response = await run_concurrently(
                        lambda: client.describe_pod_identity_association(
                            clusterName=cluster_name, associationId=ident))
                except Exception as error:
                    self.error('DescribePodIdentityAssociation', error, partial=True)
                    return None
            detail = response.get('association') if isinstance(response, dict) else None
            if not isinstance(detail, dict) or any((
                    detail.get('associationId') != ident,
                    detail.get('clusterName') != cluster_name,
                    detail.get('namespace') != summary['namespace'],
                    detail.get('serviceAccount') != summary['service_account'],
                    detail.get('associationArn') != summary['association_arn'],
            )):
                self.issue('partial', 'PodIdentityDescribeMismatch')
                return None
            role = detail.get('roleArn')
            partition = ('aws', 'aws-us-gov', 'aws-cn')
            parts = role.split(':', 5) if isinstance(role, str) else []
            if (len(parts) != 6 or parts[0] != 'arn' or parts[1] not in partition
                    or parts[2] != 'iam' or parts[3] != ''
                    or parts[4] != self.owner_id or not parts[5].startswith('role/')):
                self.issue('partial', 'PodIdentityRoleMissingOrCrossAccount')
                return None
            target = detail.get('targetRoleArn')
            if target is not None and (not isinstance(target, str)
                                       or re.fullmatch(r'arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/.+', target) is None):
                self.issue('partial', 'MalformedPodIdentityTargetRole')
                return None
            raw_policy = detail.get('policy')
            if raw_policy is not None and not isinstance(raw_policy, str):
                self.issue('partial', 'MalformedPodIdentitySessionPolicy')
                return None
            # Only metadata, not raw session policy/values.
            return {
                **summary, 'role_arn': role, 'target_role_arn': target,
                'session_policy_present': bool(raw_policy),
                'session_policy_status': 'present' if raw_policy else 'absent',
                'disable_session_tags': detail.get('disableSessionTags')
                if isinstance(detail.get('disableSessionTags'), bool) else None,
                'detail_collection_status': 'complete',
            }

        details = await asyncio.gather(*(describe(summary) for summary in summaries))
        if any(item is None for item in details):
            complete = False
        records = [
            item if item is not None else {
                **summary, 'role_arn': None, 'target_role_arn': None,
                'session_policy_status': 'unknown', 'session_policy_present': None,
                'detail_collection_status': 'unknown',
            }
            for summary, item in zip(summaries, details)
        ]
        return {'status': 'complete' if complete else 'partial', 'associations': records}
