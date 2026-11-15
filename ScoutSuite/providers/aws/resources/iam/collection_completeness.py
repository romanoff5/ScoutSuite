"""Conservative, payload-free IAM identity-listing completeness.

Only the AWS SDK final-response telemetry can prove that an empty IAM list was
successfully enumerated. Paginator failures after earlier successful pages
must not be reported as a complete empty IAM attack graph.
"""
from ScoutSuite.core.run_context import get_current_run_context


IDENTITY_LISTS = {
    'users': 'ListUsers',
    'roles': 'ListRoles',
    'groups': 'ListGroups',
    'policies': 'ListPolicies',
}
POLICY_DETAILS = ('GetPolicyVersion', 'ListEntitiesForPolicy')
CREDENTIAL_OPERATIONS = ('GenerateCredentialReport', 'GetCredentialReport')
# Paginator failures before an SDK response have no operation-level event.
GENERIC_LIST_FAILURES = frozenset((
    'AccessDenied', 'UnsupportedOperation', 'Timeout', 'MalformedPage',
    'ClientConstruction',
))


def _operation_state(counts):
    if not isinstance(counts, dict):
        return 'unknown'
    successes = counts.get('success', 0)
    denied = counts.get('denied', 0)
    failures = counts.get('failed', 0) + counts.get('unsupported', 0)
    if successes and not denied and not failures:
        return 'complete'
    if successes or (denied and failures):
        return 'partial'
    if denied:
        return 'denied'
    return 'partial' if failures else 'unknown'


def _combine(states):
    states = list(states)
    if states and all(state == 'complete' for state in states):
        return 'complete'
    if states and all(state == 'denied' for state in states):
        return 'denied'
    if states and all(state == 'unknown' for state in states):
        return 'unknown'
    return 'partial'


def iam_identity_inventory(context=None):
    """Report collection facts; never return AWS values or policy documents.

    Credential reports are independent of role/user/group privilege graph
    construction and deliberately do not gate its completeness.
    """
    context = context if context is not None else get_current_run_context()
    operations = {}
    generic_issue = False
    if context is not None and context.provider == 'aws':
        snapshot = context.aws_telemetry_snapshot()
        operations = snapshot['api'].get(('iam', 'global'), {}).get('operations', {})
        generic_issue = any(
            issue.get('scope') == 'iam'
            and issue.get('reason_code') in GENERIC_LIST_FAILURES
            for issue in context.collection_issues if isinstance(issue, dict))
    components = {
        name: _operation_state(operations.get(op))
        for name, op in IDENTITY_LISTS.items()
    }
    # ListPolicies can succeed while policy versions or attachments fail.
    if components['policies'] == 'complete' and any(
            _operation_state(operations.get(op)) in ('denied', 'partial')
            for op in POLICY_DETAILS):
        components['policies'] = 'partial'
    status = _combine(components.values())
    if generic_issue and status == 'complete':
        status = 'partial'
    # Both GenerateCredentialReport and GetCredentialReport are needed to
    # classify that optional independent inventory as complete.
    generate = _operation_state(operations.get('GenerateCredentialReport'))
    retrieve = _operation_state(operations.get('GetCredentialReport'))
    # A denied GenerateCredentialReport has no corresponding download attempt.
    # Preserve DENIED rather than diluting it with an unattempted UNKNOWN.
    credential_status = (generate if generate != 'complete' else
                         'partial' if retrieve == 'unknown' else retrieve)
    return {
        'schema': 'iam-identity-collection-v1',
        'status': status,
        'components': components,
        'credential_report_status': credential_status,
        'evidence': 'aws_final_response_telemetry',
        'complete': status == 'complete',
    }
