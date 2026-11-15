"""P4-B: conservative IAM relationship graph (role / OIDC provider / PassRole).

The graph captures identity-policy *candidates*, NOT effective AWS authorization.
It does not evaluate SCP/RCP, session policies, cross-account resource policies,
permissions boundaries, IAM policy simulator, or actual service execution.
Unknown or conditional policies never become verified PASS. No AWS mutations.
"""
import fnmatch
import hashlib
import json

from ScoutSuite.providers.aws.resources.iam.policy_accuracy import (
    identity_permission, creation_permission,
)


MAX_ROLES = 2500
MAX_EDGES = 4000
SERVICE_PATHS = (
    ('ec2', 'ec2:RunInstances', 'ec2.amazonaws.com'),
    ('lambda', 'lambda:CreateFunction', 'lambda.amazonaws.com'),
)


def _values(value):
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    return None


def _statements(document):
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except (ValueError, TypeError):
            return None
    if not isinstance(document, dict):
        return None
    rows = document.get('Statement')
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list) or len(rows) > 500:
        return None
    return rows if all(isinstance(row, dict) for row in rows) else None


def _matches_action(row, action):
    if 'NotAction' in row:
        return 'unknown'
    actions = _values(row.get('Action'))
    if actions is None:
        return 'unknown'
    return 'yes' if any(fnmatch.fnmatchcase(action.lower(), pattern.lower())
                        for pattern in actions) else 'no'


def _matches_resource(row, arn):
    if 'NotResource' in row:
        return 'unknown'
    resources = _values(row.get('Resource'))
    if resources is None:
        return 'unknown'
    return 'yes' if any(fnmatch.fnmatchcase(arn, pattern) for pattern in resources) else 'no'


def _permission(row, action, target, service=None):
    """Tri-state statement match; no speculative matching of other conditions."""
    if row.get('Effect') != 'Allow':
        return 'no' if row.get('Effect') == 'Deny' else 'unknown'
    match = _matches_action(row, action)
    if match != 'yes':
        return match
    match = _matches_resource(row, target)
    if match != 'yes':
        return match
    condition = row.get('Condition')
    if condition is None:
        return 'yes'
    if (not isinstance(condition, dict) or len(condition) != 1 or
            not service or 'StringEquals' not in condition or
            not isinstance(condition['StringEquals'], dict) or
            set(condition['StringEquals']) != {'iam:PassedToService'}):
        return 'unknown'
    allowed = _values(condition['StringEquals']['iam:PassedToService'])
    if allowed is None:
        return 'unknown'
    # StringEquals is literal, so a wildcard does not match a service name.
    return 'yes' if service in allowed else 'no'


def _role_documents(role, policies_by_id):
    docs = []
    incomplete = False
    inline = role.get('inline_policies')
    if role.get('inline_policy_collection_status') not in (None, 'complete'):
        incomplete = True
    if not isinstance(inline, dict):
        incomplete = True
    else:
        for key, data in sorted(inline.items()):
            document = data.get('PolicyDocument') if isinstance(data, dict) else None
            statements = _statements(document)
            if statements is None:
                incomplete = True
            else:
                docs.append(('inline:' + str(key), statements))
    attached_status = role.get('attached_managed_policy_collection_status')
    if attached_status is not None:
        # In real scans, use the independently verified exact role attachment
        # inventory. Legacy role["policies"] is filled by the policy-centric
        # collector, which cannot distinguish denied from empty attachments.
        if attached_status != 'complete':
            incomplete = True
            managed = []
        else:
            managed = role.get('attached_managed_policy_arns')
    else:
        # Preserve synthetic/older replay fixtures; absence is UNKNOWN.
        managed = role.get('policies')
    if not isinstance(managed, list) or any(not isinstance(k, str) for k in managed):
        incomplete = True
    else:
        for key in sorted(set(managed)):
            policy = policies_by_id.get(key)
            statements = _statements(policy.get('PolicyDocument')) if isinstance(policy, dict) else None
            if statements is None:
                incomplete = True
            else:
                docs.append((policy.get('arn') or str(key), statements))
    return docs, incomplete


def _admin_hint(role, docs, incomplete):
    """Admin-looking identity grant with scope-aware Deny review.

    This remains a policy candidate, never effective administrator access.
    """
    if role.get('role_boundary_collection_status') not in (None, 'complete'):
        return 'unknown'
    if role.get('permissions_boundary') or incomplete:
        return 'unknown'
    # AWS unions Allows across policy documents/statements; requiring all
    # admin-like actions in *one* statement incorrectly misses ordinary
    # split IAM/EC2/S3 managed policies. Keep the original broad Resource='*'
    # bar per action, then evaluate each synthetic request with scoped Deny.
    broad = all(
        any(row.get('Effect') == 'Allow'
            and row.get('Condition') is None
            and _matches_action(row, action) == 'yes'
            and _matches_resource(row, '*') == 'yes'
            for _, rows in docs for row in rows)
        for action in ('iam:CreateRole', 'ec2:RunInstances', 's3:DeleteObject')
    )
    if not broad:
        return 'no_admin_grant_observed'
    arn = role.get('arn', '')
    parts = arn.split(':', 5) if isinstance(arn, str) else []
    if len(parts) != 6:
        return 'unknown'
    partition, account = parts[1], parts[4]
    scenarios = (
        ('iam:CreateRole', f'arn:{partition}:iam::{account}:role/P5AAdminWitness'),
        ('ec2:RunInstances',
         f'arn:{partition}:ec2:us-east-1:{account}:instance/i-0123456789abcdef0'),
        ('s3:DeleteObject', 'arn:aws:s3:::p5a-iam-review/object'),
    )
    results = [identity_permission(docs, action, resource)
               for action, resource in scenarios]
    return 'admin_policy_candidate' if all(r == 'yes' for r in results) else 'unknown'


def _trust_entries(role):
    wrapper = role.get('assume_role_policy')
    policy = wrapper.get('PolicyDocument') if isinstance(wrapper, dict) else None
    return _statements(policy)


def _service_trust(role, service):
    rows = _trust_entries(role)
    if rows is None:
        return 'unknown'
    allowed = False
    uncertain = False
    for row in rows:
        action = _matches_action(row, 'sts:AssumeRole')
        if action == 'no':
            continue
        principal = row.get('Principal')
        # Principal='*' (or AWS='*') applies a Deny to service principals
        # too. A conditional or malformed trust statement is not proof of
        # usable service trust. Action-unrelated Denies are excluded above.
        if ('NotPrincipal' in row or principal == '*' or
                (isinstance(principal, dict) and
                 '*' in (_values(principal.get('AWS')) or []))):
            uncertain = True
            continue
        value = principal.get('Service') if isinstance(principal, dict) else None
        values = _values(value)
        if values is None or service not in values:
            if value is not None and values is None:
                uncertain = True
            continue
        if action == 'unknown':
            uncertain = True
            continue
        if row.get('Effect') == 'Deny':
            uncertain = True
        elif row.get('Effect') == 'Allow':
            if row.get('Condition') is not None:
                uncertain = True
            else:
                allowed = True
        else:
            uncertain = True
    return 'unknown' if uncertain else 'yes' if allowed else 'no'


def _oidc_scope(condition, provider_arn):
    host = provider_arn.split('oidc-provider/', 1)[-1].lower()
    if not isinstance(condition, dict):
        # AWS normally rejects an unscoped GitHub trust at policy creation.
        return 'unknown' if host == 'token.actions.githubusercontent.com' else 'broad_subject'
    subject = []
    recognized = False
    for operator, fields in condition.items():
        if not isinstance(fields, dict):
            return 'unknown'
        if operator not in ('StringEquals', 'StringLike'):
            return 'unknown'
        for name, value in fields.items():
            if not isinstance(name, str):
                return 'unknown'
            if name.lower() == host + ':sub':
                vals = _values(value)
                if vals is None:
                    return 'unknown'
                subject.extend((operator, item) for item in vals)
                recognized = True
    if not recognized:
        return 'unknown' if host == 'token.actions.githubusercontent.com' else 'broad_subject'
    if not subject:
        return 'unknown'
    for operator, value in subject:
        if operator == 'StringLike' and (
                value in ('*', '?') or
                value.startswith(('repo:*', 'repo:*/', 'repo:?', 'system:serviceaccount:*'))):
            return 'broad_subject'
    if any((op == 'StringEquals' and ('*' in val or '?' in val))
           for op, val in subject):
        # Wildcards are literal in StringEquals.
        return 'unknown'
    if any(('*' in val or '?' in val) for _, val in subject):
        return 'review_wildcard'
    return 'scoped_subject'


def _oidc_trust(role):
    rows = _trust_entries(role)
    if rows is None:
        return 'unknown', []
    entries = []
    uncertain = False
    for row in rows:
        action = _matches_action(row, 'sts:AssumeRoleWithWebIdentity')
        if action == 'unknown':
            uncertain = True
            continue
        if action != 'yes':
            continue
        principal = row.get('Principal')
        federated = principal.get('Federated') if isinstance(principal, dict) else None
        values = _values(federated)
        if values is None:
            if federated is not None:
                uncertain = True
            continue
        providers = [v for v in values if ':oidc-provider/' in v]
        for provider in providers:
            if row.get('Effect') == 'Deny':
                uncertain = True
                continue
            if row.get('Effect') != 'Allow':
                uncertain = True
                continue
            scope = _oidc_scope(row.get('Condition'), provider)
            if scope == 'unknown':
                uncertain = True
            entries.append({'provider_arn': provider, 'subject_scope': scope,
                            'statement_sid': str(row.get('Sid', ''))[:100]})
    if uncertain:
        return 'unknown', entries
    if not entries:
        return 'not_applicable', entries
    scopes = [row['subject_scope'] for row in entries]
    if 'broad_subject' in scopes:
        return 'broad_subject', entries
    if 'review_wildcard' in scopes:
        return 'review_wildcard', entries
    return 'scoped_subject', entries


def _edge_id(source, target, kind, service):
    value = '|'.join((source, target, kind, service)).encode('utf-8')
    return hashlib.sha256(value).hexdigest()[:24]


def build_relationship_graph(roles, policies):
    """Annotate roles and return a deterministic, bounded, read-only graph."""
    graph = {'schema': 'iam-relationships-p4b-v1', 'status': 'complete',
             'nodes': {}, 'edges': {}, 'nodes_count': 0,
             'edges_count': 0, 'limitations': [
                 'identity-policy candidates only',
                 'SCP/RCP, session policies, resource policies, boundaries and simulation not evaluated',
                 'role principals only in first P4-B phase',
             ]}
    if not isinstance(roles, dict) or not isinstance(policies, dict):
        graph['status'] = 'unknown'
        return graph
    if len(roles) > MAX_ROLES:
        graph['status'] = 'partial'
    listed = sorted((role for role in roles.values() if isinstance(role, dict)),
                    key=lambda role: str(role.get('arn', '')))[:MAX_ROLES]
    # Both IAM role attachment ARNs and legacy policy IDs resolve here.
    # An attachment with no collected policy document remains UNKNOWN.
    policy_lookup = dict(policies)
    for policy in policies.values():
        if isinstance(policy, dict) and isinstance(policy.get('arn'), str):
            policy_lookup[policy['arn']] = policy
    role_index = {}
    policy_data = {}
    oidc_entries = {}
    for role in listed:
        role['p4b_passrole_path_status'] = 'unknown'
        role['p4b_passrole_target_arns'] = []
        role['p4b_oidc_scope_status'] = 'unknown'
        role['p4b_privileged_oidc_status'] = 'unknown'
        arn = role.get('arn')
        if not isinstance(arn, str) or ':iam::' not in arn or ':role/' not in arn:
            graph['status'] = 'partial'
            continue
        role_index[arn] = role
        docs, incomplete = _role_documents(role, policy_lookup)
        policy_data[arn] = (docs, incomplete)
        role['p4b_admin_policy_status'] = _admin_hint(role, docs, incomplete)
        scope, entries = _oidc_trust(role)
        role['p4b_oidc_scope_status'] = scope
        oidc_entries[arn] = entries
        role['p4b_privileged_oidc_status'] = (
            'candidate' if entries and scope != 'unknown' and
            role['p4b_admin_policy_status'] == 'admin_policy_candidate'
            else 'review' if entries and
            (scope == 'unknown' or role['p4b_admin_policy_status'] == 'unknown')
            else 'not_applicable' if not entries and scope == 'not_applicable'
            else 'unknown')
        graph['nodes'][arn] = {'id': arn, 'type': 'role',
                               'name': role.get('name'), 'admin_hint': role['p4b_admin_policy_status']}

    def add_edge(source, target, kind, service='', evidence=''):
        if len(graph['edges']) >= MAX_EDGES:
            graph['status'] = 'partial'
            return False
        key = _edge_id(source, target, kind, service)
        graph['edges'][key] = {'id': key, 'source': source, 'target': target,
                               'type': kind, 'service': service, 'evidence_ref': evidence}
        return True

    for arn, entries in sorted(oidc_entries.items()):
        for entry in entries:
            provider = entry['provider_arn']
            graph['nodes'].setdefault(provider, {'id': provider, 'type': 'oidc_provider'})
            add_edge(provider, arn, 'oidc_trust', evidence=entry['subject_scope'])

    admins = [role for role in role_index.values()
              if role.get('p4b_admin_policy_status') == 'admin_policy_candidate']
    for source_arn, source in sorted(role_index.items()):
        if source['p4b_admin_policy_status'] == 'admin_policy_candidate':
            source['p4b_passrole_path_status'] = 'not_applicable'
            continue  # Not privilege escalation for an already admin-like source.
        docs, incomplete = policy_data[source_arn]
        if (source.get('role_boundary_collection_status') not in (None, 'complete')
                or source.get('permissions_boundary')):
            source['p4b_passrole_path_status'] = 'unknown'
            continue
        creation_cache = {}
        for target in admins:
            target_arn = target['arn']
            if target_arn == source_arn:
                continue
            found = False
            for label, service_action, service_principal in SERVICE_PATHS:
                if _service_trust(target, service_principal) != 'yes':
                    continue
                if incomplete:
                    source['p4b_passrole_path_status'] = 'unknown'
                    continue
                passing = identity_permission(
                    docs, 'iam:PassRole', target_arn, service_principal)
                if passing != 'yes':
                    continue
                if service_action not in creation_cache:
                    creation_cache[service_action] = creation_permission(
                        docs, service_action, source_arn)
                if creation_cache[service_action] != 'yes':
                    continue
                source['p4b_passrole_path_status'] = 'candidate'
                source['p4b_passrole_target_arns'].append(target_arn)
                add_edge(source_arn, target_arn, 'passrole_privileged_role_candidate',
                         service=label, evidence='identity policy + scoped Deny review')
                found = True
            if found and graph['status'] == 'partial':
                source['p4b_passrole_path_status'] = 'unknown'
        if source['p4b_passrole_path_status'] != 'candidate':
            source['p4b_passrole_path_status'] = 'unknown'  # no verified absence

    graph['nodes_count'] = len(graph['nodes'])
    graph['edges_count'] = len(graph['edges'])
    if graph['status'] == 'partial':
        # Truncated inventory is never a proof that other paths are absent.
        for role in roles.values():
            if isinstance(role, dict):
                role['p4b_passrole_path_status'] = 'unknown'
                role['p4b_oidc_scope_status'] = 'unknown'
                role['p4b_privileged_oidc_status'] = 'unknown'
    return graph
