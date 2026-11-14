"""P4-B2: conservative user/group, AssumeRole and OIDC-claims graph extension.

Read-only, deterministic and bounded. Graph edges are authorization candidates,
never confirmed IAM effective permissions (SCP/RCP/session/resource policies,
account constraints, organization boundaries and service execution not simulated).
"""
from ScoutSuite.providers.aws.resources.iam.relationship_graph import (
    _admin_hint, _edge_id, _matches_action, _oidc_scope, _permission,
    _role_documents, _service_trust, _trust_entries, _values,
    SERVICE_PATHS,
)

MAX_SOURCES = 1800
MAX_PAIRS = 160000
MAX_EDGES_B2 = 4000


def _policy_index(policies):
    result = dict(policies)
    for policy in policies.values():
        if isinstance(policy, dict) and isinstance(policy.get('arn'), str):
            result[policy['arn']] = policy
    return result


def _entity_documents(entity, policies, kind):
    """Exact attachments, never policy-centric best-effort lists."""
    if not isinstance(entity, dict):
        return [], True
    role_like = {
        'inline_policy_collection_status': entity.get(
            'inline_policy_collection_status', 'unknown'),
        'inline_policies': entity.get('inline_policies'),
        'attached_managed_policy_collection_status': entity.get('p4b2_managed_status', 'unknown'),
        'attached_managed_policy_arns': entity.get('p4b2_managed_arns'),
    }
    docs, incomplete = _role_documents(role_like, policies)
    if kind == 'user' and (entity.get('p4b2_boundary_status') != 'complete' or
                           entity.get('p4b2_boundary') is not None):
        incomplete = True
    return docs, incomplete


def _has_uncertain_effect(docs):
    return any(row.get('Effect') != 'Allow' or 'NotAction' in row or
               'NotResource' in row for _, rows in docs for row in rows)


def _trust_principal(target, principal_arn):
    """Only exact explicit IAM principal or same-account root trust is supported."""
    rows = _trust_entries(target)
    if rows is None or not isinstance(principal_arn, str):
        return 'unknown'
    account = principal_arn.split(':')[4] if principal_arn.count(':') >= 5 else ''
    root = principal_arn.split(':')[0] + ':' + principal_arn.split(':')[1] + ':iam::' + account + ':root'
    allowed = False
    ambiguous = False
    for row in rows:
        if 'NotPrincipal' in row:
            ambiguous = True
            continue
        action = _matches_action(row, 'sts:AssumeRole')
        if action == 'unknown':
            ambiguous = True
            continue
        if action != 'yes':
            continue
        principal = row.get('Principal')
        aws = principal.get('AWS') if isinstance(principal, dict) else None
        values = _values(aws)
        if values is None:
            if aws is not None or principal == '*':
                ambiguous = True
            continue
        if '*' in values:
            ambiguous = True
            continue
        relevant = principal_arn in values or root in values
        if relevant and row.get('Effect') == 'Deny':
            ambiguous = True
        elif relevant and row.get('Effect') == 'Allow':
            if row.get('Condition') is None:
                allowed = True
            else:
                ambiguous = True
    return 'unknown' if ambiguous else 'yes' if allowed else 'no'


def _oidc_audience_and_subject(role):
    rows = _trust_entries(role)
    if rows is None:
        return 'unknown', 'unknown'
    values = []
    uncertain = False
    for row in rows:
        action = _matches_action(row, 'sts:AssumeRoleWithWebIdentity')
        if action == 'unknown' or 'NotPrincipal' in row:
            uncertain = True
            continue
        if action != 'yes':
            continue
        if row.get('Effect') != 'Allow':
            uncertain = True
            continue
        principal = row.get('Principal')
        providers = _values(principal.get('Federated')) if isinstance(principal, dict) else None
        if providers is None:
            uncertain = True
            continue
        for provider in providers:
            if ':oidc-provider/' not in provider:
                continue
            host = provider.split('oidc-provider/', 1)[-1].lower()
            condition = row.get('Condition')
            audience, subject = 'missing', _oidc_scope(condition, provider)
            if not isinstance(condition, dict):
                values.append((audience, subject))
                continue
            found = []
            unexpected = False
            for op, keys in condition.items():
                if op not in ('StringEquals', 'StringLike') or not isinstance(keys, dict):
                    unexpected = True
                    continue
                for name, raw in keys.items():
                    if not isinstance(name, str):
                        unexpected = True
                    elif name.lower() == host + ':aud':
                        items = _values(raw)
                        if items is None:
                            unexpected = True
                        else:
                            found.extend((op, item) for item in items)
            if unexpected:
                uncertain = True
            elif found:
                if any(op == 'StringLike' and any(w in val for w in '*?')
                       for op, val in found):
                    audience = 'wildcard'
                elif any(op == 'StringEquals' and any(w in val for w in '*?')
                         for op, val in found):
                    audience = 'unknown'
                else:
                    audience = 'scoped'
            values.append((audience, subject))
    if uncertain:
        return 'unknown', 'unknown'
    if not values:
        return 'not_applicable', 'not_applicable'
    audiences, subjects = zip(*values)
    a = ('unknown' if 'unknown' in audiences else
         'review' if any(x in ('missing', 'wildcard') for x in audiences)
         else 'scoped')
    s = ('unknown' if 'unknown' in subjects else
         'review' if any(x in ('broad_subject', 'review_wildcard') for x in subjects)
         else 'scoped')
    return a, s


def _role_documents_complete(role, policies):
    docs, incomplete = _role_documents(role, policies)
    if role.get('inline_policy_collection_status') not in (None, 'complete'):
        incomplete = True
    if (role.get('role_boundary_collection_status') not in (None, 'complete')
            or role.get('permissions_boundary')):
        incomplete = True
    if _has_uncertain_effect(docs):
        incomplete = True
    return docs, incomplete


def _candidate_actions(docs, target_arn, target, kind):
    if kind == 'assume':
        return any(_permission(row, 'sts:AssumeRole', target_arn) == 'yes'
                   for _, rows in docs for row in rows)
    for _, action, principal in SERVICE_PATHS:
        if _service_trust(target, principal) != 'yes':
            continue
        passrole = any(_permission(row, 'iam:PassRole', target_arn, principal) == 'yes'
                       for _, rows in docs for row in rows)
        can_create = any(_permission(row, action, '*') == 'yes'
                         for _, rows in docs for row in rows)
        if passrole and can_create:
            return True
    return False


def extend_relationship_graph_b2(graph, roles, users, groups, policies):
    """Annotate users/groups/roles and return a bounded typed graph."""
    graph['schema'] = 'iam-relationships-p4b2-v1'
    graph.setdefault('limitations', []).extend((
        'B2 identity-policy candidates only; no effective IAM authorization proof',
        'Access Analyzer ValidatePolicy is policy lint, not IAM simulation',
        'exact user/group membership and attachment inventory required',
    ))
    if any(not isinstance(x, dict) for x in (roles, users, groups, policies)):
        graph['status'] = 'unknown'
        return graph
    lookup = _policy_index(policies)
    role_index = {r.get('arn'): r for r in roles.values()
                  if isinstance(r, dict) and isinstance(r.get('arn'), str)}
    admin_roles = [r for r in role_index.values()
                   if r.get('p4b_admin_policy_status') == 'admin_policy_candidate']
    user_index = {}
    group_index = {}
    for role in role_index.values():
        role['p4b2_role_assumerole_status'] = 'unknown'
        a, sub = _oidc_audience_and_subject(role)
        role['p4b2_oidc_audience_status'] = a
        role['p4b2_oidc_subject_status'] = sub
        role['p4b2_oidc_claims_status'] = (
            'unknown' if 'unknown' in (a, sub) else
            'not_applicable' if a == sub == 'not_applicable' else
            'review' if 'review' in (a, sub) else 'scoped')
        role['p4b2_access_analyzer_status'] = 'unknown'
        role['p4b2_access_analyzer_issue_codes'] = []

    for user in users.values():
        if not isinstance(user, dict):
            graph['status'] = 'partial'
            continue
        user['p4b2_user_passrole_status'] = 'unknown'
        user['p4b2_user_assumerole_status'] = 'unknown'
        if isinstance(user.get('arn'), str) and ':user/' in user['arn']:
            user_index[user['arn']] = user
    for group in groups.values():
        if not isinstance(group, dict):
            graph['status'] = 'partial'
            continue
        group['p4b2_group_passrole_status'] = 'unknown'
        if isinstance(group.get('arn'), str) and ':group/' in group['arn']:
            group_index[group['name']] = group

    if len(user_index) + len(group_index) + len(role_index) > MAX_SOURCES:
        graph['status'] = 'partial'
    source_count = 0
    pairs = 0
    user_to_groups = {}
    for user_arn, user in sorted(user_index.items()):
        membership = user.get('groups')
        if user.get('p4b2_membership_status') != 'complete' or not isinstance(membership, list):
            user_to_groups[user_arn] = None
        else:
            if any(not isinstance(x, str) or x not in group_index for x in membership):
                user_to_groups[user_arn] = None
            else:
                user_to_groups[user_arn] = sorted(set(membership))
    def edge(source, target, kind, service=''):
        if len(graph['edges']) >= MAX_EDGES_B2:
            graph['status'] = 'partial'
            return False
        key = _edge_id(source, target, kind, service)
        graph['edges'][key] = {'id': key, 'source': source, 'target': target,
                               'type': kind, 'service': service, 'evidence_ref': 'identity policy + trust review'}
        return True

    for name, group in sorted(group_index.items()):
        group_arn = group['arn']
        graph['nodes'][group_arn] = {'id': group_arn, 'type': 'group', 'name': name}
    for arn, user in sorted(user_index.items()):
        graph['nodes'][arn] = {'id': arn, 'type': 'user', 'name': user.get('name')}
        member = user_to_groups.get(arn)
        if member is not None:
            for name in member:
                edge(group_index[name]['arn'], arn, 'group_membership')

    sources = [('role', x['arn'], x) for x in role_index.values()] + [
        ('user', arn, user) for arn, user in user_index.items()]
    sources.sort(key=lambda x: x[1])
    for kind, arn, source in sources:
        source_count += 1
        if source_count > MAX_SOURCES:
            graph['status'] = 'partial'
            break
        if kind == 'role':
            docs, incomplete = _role_documents_complete(source, lookup)
        else:
            docs, incomplete = _entity_documents(source, lookup, 'user')
            memberships = user_to_groups.get(arn)
            if memberships is None:
                incomplete = True
            else:
                for name in memberships:
                    group_docs, missing = _entity_documents(group_index[name], lookup, 'group')
                    docs.extend(group_docs)
                    incomplete |= missing
        incomplete |= _has_uncertain_effect(docs)
        if incomplete:
            continue
        for target in sorted(admin_roles, key=lambda r: r['arn']):
            pairs += 1
            if pairs > MAX_PAIRS:
                graph['status'] = 'partial'
                break
            target_arn = target['arn']
            if arn == target_arn:
                continue
            if _candidate_actions(docs, target_arn, target, 'assume') and (
                    _trust_principal(target, arn) == 'yes'):
                if edge(arn, target_arn, 'assumerole_privileged_candidate'):
                    source['p4b2_role_assumerole_status' if kind == 'role'
                           else 'p4b2_user_assumerole_status'] = 'candidate'
            if kind == 'user' and _candidate_actions(docs, target_arn, target, 'passrole'):
                if edge(arn, target_arn, 'user_passrole_privileged_candidate'):
                    source['p4b2_user_passrole_status'] = 'candidate'
                    for name in user_to_groups.get(arn) or []:
                        group = group_index[name]
                        g_docs, g_incomplete = _entity_documents(group, lookup, 'group')
                        if not g_incomplete and any(
                                _permission(row, 'iam:PassRole', target_arn, p) == 'yes'
                                for _, rs in g_docs for row in rs
                                for _, _, p in SERVICE_PATHS):
                            group['p4b2_group_passrole_status'] = 'candidate'
        if graph['status'] == 'partial':
            break
    graph['nodes_count'] = len(graph['nodes'])
    graph['edges_count'] = len(graph['edges'])
    if graph['status'] != 'complete':
        for role in role_index.values():
            role['p4b2_role_assumerole_status'] = 'unknown'
            role['p4b2_oidc_audience_status'] = 'unknown'
            role['p4b2_oidc_subject_status'] = 'unknown'
        for user in user_index.values():
            user['p4b2_user_passrole_status'] = 'unknown'
            user['p4b2_user_assumerole_status'] = 'unknown'
        for group in group_index.values():
            group['p4b2_group_passrole_status'] = 'unknown'
    return graph
