"""P3-D: review of broad S3 read IAM statements attached to running EC2 roles.

A broad identity-policy Allow is a *grant candidate*, NOT proof of effective
permissions: explicit Deny, permission boundaries, SCPs, resource policies and
session conditions may restrict it. No IAM policy simulation or AWS calls.
"""
import fnmatch
import json


def _as_policy(document):
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except (ValueError, TypeError):
            return None
    return document if isinstance(document, dict) else None


def _broad_action(action):
    if not isinstance(action, str):
        return False
    a = action.casefold()
    # ListAllMyBuckets is account-wide by design and insufficient alone.
    return a == '*' or a == 's3:*' or a.startswith('s3:get') or a.startswith('s3:list') and a != 's3:listallmybuckets'


def _broad_resource(value):
    if not isinstance(value, str):
        return False
    x = value.casefold()
    return x == '*' or x.startswith(('arn:aws:s3:::*', 'arn:aws-us-gov:s3:::*', 'arn:aws-cn:s3:::*'))


def _inspect_policy(document, name, source):
    doc = _as_policy(document)
    if doc is None:
        return [], True
    statements = doc.get('Statement')
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return [], True
    found, uncertain = [], False
    for row in statements:
        if not isinstance(row, dict):
            uncertain = True
            continue
        if 'NotAction' in row or 'NotResource' in row:
            uncertain = True  # Potential broad grant beyond the narrow matcher.
            continue
        effect = row.get('Effect')
        if effect not in ('Allow', 'Deny'):
            uncertain = True
            continue
        actions = row.get('Action', [])
        resources = row.get('Resource', [])
        actions = [actions] if isinstance(actions, str) else actions
        resources = [resources] if isinstance(resources, str) else resources
        if not isinstance(actions, list) or not isinstance(resources, list):
            uncertain = True
            continue
        if any(not isinstance(x, str) for x in actions + resources):
            uncertain = True
            continue
        is_broad = [action for action in actions if _broad_action(action)]
        target = [resource for resource in resources if _broad_resource(resource)]
        if not is_broad or not target:
            continue
        if effect == 'Deny' or row.get('Condition'):
            uncertain = True
            continue
        for action in is_broad:
            for resource in target:
                found.append({'policy': name, 'policy_origin': source,
                              'statement_sid': row.get('Sid'), 'action': action,
                              'resource': resource})
    return found, uncertain


def _role_grants(role, policies):
    if not isinstance(role, dict) or not isinstance(policies, dict):
        return 'unknown', []
    all_found, uncertain = [], False
    inline = role.get('inline_policies')
    if not isinstance(inline, dict):
        return 'unknown', []
    for name, value in inline.items():
        if not isinstance(value, dict) or 'PolicyDocument' not in value:
            uncertain = True
            continue
        found, partial = _inspect_policy(value['PolicyDocument'], value.get('name', name), 'inline')
        all_found.extend(found)
        uncertain |= partial
    managed = role.get('policies', [])
    if not isinstance(managed, list):
        return 'unknown', all_found
    for ident in managed:
        row = policies.get(ident)
        if not isinstance(row, dict) or 'PolicyDocument' not in row:
            uncertain = True
            continue
        found, partial = _inspect_policy(row['PolicyDocument'], row.get('arn', ident), 'managed')
        all_found.extend(found)
        uncertain |= partial
    return ('broad_grant_candidate' if all_found else 'unknown' if uncertain else
            'no_broad_grant_observed'), all_found


def annotate_instance_s3_grants(services, selected):
    ec2 = (services.get('ec2') or {}).get('regions') or {}
    iam = services.get('iam') if 'iam' in selected else None
    roles = (iam or {}).get('roles') if isinstance(iam, dict) else None
    policies = (iam or {}).get('policies') if isinstance(iam, dict) else None
    profile_index = {}
    if isinstance(roles, dict):
        for role in roles.values():
            if not isinstance(role, dict):
                continue
            profiles = role.get('instance_profiles')
            if not isinstance(profiles, dict):
                continue
            for profile_id in profiles:
                profile_index.setdefault(profile_id, []).append(role)
    for region in ec2.values():
        for vpc in (region.get('vpcs') or {}).values():
            for instance in (vpc.get('instances') or {}).values():
                instance['s3_wildcard_read_status'] = 'unknown'
                instance['s3_wildcard_read_evidence'] = []
                instance['s3_wildcard_read_role_arns'] = []
                state = (instance.get('State') or {}).get('Name')
                if state in ('stopped', 'stopping', 'shutting-down', 'terminated'):
                    instance['s3_wildcard_read_status'] = 'not_applicable'
                    continue
                if state != 'running':
                    continue
                profile = instance.get('iam_instance_profile_id')
                if not profile:
                    if instance.get('IamInstanceProfile') is None:
                        instance['s3_wildcard_read_status'] = 'not_applicable'
                    continue
                matching = profile_index.get(profile)
                if not matching or not isinstance(policies, dict):
                    continue
                if len(matching) != 1:
                    continue  # Ambiguous profile association.
                role = matching[0]
                status, grants = _role_grants(role, policies)
                instance['s3_wildcard_read_status'] = status
                instance['s3_wildcard_read_evidence'] = grants
                instance['s3_wildcard_read_role_arns'] = [role.get('arn')]
