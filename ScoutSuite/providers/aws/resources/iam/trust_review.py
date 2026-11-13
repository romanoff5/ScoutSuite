"""Conservative review of supported AWS service role trust scopes.

This flags only recognized services for which AWS documents SourceArn/SourceAccount
confused-deputy protections; it does not claim an exploit is practical.
"""
SCOPED_SERVICES = frozenset({
    'ecs-tasks.amazonaws.com', 'codedeploy.amazonaws.com',
    'config.amazonaws.com', 'codebuild.amazonaws.com',
})

def _values(value):
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return value
    return None

def review_trust(policy):
    doc = policy.get('PolicyDocument') if isinstance(policy, dict) else None
    statements = doc.get('Statement') if isinstance(doc, dict) else None
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return 'unknown'
    applicable = False
    for statement in statements:
        if not isinstance(statement, dict):
            return 'unknown'
        if statement.get('Effect') != 'Allow':
            continue
        actions = _values(statement.get('Action'))
        if actions is None:
            return 'unknown'
        if not any(a.lower() in ('sts:assumerole', 'sts:*', '*') for a in actions):
            continue
        principal = statement.get('Principal')
        if not isinstance(principal, dict) or 'Service' not in principal:
            continue
        services = _values(principal.get('Service'))
        if services is None:
            return 'unknown'
        if not any(s.lower() in SCOPED_SERVICES for s in services):
            continue
        applicable = True
        condition = statement.get('Condition')
        if condition is None:
            return 'missing'
        if not isinstance(condition, dict):
            return 'unknown'
        scoped = False
        for op, keys in condition.items():
            if not isinstance(keys, dict):
                return 'unknown'
            # IAM policy key casing is insignificant; positive operators only.
            if op.lower() not in ('stringequals','stringlike','arnequals','arnlike',
                                  'foranyvalue:stringequals','foranyvalue:arnlike'):
                continue
            for key, value in keys.items():
                if not isinstance(key, str) or key.lower() not in ('aws:sourceaccount','aws:sourcearn'):
                    continue
                values = _values(value)
                if values is None:
                    return 'unknown'
                # '*' alone does not meaningfully bind the principal to a source.
                if any(v.strip() and v.strip() != '*' and not v.strip().startswith('!') for v in values):
                    scoped = True
        if not scoped:
            return 'missing'
    return 'scoped' if applicable else 'not_applicable'
