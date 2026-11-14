"""P5-A: path-scoped conservative IAM identity-policy candidate evaluation.

This is not IAM effective authorization or a substitute for SimulatePrincipalPolicy:
SCPs, RCPs, resource policies, session policies and permission boundaries are
not evaluated. Resource witnesses are synthetic, never evidence that a resource
exists or that a create API call would succeed.
"""
import fnmatch
import re

REGIONS = ('us-east-1', 'us-west-2', 'eu-west-1', 'eu-central-1',
           'ap-southeast-1', 'ap-northeast-1', 'af-south-1')
EC2_REQUIRED = ('image', 'instance', 'network-interface', 'security-group',
                'subnet', 'volume')
EC2_IDS = {
    'image': 'ami-0123456789abcdef0',
    'instance': 'i-0123456789abcdef0',
    'network-interface': 'eni-0123456789abcdef0',
    'security-group': 'sg-0123456789abcdef0',
    'subnet': 'subnet-0123456789abcdef0',
    'volume': 'vol-0123456789abcdef0',
}


def _strings(value):
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return value
    return None


def _scope(row, positive, negative, actual, *, ignore_case=False):
    """Match Action/NotAction or Resource/NotResource, including IAM negation."""
    if (positive in row) == (negative in row):
        return 'unknown'
    negate = negative in row
    patterns = _strings(row[negative if negate else positive])
    if patterns is None or not patterns:
        return 'unknown'
    if ignore_case:
        actual = actual.lower()
        patterns = [p.lower() for p in patterns]
    matched = any(fnmatch.fnmatchcase(actual, pattern) for pattern in patterns)
    return 'yes' if matched != negate else 'no'


def _condition(row, service):
    condition = row.get('Condition')
    if condition is None:
        return 'yes'
    if (not isinstance(condition, dict) or len(condition) != 1 or
            not service):
        return 'unknown'
    operator, keys = next(iter(condition.items()))
    if (operator not in ('StringEquals', 'StringNotEquals', 'StringLike',
                         'StringNotLike') or not isinstance(keys, dict) or
            set(keys) != {'iam:PassedToService'}):
        return 'unknown'
    values = _strings(keys['iam:PassedToService'])
    if not values:
        return 'unknown'
    if operator in ('StringEquals', 'StringNotEquals'):
        matched = service in values
    else:
        matched = any(fnmatch.fnmatchcase(service, value) for value in values)
    if operator in ('StringNotEquals', 'StringNotLike'):
        matched = not matched
    return 'yes' if matched else 'no'


def _statement_scope(row, action, resource, service=None):
    a = _scope(row, 'Action', 'NotAction', action, ignore_case=True)
    if a == 'no':
        return 'no'
    r = _scope(row, 'Resource', 'NotResource', resource)
    if r == 'no':
        return 'no'
    if a == 'unknown' or r == 'unknown':
        return 'unknown'
    return _condition(row, service)


def identity_permission(docs, action, resource, service=None):
    """Return yes/no/unknown for one synthetic request, with Deny precedence.

    'yes' means supported identity-policy grant and no applicable Deny found.
    Unknown relevant Deny/conditions always veto a confident candidate.
    Call only with a separately verified complete identity-policy inventory.
    """
    allowed = False
    maybe_allowed = False
    maybe_denied = False
    for _, statements in docs:
        for row in statements:
            scope = _statement_scope(row, action, resource, service)
            if scope == 'no':
                continue
            effect = row.get('Effect')
            if effect == 'Deny':
                if scope == 'yes':
                    return 'no'
                maybe_denied = True
            elif effect == 'Allow':
                if scope == 'yes':
                    allowed = True
                else:
                    maybe_allowed = True
            else:
                maybe_denied = True
    if maybe_denied:
        return 'unknown'
    if allowed:
        return 'yes'
    return 'unknown' if maybe_allowed else 'no'


def _identity(arn):
    if not isinstance(arn, str):
        return None
    parts = arn.split(':', 5)
    if (len(parts) != 6 or parts[0] != 'arn' or
            not re.fullmatch(r'[a-z0-9-]+', parts[1]) or
            not re.fullmatch(r'\d{12}', parts[4])):
        return None
    return parts[1], parts[4]


def _matching_rows(docs, action):
    for _, statements in docs:
        for row in statements:
            if row.get('Effect') != 'Allow':
                continue
            if _scope(row, 'Action', 'NotAction', action, ignore_case=True) == 'yes':
                yield row


def _regions(docs, action, service):
    regions = list(REGIONS)
    for row in _matching_rows(docs, action):
        for pattern in _strings(row.get('Resource')) or []:
            parts = pattern.split(':', 5)
            if len(parts) == 6 and parts[2] == service:
                region = parts[3]
                if re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d', region) and region not in regions:
                    regions.insert(0, region)
    return regions[:12]


def _suffixes(docs, action, service, kind):
    """Derive resource names from scoped Allow ARNs, avoiding Resource='*' FN."""
    defaults = (('P5ACandidate', 'P5AAlternate') if kind == 'function'
                else (EC2_IDS[kind],))
    suffixes = list(defaults)
    separator = ':' if service == 'lambda' else '/'
    prefix = kind + separator
    for row in _matching_rows(docs, action):
        for pattern in _strings(row.get('Resource')) or []:
            parts = pattern.split(':', 5)
            if len(parts) != 6 or parts[2] != service:
                continue
            resource = parts[5]
            if not resource.startswith(prefix):
                continue
            glob = resource[len(prefix):]
            if kind == 'function':
                value = glob.replace('*', 'P5A').replace('?', 'A')
                if re.fullmatch(r'[A-Za-z0-9_-]{1,64}', value):
                    suffixes.insert(0, value)
            else:
                marker = EC2_IDS[kind].split('-', 1)[0] + '-'
                raw = glob.replace('?', '0').split('*', 1)[0]
                if raw.startswith(marker) and re.fullmatch(r'[a-z0-9-]+', raw):
                    suffix = raw[len(marker):]
                    if re.fullmatch(r'[0-9a-f]{0,17}', suffix):
                        value = marker + (suffix + '0' * 17)[:17]
                        if fnmatch.fnmatchcase(value, glob):
                            suffixes.insert(0, value)
    return list(dict.fromkeys(suffixes))[:6]


def creation_permission(docs, action, principal_arn):
    """Bounded concrete-resource scenarios for Lambda and EC2 create actions.

    EC2 checks all six resource classes in one plausible VPC/EBS/subnet
    launch. A positive result is a candidate, never a claim of API success.
    Unsupported constraints are UNKNOWN rather than a verified permission.
    """
    who = _identity(principal_arn)
    if who is None:
        return 'unknown'
    partition, account = who
    if action == 'lambda:CreateFunction':
        service = 'lambda'
        required = ('function',)
    elif action == 'ec2:RunInstances':
        service = 'ec2'
        required = EC2_REQUIRED
    else:
        return 'unknown'
    seen_unknown = False
    for region in _regions(docs, action, service):
        # A bounded set of concrete scenarios; all paths are deterministic.
        for variant in range(2):
            results = []
            for kind in required:
                suffixes = _suffixes(docs, action, service, kind)
                suffix = suffixes[min(variant, len(suffixes) - 1)]
                if kind == 'function':
                    arn = f'arn:{partition}:lambda:{region}:{account}:function:{suffix}'
                else:
                    owner = '' if kind == 'image' else account
                    arn = f'arn:{partition}:ec2:{region}:{owner}:{kind}/{suffix}'
                results.append(identity_permission(docs, action, arn))
            if all(result == 'yes' for result in results):
                return 'yes'
            if any(result == 'unknown' for result in results):
                seen_unknown = True
    return 'unknown' if seen_unknown else 'no'
