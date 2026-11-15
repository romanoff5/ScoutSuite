"""P5-D read-only, bounded AWS cross-service ATTACK PATH CANDIDATES.

Neither policy Allows nor resource grants prove effective AWS authorization.
Never upgrade missing collector data, conditions, restrictions or boundaries to PASS.
Real identifiers are retained in the ordinary report; replay export redaction is separate.
"""
import fnmatch
import hashlib
import re

from ScoutSuite.providers.aws.resources.iam.policy_accuracy import (
    identity_permission, creation_permission, _statement_scope, _scope,
    _regions as creation_regions, _suffixes as creation_suffixes,
)
from ScoutSuite.providers.aws.resources.iam.relationship_graph import (
    _role_documents, _service_trust, _statements, _matches_action,
)
from ScoutSuite.providers.aws.resources.iam.relationship_graph_b2 import (
    _entity_documents, _policy_index,
)

MAX_SOURCES = 1200
MAX_TARGETS = 1200
MAX_PAIRS = 150000
MAX_EDGES = 5000
MAX_RESOURCES = 3000
MAX_DETAILS_PER_RESOURCE = 80
READ_ACTIONS = ('s3:GetObject', 's3:PutObject', 's3:ListBucket')


def _arn_account(arn):
    if not isinstance(arn, str):
        return None
    parts = arn.split(':', 5)
    return parts[4] if len(parts) == 6 and re.fullmatch(r'[0-9]{12}', parts[4]) else None


def _values(value):
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(x, str) for x in value):
        return value
    return None


def _node_id(source, target, kind, action):
    value = '|'.join((source, target, kind, action))
    return hashlib.sha256(value.encode('utf-8')).hexdigest()[:24]


def _principal_scope(row, principal):
    if 'NotPrincipal' in row:
        return 'unknown'
    identity = row.get('Principal')
    if identity == '*':
        return 'unknown'  # Public/wildcard is not an identified external principal.
    if not isinstance(identity, dict) or 'AWS' not in identity:
        return 'no'
    allowed = _values(identity.get('AWS'))
    if not allowed:
        return 'unknown'
    if principal in allowed:
        return 'yes'
    return 'unknown' if any('*' in x or '?' in x for x in allowed) else 'no'


def _external_principals(policy, own_account):
    statements = _statements(policy)
    if statements is None:
        return [], True
    external, unknown = set(), False
    for row in statements:
        if row.get('Effect') != 'Allow':
            continue
        if row.get('NotPrincipal') is not None or row.get('Principal') == '*':
            unknown = True
            continue
        principal = row.get('Principal')
        identities = _values(principal.get('AWS')) if isinstance(principal, dict) else None
        if identities is None:
            unknown = True
            continue
        for arn in identities:
            account = _arn_account(arn)
            if account is not None and account != own_account and ':iam::' in arn:
                external.add(arn)
            elif account is None or '*' in arn or '?' in arn:
                unknown = True
    return sorted(external)[:MAX_RESOURCES], unknown or len(external) > MAX_RESOURCES


def _resource_permission(policy, principal, action, resource):
    """Tri-state policy evaluator with explicit Deny precedence.

    Treat unmodelled resource-policy conditions as UNKNOWN, not an authorization.
    """
    statements = _statements(policy)
    if statements is None:
        return 'unknown'
    allowed, uncertain = False, False
    for row in statements:
        p = _principal_scope(row, principal)
        if p == 'no':
            continue
        s = _statement_scope(row, action, resource)
        if s == 'no':
            continue
        if p == 'unknown' or s == 'unknown':
            uncertain = True
        elif row.get('Effect') == 'Deny':
            return 'no'
        elif row.get('Effect') == 'Allow':
            allowed = True
        else:
            uncertain = True
    if uncertain:
        return 'unknown'
    return 'yes' if allowed else 'no'


def _s3_object_witnesses(policy, bucket_name, principal, action, partition='aws'):
    """Construct bounded existing-policy prefix witnesses, not a fixed key.

    A bucket policy restricted to reports/* must not be tested only against
    P5DObjectWitness at the bucket root. All witnesses remain hypothetical;
    neither object existence nor external IAM authorization is inferred.
    """
    candidates = [f'arn:{partition}:s3:::{bucket_name}/P5DObjectWitness']
    rows = _statements(policy)
    if rows is None:
        return candidates
    for row in rows:
        if row.get('Effect') != 'Allow' or _principal_scope(row, principal) != 'yes':
            continue
        # Test Action/NotAction without changing the source statement.
        # Unknown conditions remain for _resource_permission to reject.
        if _scope(row, 'Action', 'NotAction', action, ignore_case=True) != 'yes':
            continue
        resources = _values(row.get('Resource'))
        if not resources:
            continue
        for pattern in resources:
            parts = pattern.split(':', 5)
            if (len(parts) != 6 or parts[0] != 'arn'
                    or parts[2] != 's3' or parts[3] or parts[4]
                    or not parts[5].startswith(bucket_name + '/')):
                continue
            suffix = parts[5][len(bucket_name) + 1:]
            if not suffix or len(suffix) > 400:
                continue
            # Literal keys and folder/extension patterns both get a witness.
            key = suffix.replace('*', 'P5DObjectWitness').replace('?', 'X')
            arn = ':'.join(parts[:5]) + ':' + bucket_name + '/' + key
            if fnmatch.fnmatchcase(arn, pattern):
                candidates.append(arn)
            if len(candidates) >= 24:
                break
        if len(candidates) >= 24:
            break
    return list(dict.fromkeys(candidates))[:24]


def _sources(iam):
    policies = iam.get('policies')
    roles = iam.get('roles')
    users = iam.get('users')
    groups = iam.get('groups')
    if any(not isinstance(v, dict) for v in (policies, roles, users, groups)):
        return [], False
    lookup = _policy_index(policies)
    groups_by_name = {v.get('name'): v for v in groups.values()
                      if isinstance(v, dict) and isinstance(v.get('name'), str)}
    result = []
    complete = True
    for kind, items in (('role', roles), ('user', users)):
        for obj in items.values():
            if not isinstance(obj, dict):
                complete = False
                continue
            arn = obj.get('arn')
            if _arn_account(arn) is None:
                complete = False
                continue
            if kind == 'role':
                docs, missing = _role_documents(obj, lookup)
                missing |= obj.get('role_boundary_collection_status') != 'complete'
                missing |= bool(obj.get('permissions_boundary'))
            else:
                docs, missing = _entity_documents(obj, lookup, 'user')
                memberships = obj.get('groups')
                if obj.get('p4b2_membership_status') != 'complete' or not isinstance(memberships, list):
                    missing = True
                else:
                    for name in memberships:
                        group = groups_by_name.get(name)
                        if group is None:
                            missing = True
                            continue
                        inherited, incomplete = _entity_documents(group, lookup, 'group')
                        docs.extend(inherited)
                        missing |= incomplete
            obj['p5d_service_delegation_status'] = 'unknown'
            obj['p5d_service_delegation_edges'] = []
            obj['p5d_ecs_execution_review_status'] = 'unknown'
            obj['p5d_attack_path_details'] = []
            result.append((arn, kind, obj, docs, missing))
            complete &= not missing
    result.sort(key=lambda row: row[0])
    return result[:MAX_SOURCES], complete and len(result) <= MAX_SOURCES


def _regions(services, service, subkey):
    root = services.get(service)
    if not isinstance(root, dict):
        return []
    regions = root.get('regions')
    if not isinstance(regions, dict):
        return []
    objects = []
    for region in regions.values():
        if not isinstance(region, dict):
            continue
        entries = region.get(subkey)
        if isinstance(entries, dict):
            objects.extend((v for v in entries.values() if isinstance(v, dict)))
    return objects[:MAX_RESOURCES]


def _regional_inventory_scope(services, service, subkey):
    """State whether a selected regional inventory is bounded and well-formed.

    _regions intentionally caps its output. Without checking the original
    source, a 3,001st resource can be silently skipped while the graph says
    complete and a clean finding incorrectly suggests full coverage.
    """
    root = services.get(service)
    regions = root.get('regions') if isinstance(root, dict) else None
    if not isinstance(regions, dict):
        return 'unknown'
    count = 0
    for region in regions.values():
        if not isinstance(region, dict):
            return 'partial'
        items = region.get(subkey)
        if not isinstance(items, dict):
            return 'unknown'
        count += len(items)
        if count > MAX_RESOURCES or any(not isinstance(item, dict)
                                        for item in items.values()):
            return 'partial'
    return 'observed_bounded'


def _s3_inventory_scope(s3):
    """Treat denied or truncated bucket policies as incomplete, not empty."""
    buckets = s3.get('buckets') if isinstance(s3, dict) else None
    if not isinstance(buckets, dict):
        return 'unknown'
    if len(buckets) > MAX_RESOURCES:
        return 'partial'
    for bucket in buckets.values():
        if not isinstance(bucket, dict):
            return 'partial'
        policy_status = bucket.get('policy_collection_status')
        if policy_status not in ('success', 'absent'):
            return 'partial'
        if policy_status == 'success' and _statements(bucket.get('policy')) is None:
            return 'partial'
    advanced = s3.get('advanced')
    if advanced is not None:
        regions = advanced.get('regions') if isinstance(advanced, dict) else None
        if not isinstance(regions, dict):
            return 'unknown'
        count = 0
        for region in regions.values():
            if not isinstance(region, dict):
                return 'partial'
            points = region.get('access_points')
            if not isinstance(points, dict):
                return 'unknown'
            count += len(points)
            if count > MAX_RESOURCES or any(not isinstance(ap, dict)
                                            for ap in points.values()):
                return 'partial'
            # A denied/unfinished GetAccessPointPolicy is not an empty policy.
            # Preserve uncertainty even when the AP inventory itself was read.
            if any(ap.get('policy_status') != 'verified'
                   or ap.get('detail_complete') is not True
                   or _statements(ap.get('policy_document')) is None
                   for ap in points.values()):
                return 'partial'
    return 'observed_bounded'


def _kms_inventory_scope(services):
    """KMS coverage includes policy and grant API results, not only key list."""
    census = _regional_inventory_scope(services, 'kms', 'keys')
    if census != 'observed_bounded':
        return census
    for key in _regions(services, 'kms', 'keys'):
        manager = key.get('key_manager')
        enabled = key.get('key_enabled')
        if manager not in ('CUSTOMER', 'AWS') or enabled is None:
            return 'partial'
        if manager != 'CUSTOMER' or enabled is False:
            continue
        if (key.get('policy_collection_status') != 'complete'
                or key.get('grants_collection_status') != 'complete'
                or _statements(key.get('policy')) is None):
            return 'partial'
        grants = key.get('grants')
        if not isinstance(grants, dict) or len(grants) > MAX_RESOURCES:
            return 'partial'
        if any(not isinstance(grant, dict) for grant in grants.values()):
            return 'partial'
    return 'observed_bounded'


def _invokable_lambda_creation(docs, source_arn):
    """One concrete witness must satisfy both creation and execution grants."""
    account = _arn_account(source_arn)
    if not account:
        return False
    partition = source_arn.split(':')[1]
    suffixes = creation_suffixes(docs, 'lambda:CreateFunction',
                                'lambda', 'function')
    for region in creation_regions(docs, 'lambda:CreateFunction', 'lambda'):
        for suffix in suffixes:
            arn = f'arn:{partition}:lambda:{region}:{account}:function:{suffix}'
            if (identity_permission(docs, 'lambda:CreateFunction', arn) == 'yes'
                    and identity_permission(docs, 'lambda:InvokeFunction', arn) == 'yes'):
                return True
    return False


def _workload_routes(docs, source_arn, target, services, cache):
    """Per-source capability precomputation avoids quadratic inventory scans."""
    target_arn = target['arn']
    paths = []
    for service, principal, action in (
        ('lambda', 'lambda.amazonaws.com', 'lambda:CreateFunction'),
        ('ec2', 'ec2.amazonaws.com', 'ec2:RunInstances'),
    ):
        if _service_trust(target, principal) != 'yes':
            continue
        if identity_permission(docs, 'iam:PassRole', target_arn, principal) != 'yes':
            continue
        if service == 'ec2' and not target.get('instance_profiles'):
            # RunInstances accepts an instance profile, not a bare IAM role.
            continue
        if service not in cache:
            cache[service] = (
                _invokable_lambda_creation(docs, source_arn)
                if service == 'lambda' else
                creation_permission(docs, action, source_arn) == 'yes')
        if cache[service]:
            paths.append((service + '_create', action,
                          'scoped identity grant + service trust; creation witness and execution grant verified as candidate'))

    # CloudGoat iam_privesc_by_attachment: a privileged role may have
    # *no* instance profile yet. An operator able to remove the current role
    # from an observed profile, add the privileged role, pass that role to EC2
    # and run a new instance has a separate potential delegation path.
    # Require an actual collected, occupied instance profile and both profile
    # mutation grants. Never assume an unobserved empty profile or that the
    # change/instance creation succeeds in AWS.
    if (_service_trust(target, 'ec2.amazonaws.com') == 'yes'
            and not target.get('instance_profiles')
            and identity_permission(docs, 'iam:PassRole', target_arn,
                                    'ec2.amazonaws.com') == 'yes'):
        if 'ec2' not in cache:
            cache['ec2'] = (creation_permission(
                docs, 'ec2:RunInstances', source_arn) == 'yes')
        if cache['ec2']:
            # This check executes once per source, not once per source-target
            # pair: scanning IAM profiles inside MAX_PAIRS would be cubic.
            if 'ec2_mutable_profile' not in cache:
                cache['ec2_mutable_profile'] = None
                inventory = services.get('iam') or {}
                roles = inventory.get('roles') or {}
                if isinstance(roles, dict):
                    for other in sorted(roles.values(), key=lambda item:
                                        str(item.get('arn', '')) if isinstance(item, dict) else ''):
                        if not isinstance(other, dict):
                            continue
                        profiles = other.get('instance_profiles')
                        if not isinstance(profiles, dict):
                            continue
                        for profile in sorted(profiles.values(), key=lambda item:
                                              str(item.get('arn', '')) if isinstance(item, dict) else ''):
                            if not isinstance(profile, dict):
                                continue
                            arn = profile.get('arn')
                            if (_arn_account(arn) != _arn_account(source_arn)
                                    or not arn.startswith(
                                        'arn:' + source_arn.split(':')[1] + ':iam::')
                                    or ':instance-profile/' not in arn):
                                continue
                            if (identity_permission(
                                    docs, 'iam:RemoveRoleFromInstanceProfile', arn) == 'yes'
                                    and identity_permission(
                                        docs, 'iam:AddRoleToInstanceProfile', arn) == 'yes'):
                                cache['ec2_mutable_profile'] = arn
                                break
                        if cache['ec2_mutable_profile']:
                            break
            profile_arn = cache['ec2_mutable_profile']
            if profile_arn:
                paths.append((
                    'ec2_profile_mutation',
                    'iam:RemoveRoleFromInstanceProfile+AddRoleToInstanceProfile+ec2:RunInstances',
                    'observed occupied instance profile ' + profile_arn
                    + '; profile replacement, propagation, EC2 launch and '
                    'runtime credential access NOT verified'))

    if (_service_trust(target, 'lambda.amazonaws.com') == 'yes'
            and identity_permission(docs, 'iam:PassRole', target_arn,
                                    'lambda.amazonaws.com') == 'yes'):
        if 'lambda_update' not in cache:
            cache['lambda_update'] = None
            for function in _regions(services, 'awslambda', 'functions'):
                arn = function.get('arn')
                if _arn_account(arn) != _arn_account(source_arn):
                    continue
                if (identity_permission(docs, 'lambda:UpdateFunctionConfiguration', arn) == 'yes'
                        and identity_permission(docs, 'lambda:UpdateFunctionCode', arn) == 'yes'
                        and identity_permission(docs, 'lambda:InvokeFunction', arn) == 'yes'):
                    cache['lambda_update'] = arn
                    break
        if cache['lambda_update']:
            paths.append(('lambda_update',
                          'lambda:UpdateFunctionConfiguration+UpdateFunctionCode+InvokeFunction',
                          'observed function ' + cache['lambda_update']
                          + '; role replacement + code control + invocation candidate'))

    if (_service_trust(target, 'ecs-tasks.amazonaws.com') == 'yes'
            and identity_permission(docs, 'iam:PassRole', target_arn,
                                    'ecs-tasks.amazonaws.com') == 'yes'):
        if 'ecs_run_by_role' not in cache:
            cache['ecs_run_by_role'] = {}
            cache['ecs_execution_by_role'] = {}
            for task in _regions(services, 'ecs', 'task_definitions'):
                arn = task.get('task_definition_arn')
                if (_arn_account(arn) != _arn_account(source_arn)
                        or identity_permission(docs, 'ecs:RunTask', arn) != 'yes'):
                    continue
                task_role = task.get('task_role_arn')
                if isinstance(task_role, str):
                    cache['ecs_run_by_role'].setdefault(task_role, arn)
                execution_role = task.get('execution_role_arn')
                if isinstance(execution_role, str):
                    cache['ecs_execution_by_role'].setdefault(execution_role, arn)
        arn = cache['ecs_run_by_role'].get(target_arn)
        if arn:
            paths.append(('ecs_run_task', 'ecs:RunTask',
                          'observed task-role definition ' + arn
                          + '; cluster/network execution unverified'))
        execution_arn = cache['ecs_execution_by_role'].get(target_arn)
        if execution_arn:
            # The ECS agent uses execution-role credentials; they are NOT
            # exposed to application containers. Never treat this as
            # container task-role privilege escalation.
            paths.append(('ecs_execution_role_review', 'ecs:RunTask',
                          'observed ECS agent execution role in ' + execution_arn
                          + '; agent permissions only, container access NOT proven'))
        if 'ecs_register_witness' not in cache:
            cache['ecs_register_witness'] = None
            if identity_permission(docs, 'ecs:RegisterTaskDefinition', '*') == 'yes':
                seen = set()
                for task in _regions(services, 'ecs', 'task_definitions'):
                    arn = task.get('task_definition_arn')
                    if not isinstance(arn, str) or _arn_account(arn) != _arn_account(source_arn):
                        continue
                    family = arn.rsplit(':', 1)[0]
                    if family in seen:
                        continue
                    seen.add(family)
                    witness = family + ':99999'
                    if identity_permission(docs, 'ecs:RunTask', witness) == 'yes':
                        cache['ecs_register_witness'] = witness
                        break
        if cache['ecs_register_witness']:
            paths.append(('ecs_register_run', 'ecs:RegisterTaskDefinition+RunTask',
                          'synthetic revision witness ' + cache['ecs_register_witness']
                          + '; workload launch unverified'))
    return paths


def _trust_blocked(statements, action, principal, principal_kind):
    """Reject a matching or uncertain explicit trust Deny, not unrelated Denies."""
    if not isinstance(statements, list):
        return True
    for row in statements:
        if row.get('Effect') != 'Deny':
            continue
        match = _matches_action(row, action)
        if match == 'no':
            continue
        if match == 'unknown' or 'NotPrincipal' in row:
            return True
        who = row.get('Principal')
        if who == '*':
            return True
        scoped = _values(who.get(principal_kind)) if isinstance(who, dict) else None
        if scoped is not None and (principal in scoped or '*' in scoped):
            # Even conditional Deny may apply. We do not simulate request context.
            return True
    return False


def _pod_trust_allow(statements, action):
    """Find one unconditional, explicit service Allow for this STS action.

    Separate trust Allow statements are combined by IAM policy evaluation;
    requiring AssumeRole and TagSession in the same statement creates false
    negatives. Unknown conditions, NotAction and wildcard principals do not
    count as confirmed Allows. Explicit Deny is checked separately.
    """
    return any(
        row.get('Effect') == 'Allow' and row.get('Condition') is None
        and isinstance(row.get('Principal'), dict)
        and 'pods.eks.amazonaws.com' in (
            _values(row['Principal'].get('Service')) or [])
        and any(fnmatch.fnmatchcase(action.lower(), pattern.lower())
                for pattern in (_values(row.get('Action')) or []))
        for row in statements
    )


def _eks_routes(services, iam, emit):
    roles = [r for r in (iam.get('roles') or {}).values()
             if isinstance(r, dict) and r.get('p4b_admin_policy_status') == 'admin_policy_candidate']
    for cluster in _regions(services, 'eks', 'clusters'):
        issuer = cluster.get('oidc_issuer')
        cluster_arn = cluster.get('cluster_arn')
        account = _arn_account(cluster_arn)
        if not account:
            cluster['p5d_workload_identity_status'] = 'unknown'
            continue
        # Pod Identity is independent of IRSA/OIDC: a cluster without an
        # observed OIDC issuer may still have verified EKS Pod Identity roles.
        has_issuer = isinstance(issuer, str) and issuer.startswith('https://')
        issuer_host = issuer[len('https://'):].rstrip('/') if has_issuer else ''
        partition = cluster_arn.split(':')[1]
        provider = 'arn:' + partition + ':iam::' + account + ':oidc-provider/' + issuer_host
        found = False
        for role in roles[:MAX_TARGETS]:
            target = role.get('arn')
            if not isinstance(target, str) or _arn_account(target) != account:
                continue
            statements = _statements((role.get('assume_role_policy') or {}).get('PolicyDocument'))
            if statements is None:
                continue
            if not has_issuer or _trust_blocked(
                    statements, 'sts:AssumeRoleWithWebIdentity',
                    provider, 'Federated'):
                continue
            for row in statements:
                principal = row.get('Principal')
                fed = _values(principal.get('Federated')) if isinstance(principal, dict) else None
                actions = _values(row.get('Action')) or []
                if row.get('Effect') != 'Allow' or provider not in (fed or []):
                    continue
                if not any(fnmatch.fnmatchcase('sts:assumerolewithwebidentity', a.lower()) for a in actions):
                    continue
                condition = row.get('Condition')
                if not isinstance(condition, dict):
                    continue
                keys = {}
                ambiguous = False
                if any(op not in ('StringEquals', 'StringLike') or not isinstance(values, dict)
                       for op, values in condition.items()):
                    continue
                for op, values in condition.items():
                    for key, valueset in values.items():
                        if key in keys:
                            # AWS ANDs separate condition operators: never
                            # replace one sub/aud restriction with another.
                            ambiguous = True
                        keys[key] = (op, _values(valueset))
                if ambiguous:
                    continue
                aud = keys.get(issuer_host + ':aud')
                sub = keys.get(issuer_host + ':sub')
                if (not aud or aud[0] != 'StringEquals' or aud[1] != ['sts.amazonaws.com']
                        or not sub or not sub[1]):
                    continue
                if sub[0] == 'StringEquals' and all(
                        re.fullmatch(r'system:serviceaccount:[a-z0-9-]+:[a-z0-9-]+', s)
                        for s in sub[1]):
                    emit(cluster_arn, target, 'eks_irsa_role', 'sts:AssumeRoleWithWebIdentity',
                         'observed EKS issuer + exact audience/subject; ServiceAccount existence not verified',
                         role, 'p5d_eks_identity_status')
                    found = True
        associations = cluster.get('pod_identity_associations')
        if cluster.get('pod_identity_inventory_status') == 'complete' and isinstance(associations, dict):
            for assoc in associations.values():
                if not isinstance(assoc, dict) or assoc.get('detail_collection_status') != 'complete':
                    continue
                namespace = assoc.get('namespace')
                service_account = assoc.get('service_account')
                if (not isinstance(namespace, str) or not namespace or
                        not isinstance(service_account, str) or not service_account):
                    continue
                # Role chaining or a restrictive association session policy
                # changes effective permissions. Do not label the first role
                # as an exploitable privilege destination in this case.
                if assoc.get('target_role_arn') or assoc.get('session_policy_present') is not False:
                    continue
                target = assoc.get('role_arn')
                role = next((x for x in roles if x.get('arn') == target), None)
                if role is None:
                    continue
                trust = _statements((role.get('assume_role_policy') or {}).get('PolicyDocument'))
                if trust is None:
                    continue
                if _trust_blocked(trust, 'sts:AssumeRole',
                                  'pods.eks.amazonaws.com', 'Service'):
                    continue
                if _trust_blocked(trust, 'sts:TagSession',
                                  'pods.eks.amazonaws.com', 'Service'):
                    continue
                if (_pod_trust_allow(trust, 'sts:AssumeRole')
                        and _pod_trust_allow(trust, 'sts:TagSession')):
                    emit(cluster_arn + '/' + namespace + '/' + service_account,
                         target, 'eks_pod_identity', 'sts:AssumeRole+TagSession',
                         'observed Pod Identity association + compatible trust; pod execution unverified',
                         role, 'p5d_eks_identity_status')
                    found = True
        cluster['p5d_workload_identity_status'] = (
            'candidate' if found else 'unknown')  # no in-cluster SA/pod census


def _resource_routes(services, own_account, emit):
    s3 = services.get('s3')
    if isinstance(s3, dict):
        for bucket in list((s3.get('buckets') or {}).values())[:MAX_RESOURCES]:
            if not isinstance(bucket, dict):
                continue
            bucket['p5d_cross_account_status'] = 'unknown'
            bucket['p5d_cross_account_edges'] = []
            if bucket.get('policy_collection_status') != 'success':
                continue
            name = bucket.get('name')
            policy = bucket.get('policy')
            if not isinstance(name, str) or not name:
                continue
            # The bucket collector's arn denotes bucket/*, not the bucket
            # root. Reconstruct the bucket root with its real AWS partition.
            raw_bucket_arn = bucket.get('arn')
            parts = raw_bucket_arn.split(':', 5) if isinstance(raw_bucket_arn, str) else []
            partition = (parts[1] if len(parts) == 6
                         and parts[0] == 'arn' and parts[2] == 's3'
                         and parts[1] in ('aws', 'aws-cn', 'aws-us-gov')
                         else 'aws')
            bucket_arn = f'arn:{partition}:s3:::{name}'
            principals, uncertain = _external_principals(policy, own_account)
            for principal in principals:
                # RestrictPublicBuckets blocks cross-account permissions from a
                # policy AWS has classified as public, regardless of explicit Allows.
                pab = bucket.get('public_access_block_configuration') or {}
                if bucket.get('policy_is_public') is True and pab.get('RestrictPublicBuckets') is True:
                    continue
                for action in READ_ACTIONS:
                    candidates = ([bucket_arn] if action == 's3:ListBucket'
                                  else _s3_object_witnesses(policy, name, principal, action,
                                                            partition))
                    witness = next((r for r in candidates if
                                    _resource_permission(policy, principal, action, r) == 'yes'), None)
                    if witness is None:
                        continue
                    if principal.endswith(':root'):
                        continue  # Account root principal delegates to remote IAM.
                    if bucket.get('policy_is_public') is True and pab.get('RestrictPublicBuckets') is None:
                        continue
                    edge_id = emit(principal, bucket_arn,
                                   's3_cross_account_resource_policy', action,
                                   'explicit external principal + scoped policy witness ' + witness
                                   + '; remote identity policy and object existence unknown',
                                   bucket, 'p5d_cross_account_status')
                    if edge_id:
                        bucket['p5d_cross_account_edges'].append(edge_id)
                    break
            if uncertain and bucket.get('p5d_cross_account_status') != 'candidate':
                bucket['p5d_cross_account_status'] = 'unknown'
        advanced = s3.get('advanced') or {}
        regions = advanced.get('regions', {}) if isinstance(advanced, dict) else {}
        for region in (regions.values() if isinstance(regions, dict) else []):
            if not isinstance(region, dict):
                continue
            for ap in list((region.get('access_points') or {}).values())[:MAX_RESOURCES]:
                if not isinstance(ap, dict):
                    continue
                ap['p5d_cross_account_status'] = 'unknown'
                if ap.get('policy_status') != 'verified' or not ap.get('detail_complete'):
                    continue
                policy = ap.get('policy_document')
                principals, _ = _external_principals(policy, own_account)
                ap_arn = ap.get('AccessPointArn')
                if not isinstance(ap_arn, str):
                    continue
                for principal in principals:
                    if principal.endswith(':root'):
                        continue
                    if _resource_permission(policy, principal, 's3:GetObject',
                                            ap_arn + '/object/P5DObjectWitness') == 'yes':
                        emit(principal, ap_arn, 's3_access_point_cross_account',
                             's3:GetObject',
                             'explicit AP policy; bucket policy, network origin and remote IAM unverified',
                             ap, 'p5d_cross_account_status')
    kms = services.get('kms')
    if isinstance(kms, dict):
        for key in _regions(services, 'kms', 'keys'):
            key['p5d_cross_account_status'] = 'unknown'
            if key.get('key_enabled') is False:
                key['p5d_cross_account_status'] = 'not_applicable'
                continue
            if key.get('key_enabled') is not True or key.get('key_manager') != 'CUSTOMER':
                continue
            arn = key.get('arn')
            if not isinstance(arn, str):
                continue
            # Do not trust a stale/partially collected key policy. A denied
            # GetKeyPolicy cannot be treated as a verified cross-account Allow.
            # Grant results are independently checked below: their existence
            # may still be observed even when the key policy is unreadable.
            if key.get('policy_collection_status') == 'complete':
                policy = key.get('policy')
                principals, _ = _external_principals(policy, own_account)
                for principal in principals:
                    if principal.endswith(':root'):
                        continue
                    if _resource_permission(policy, principal, 'kms:Decrypt', arn) == 'yes':
                        emit(principal, arn, 'kms_cross_account_key_policy', 'kms:Decrypt',
                             'explicit key policy; remote IAM Allow, key context and SCP/RCP unknown',
                             key, 'p5d_cross_account_status')
            grants = key.get('grants')
            if (key.get('grants_collection_status') == 'complete'
                    and isinstance(grants, dict)):
                for grant in list(grants.values())[:MAX_RESOURCES]:
                    if not isinstance(grant, dict):
                        continue
                    principal = grant.get('grantee_principal')
                    if (_arn_account(principal) in (None, own_account)
                            or not isinstance(grant.get('operations'), list)
                            or 'Decrypt' not in grant['operations']
                            or grant.get('constraints')):
                        continue
                    emit(principal, arn, 'kms_cross_account_grant', 'kms:Decrypt',
                         'observed unconstrained KMS grant; key usability and external context unverified',
                         key, 'p5d_cross_account_status')
    # An invoke permission alone never proves arbitrary-code execution or
    # privilege escalation. Mark review-only, never a confirmed escalation.
    for fn in _regions(services, 'awslambda', 'functions'):
        fn['p5d_resource_policy_review'] = 'unknown'
        fn_arn = fn.get('arn')
        role = fn.get('role_arn')
        if not isinstance(fn_arn, str) or not isinstance(role, str):
            continue
        policy = fn.get('access_policy')
        principals, _ = _external_principals(policy, own_account)
        for principal in principals:
            if principal.endswith(':root'):
                continue
            if _resource_permission(policy, principal, 'lambda:InvokeFunction', fn_arn) == 'yes':
                emit(principal, fn_arn, 'lambda_external_invoke_review',
                     'lambda:InvokeFunction',
                     'observed invocation grant to function with execution role ' + role
                     + '; invocation is NOT role assumption or code execution control',
                     fn, 'p5d_resource_policy_review', review=True)


def annotate_p5d_attack_paths(services, selected, account_id):
    """Correlate existing read-only collections, with explicit scan coverage."""
    iam = services.get('iam') if 'iam' in selected else None
    if not isinstance(iam, dict):
        return
    graph = {
        'schema': 'aws-attack-paths-p5d-v1', 'status': 'complete',
        'nodes': {}, 'edges': {}, 'edges_count': 0, 'nodes_count': 0,
        'collection': {}, 'scenarios_checked': 0,
        'limitations': [
            'IAM policies and trust: candidate configuration, not effective authorization',
            'SCP/RCP, session policies, remote account policies and runtime not simulated',
            'EKS Kubernetes ServiceAccounts and pods not read',
            'S3 object existence, remote identity grant and KMS encryption context unverified',
        ],
    }
    iam['attack_paths_p5d'] = graph
    source_rows, source_complete = _sources(iam)
    identity_inventory = iam.get('identity_inventory')
    # Offline synthetic fixtures predate the explicit IAM census. Live
    # IAM.finalize always supplies it, so denied empty lists cannot pass.
    census_status = (identity_inventory.get('status', 'unknown')
                     if isinstance(identity_inventory, dict) else None)
    if census_status is None:
        iam_status = 'complete' if source_complete else 'partial'
    elif census_status != 'complete':
        iam_status = census_status
    else:
        iam_status = 'complete' if source_complete else 'partial'
    graph['collection']['iam'] = iam_status
    if iam_status != 'complete':
        graph['status'] = ('unknown' if iam_status in ('denied', 'unknown')
                           else 'partial')
    def emit(source, target, kind, action, evidence, resource=None,
             status_field=None, review=False):
        if len(graph['edges']) >= MAX_EDGES:
            graph['status'] = 'partial'
            return None
        if not isinstance(source, str) or not isinstance(target, str):
            graph['status'] = 'partial'
            return None
        ident = _node_id(source, target, kind, action)
        graph['nodes'][source] = {'id': source}
        graph['nodes'][target] = {'id': target}
        graph['edges'][ident] = {
            'id': ident, 'source': source, 'target': target, 'type': kind,
            'action': action, 'verification': 'REVIEW' if review else 'POTENTIAL',
            'confidence': 'LOW' if review else 'MEDIUM',
            'collection': 'complete', 'effective_permission_verified': False,
            'execution_verified': False,
            'evidence': {'basis': evidence, 'source': source, 'resource': target},
        }
        if isinstance(resource, dict) and status_field:
            resource[status_field] = 'review' if review else 'candidate'
            details = resource.setdefault('p5d_attack_path_details', [])
            if isinstance(details, list) and len(details) < MAX_DETAILS_PER_RESOURCE:
                details.append({
                    'id': ident, 'source': source, 'target': target,
                    'type': kind, 'action': action,
                    'verification': 'REVIEW' if review else 'POTENTIAL',
                    'confidence': 'LOW' if review else 'MEDIUM',
                    'basis': evidence,
                    'effective_permission_verified': False,
                    'execution_verified': False,
                })
            else:
                resource['p5d_attack_path_details_truncated'] = True
        return ident
    roles = iam.get('roles') if isinstance(iam.get('roles'), dict) else {}
    targets = sorted((r for r in roles.values()
                      if isinstance(r, dict) and isinstance(r.get('arn'), str)
                      and r.get('p4b_admin_policy_status') == 'admin_policy_candidate'
                      and _arn_account(r['arn']) == account_id),
                     key=lambda r: r['arn'])
    if len(targets) > MAX_TARGETS:
        targets = targets[:MAX_TARGETS]
        graph['status'] = 'partial'
    for source_arn, kind, source, docs, missing in source_rows:
        if missing or _arn_account(source_arn) != account_id:
            continue
        capability_cache = {}
        for target in targets:
            graph['scenarios_checked'] += 1
            if graph['scenarios_checked'] > MAX_PAIRS:
                graph['status'] = 'partial'
                break
            if source_arn == target['arn']:
                continue
            for service, action, basis in _workload_routes(docs, source_arn, target, services, capability_cache):
                review = service == 'ecs_execution_role_review'
                status_field = ('p5d_ecs_execution_review_status' if review
                                else 'p5d_service_delegation_status')
                edge = emit(source_arn, target['arn'], 'iam_' + service, action,
                            basis, source, status_field, review=review)
                if edge and not review:
                    source['p5d_service_delegation_edges'].append(edge)
        if graph['status'] == 'partial' and graph['scenarios_checked'] > MAX_PAIRS:
            break
    # Correlate only the bounded prefix of each AWS inventory, but make
    # incomplete/denied/truncated collection explicit. No resource omission
    # may appear as a fully observed empty attack-path graph.
    for service, subkey in (('ecs', 'task_definitions'),
                            ('awslambda', 'functions'),
                            ('eks', 'clusters'), ('kms', 'keys')):
        census = (('not_selected' if service not in selected else
                   _kms_inventory_scope(services) if service == 'kms' else
                   _regional_inventory_scope(services, service, subkey)))
        graph['collection'][service + '_inventory'] = census
        if census in ('partial', 'unknown'):
            graph['status'] = 'partial'
    s3_scope = (_s3_inventory_scope(services.get('s3'))
                if 's3' in selected else 'not_selected')
    graph['collection']['s3_inventory'] = s3_scope
    if s3_scope in ('partial', 'unknown'):
        graph['status'] = 'partial'
    graph['collection']['lambda_ecs_ec2'] = (
        'partial' if graph['status'] != 'complete' else 'candidate_only')
    if 'eks' in selected:
        _eks_routes(services, iam, emit)
        # List/Describe denied, partial or malformed on any EKS cluster
        # invalidates the coverage census even if unrelated IRSA edges exist.
        if any(cluster.get('pod_identity_inventory_status') != 'complete'
               for cluster in _regions(services, 'eks', 'clusters')):
            graph['status'] = 'partial'
        graph['collection']['eks'] = 'partial_workload_scope'
    else:
        graph['collection']['eks'] = 'not_selected'
    _resource_routes(services, account_id, emit)
    # The EKS cluster modal needs the same exact edge witnesses that are
    # already serialized for IAM target roles. No additional AWS calls.
    cluster_index = {
        cluster['cluster_arn']: cluster
        for cluster in _regions(services, 'eks', 'clusters')
        if isinstance(cluster.get('cluster_arn'), str)
    }
    for cluster in cluster_index.values():
        cluster['p5d_attack_path_details'] = []
    for edge in sorted(graph['edges'].values(), key=lambda e: e['id']):
        if edge['type'] not in ('eks_irsa_role', 'eks_pod_identity'):
            continue
        anchor = (edge['source'] if edge['type'] == 'eks_irsa_role'
                  else edge['source'].rsplit('/', 2)[0])
        cluster = cluster_index.get(anchor)
        if cluster is None:
            continue
        details = cluster['p5d_attack_path_details']
        if len(details) < MAX_DETAILS_PER_RESOURCE:
            details.append({
                'id': edge['id'], 'source': edge['source'], 'target': edge['target'],
                'type': edge['type'], 'action': edge['action'],
                'verification': edge['verification'], 'confidence': edge['confidence'],
                'basis': edge['evidence']['basis'],
                'effective_permission_verified': False, 'execution_verified': False,
            })
        else:
            cluster['p5d_attack_path_details_truncated'] = True
    for service in ('s3', 'kms', 'awslambda'):
        census = graph['collection'].get(service + '_inventory', 'not_selected')
        graph['collection'][service] = (
            'not_selected' if service not in selected else
            'partial' if graph['status'] != 'complete' or census in ('partial', 'unknown')
            else 'candidate_only')
    graph['edges_count'] = len(graph['edges'])
    graph['nodes_count'] = len(graph['nodes'])
    return graph
