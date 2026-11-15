"""P5-B2: per-resource evidence cards from already collected, read-only AWS facts.

Do not turn a correlated exposure candidate into verified network reachability.
No cloud calls are made here. All output is JSON-safe and HTML-escaped by the
Handlebars report; report identifiers remain original, not snapshot pseudonyms.
"""

import hashlib
from ipaddress import ip_address


# Mandatory predicates are confirmed only when the explicitly named field
# has the classifier's vulnerable state. No inferred policy simulator results.
POLICY_FIELDS = {
    'p5d-iam-delegation-v1': ('p5d_service_delegation_status', ('candidate',)),
    'p5d-eks-role-v1': ('p5d_eks_identity_status', ('candidate',)),
    'p5d-eks-cluster-v1': ('p5d_workload_identity_status', ('candidate',)),
    'p5d-cross-account-v1': ('p5d_cross_account_status', ('candidate',)),
    'p5d-external-invoke-review-v1': ('p5d_resource_policy_review', ('review',)),
    'iam-p4b-passrole-v1': ('p4b_passrole_path_status', ('candidate',)),
    'iam-p4b-privileged-oidc-v1': ('p4b_privileged_oidc_status', ('candidate',)),
    'iam-p4b2-user-passrole-v1': ('p4b2_user_passrole_status', ('candidate',)),
    'iam-p4b2-user-assumerole-v1': ('p4b2_user_assumerole_status', ('candidate',)),
    'iam-p4b2-role-assumerole-v1': ('p4b2_role_assumerole_status', ('candidate',)),
    'iam-p4b2-group-passrole-v1': ('p4b2_group_passrole_status', ('candidate',)),
    'iam-p4b2-oidc-audience-v1': ('p4b2_oidc_audience_status', ('review',)),
    'iam-p4b2-oidc-subject-v1': ('p4b2_oidc_subject_status', ('review',)),
    'backup-workload-arn-evidence-v1': ('p1_backup_evidence_status', ('not_reported',)),
    'backup-latest-restore-failure-v1': ('latest_restore_job_status', ('failed',)),
    'backup-latest-validation-failure-v1': ('latest_validation_status', ('failed',)),
    'backup-restore-testing-freshness-v1': (
        'restore_testing_schedule_status', ('stale', 'never_executed_stale')),
    'p3b-alb-backend-bypass-v1': ('backend_bypass_status', ('potential_bypass',)),
    'p3b-alb-hostname-cert-v1': ('https_hostname_coverage_status', ('mismatch',)),
    'cloudwatch-security-metric-alerting-v1': (
        'security_metric_alerting_status', ('missing', 'unlinked_security_filters')),
}

NETWORK_POLICIES = frozenset(('ec2-direct-public-https-v1', 'p3b-alb-backend-bypass-v1'))
IAM_CANDIDATE_POLICIES = frozenset((
    'iam-p4b-passrole-v1', 'iam-p4b-privileged-oidc-v1',
    'iam-p4b2-user-passrole-v1', 'iam-p4b2-user-assumerole-v1',
    'iam-p4b2-role-assumerole-v1', 'iam-p4b2-group-passrole-v1',
))


def _check(label, state, detail, source, required=True):
    return {'label': label, 'state': state, 'detail': detail,
            'source': source, 'required': required}


def _field(resource, field, expected, path, label=None):
    value = resource.get(field) if isinstance(resource, dict) else None
    known = isinstance(value, str) and value not in ('unknown', 'unavailable', 'incomplete')
    state = ('UNKNOWN' if not known else
             'CONFIRMED' if value in expected else 'CONTRADICTED')
    detail = ('{}={}'.format(field, value) if known else
              'Classifier state not collected or unsupported')
    return _check(label or field, state, detail, path + '.' + field)


def _unverified(label, detail, source):
    return _check(label, 'NOT_VERIFIED', detail, source, required=False)


def _ec2_sg_evidence(sg, public_v4, public_v6):
    """Return only the exact public 443 rule witnesses, never a generic SG claim."""
    from ScoutSuite.providers.aws.resources.ec2.direct_https import _port_covers_443
    protocols = (((sg.get('rules') or {}).get('ingress') or {}).get('protocols') or {})
    if not isinstance(protocols, dict):
        return []
    matches = []
    for protocol in ('TCP', 'ALL'):
        value = protocols.get(protocol)
        ports = value.get('ports', {}) if isinstance(value, dict) else {}
        if not isinstance(ports, dict):
            continue
        for port, rule in ports.items():
            if not _port_covers_443(port) or not isinstance(rule, dict):
                continue
            cidrs = rule.get('cidrs')
            if not isinstance(cidrs, list):
                continue
            for item in cidrs:
                cidr = item.get('CIDR') if isinstance(item, dict) else None
                if ((public_v4 and cidr == '0.0.0.0/0')
                        or (public_v6 and cidr == '::/0')):
                    matches.append('{} port {} from {}'.format(protocol, port, cidr))
    return matches


def _ec2_direct_checks(instance, services, path):
    """Witness: running EC2 + public ENI + world ingress TCP/443 on that ENI."""
    from ScoutSuite.providers.aws.resources.ec2.direct_https import _public_ipv6

    parts = path.split('.')
    vpc = None
    if (len(parts) >= 7 and parts[0:2] == ['ec2', 'regions']
            and parts[3] == 'vpcs' and parts[5] == 'instances'):
        vpc = ((((services.get('ec2') or {}).get('regions') or {})
                .get(parts[2]) or {}).get('vpcs') or {}).get(parts[4])
    groups = vpc.get('security_groups') if isinstance(vpc, dict) else None

    lifecycle = (instance.get('State') or {}).get('Name') if isinstance(instance.get('State'), dict) else None
    checks = [
        _field(instance, 'public_https_status', ('exposed',), path, 'Correlated HTTPS exposure candidate'),
        _check('EC2 lifecycle', 'CONFIRMED' if lifecycle == 'running' else
               'UNKNOWN' if lifecycle is None else 'CONTRADICTED',
               'State.Name={}'.format(lifecycle) if lifecycle else 'State not collected',
               path + '.State.Name'),
    ]
    interfaces = instance.get('network_interfaces')
    ip_witnesses, sg_witnesses = [], []
    inventory_unknown = not isinstance(interfaces, dict) or not interfaces
    sg_unknown = not isinstance(groups, dict)
    if isinstance(interfaces, dict):
        for eni_id, eni in interfaces.items():
            if not isinstance(eni, dict):
                inventory_unknown = True
                continue
            association = eni.get('Association')
            public_v4 = association.get('PublicIp') if isinstance(association, dict) else None
            v6 = _public_ipv6(eni)
            if v6 is None:
                inventory_unknown = True
            ipv6_values = []
            if v6:
                for item in eni.get('Ipv6Addresses', []):
                    value = item.get('Ipv6Address') if isinstance(item, dict) else None
                    try:
                        if value and ip_address(value).is_global:
                            ipv6_values.append(value)
                    except ValueError:
                        inventory_unknown = True
            if not public_v4 and not ipv6_values:
                continue
            ip_witnesses.extend('{} IPv4 {}'.format(eni_id, public_v4) for _ in [0] if public_v4)
            ip_witnesses.extend('{} IPv6 {}'.format(eni_id, value) for value in ipv6_values)
            references = eni.get('Groups')
            if not isinstance(references, list) or not references:
                sg_unknown = True
                continue
            for ref in references:
                sg_id = ref.get('GroupId') if isinstance(ref, dict) else None
                sg = groups.get(sg_id) if isinstance(groups, dict) else None
                if not isinstance(sg, dict):
                    sg_unknown = True
                    continue
                for match in _ec2_sg_evidence(sg, bool(public_v4), bool(ipv6_values)):
                    sg_witnesses.append('{} via {}: {}'.format(eni_id, sg_id, match))

    checks.append(_check(
        'Public network interface',
        'CONFIRMED' if ip_witnesses else 'UNKNOWN' if inventory_unknown else 'CONTRADICTED',
        '; '.join(ip_witnesses) if ip_witnesses else 'No confirmed public ENI address',
        path + '.network_interfaces'))
    checks.append(_check(
        'Internet-wide TCP/443 Security Group ingress',
        'CONFIRMED' if sg_witnesses else 'UNKNOWN' if sg_unknown else 'CONTRADICTED',
        '; '.join(sg_witnesses) if sg_witnesses else 'No corroborating SG ingress rule',
        path.rsplit('.instances.', 1)[0] + '.security_groups'))
    checks.extend((
        _unverified('End-to-end routing and NACL', 'No route-table/NACL reachability proof', path),
        _unverified('Host firewall and listener', 'Not verified from AWS inventory', path),
        _unverified('Active Internet reachability', 'No external connection test performed', path),
    ))
    return checks


P5D_EDGE_TYPES = {
    'p5d-iam-delegation-v1': frozenset((
        'iam_lambda_create', 'iam_lambda_update', 'iam_ec2_create',
        'iam_ecs_run_task', 'iam_ecs_register_run')),
    'p5d-eks-role-v1': frozenset(('eks_irsa_role', 'eks_pod_identity')),
    'p5d-eks-cluster-v1': frozenset(('eks_irsa_role', 'eks_pod_identity')),
    'p5d-cross-account-v1': frozenset((
        's3_cross_account_resource_policy', 's3_access_point_cross_account',
        'kms_cross_account_key_policy', 'kms_cross_account_grant')),
    'p5d-external-invoke-review-v1': frozenset(('lambda_external_invoke_review',)),
}


def _p5d_edge_belongs_to_resource(policy, resource, edge):
    """Require the graph witness to belong to THIS resource, not a sibling.

    A matching graph id and classifier state alone cannot establish which
    IAM role, EKS cluster, S3 bucket/AP, KMS key or Lambda was assessed.
    """
    source, target, kind = (edge.get('source'), edge.get('target'), edge.get('type'))
    if (not isinstance(resource, dict) or
            any(not isinstance(x, str) or not x for x in (source, target, kind))):
        return False
    if policy == 'p5d-iam-delegation-v1':
        return source == resource.get('arn')
    if policy == 'p5d-eks-role-v1':
        return target == resource.get('arn')
    if policy == 'p5d-eks-cluster-v1':
        cluster_arn = resource.get('cluster_arn')
        if not isinstance(cluster_arn, str) or not cluster_arn:
            return False
        if kind == 'eks_irsa_role':
            return source == cluster_arn
        if kind == 'eks_pod_identity':
            parts = source.rsplit('/', 2)
            return (len(parts) == 3 and parts[0] == cluster_arn
                    and bool(parts[1]) and bool(parts[2]))
        return False
    if policy == 'p5d-cross-account-v1':
        if kind == 's3_cross_account_resource_policy':
            name = resource.get('name')
            return isinstance(name, str) and bool(name) and target == 'arn:aws:s3:::' + name
        if kind == 's3_access_point_cross_account':
            return target == resource.get('AccessPointArn')
        if kind in ('kms_cross_account_key_policy', 'kms_cross_account_grant'):
            return target == resource.get('arn')
        return False
    if policy == 'p5d-external-invoke-review-v1':
        return target == resource.get('arn')
    return False


def _p5d_checks(policy, resource, services, path):
    """Bind a P5-D finding to exact serializable graph edge witnesses."""
    field, expected = POLICY_FIELDS[policy]
    state = resource.get(field)
    known = isinstance(state, str) and state not in ('unknown', 'partial', 'unavailable')
    verdict = ('UNKNOWN' if not known else
               'CONFIRMED' if state in expected else 'CONTRADICTED')
    checks = [_check('P5-D resource verdict', verdict,
                     '{}={}'.format(field, state) if known
                     else 'Classifier state not collected or unsupported',
                     path + '.' + field)]
    graph = (services.get('iam') or {}).get('attack_paths_p5d') or {}
    edges = graph.get('edges') if isinstance(graph, dict) else None
    details = resource.get('p5d_attack_path_details')
    valid = []
    if isinstance(details, list) and isinstance(edges, dict):
        for item in details[:80]:
            if not isinstance(item, dict):
                continue
            edge_id = item.get('id')
            if not isinstance(edge_id, str):
                continue
            edge = edges.get(edge_id)
            if not isinstance(edge, dict) or edge.get('type') not in P5D_EDGE_TYPES[policy]:
                continue
            canonical = (edge.get('source'), edge.get('target'),
                         edge.get('type'), edge.get('action'))
            if any(not isinstance(value, str) or not value for value in canonical):
                continue
            expected_id = hashlib.sha256('|'.join(canonical).encode('utf-8')).hexdigest()[:24]
            expected_verification = ('REVIEW' if policy == 'p5d-external-invoke-review-v1'
                                     else 'POTENTIAL')
            expected_confidence = ('LOW' if policy == 'p5d-external-invoke-review-v1'
                                   else 'MEDIUM')
            if (edge_id != expected_id or edge.get('id') != edge_id
                    or not _p5d_edge_belongs_to_resource(policy, resource, edge)
                    or any(edge.get(k) != item.get(k) for k in
                           ('id', 'source', 'target', 'type', 'action',
                            'verification', 'confidence'))
                    or edge.get('verification') != expected_verification
                    or edge.get('confidence') != expected_confidence
                    or edge.get('effective_permission_verified') is not False
                    or edge.get('execution_verified') is not False):
                continue
            valid.append(edge)
    if valid:
        example = sorted(valid, key=lambda e: e['id'])[0]
        detail = ('{} | {} -> {} | {} | {}'.format(
            example['type'], example['source'], example['target'],
            example['action'], (example.get('evidence') or {}).get('basis', '')))
        checks.append(_check(
            'Cross-service graph witness', 'CONFIRMED', detail,
            'iam.attack_paths_p5d.edges.' + example['id']))
    else:
        checks.append(_check('Cross-service graph witness', 'UNKNOWN',
                             'Missing or inconsistent graph edge; source and target unverified',
                             'iam.attack_paths_p5d.edges'))
    checks.append(_unverified(
        'Effective permission and workload execution',
        'NOT_VERIFIED: remote IAM, SCP/RCP, session policies, API execution and live Pods not simulated',
        'iam.attack_paths_p5d.limitations'))
    return checks


def build_observation_checks(policy, resource, services, path, outcome):
    """Generate explicitly sourced predicates without copying raw policies or secrets."""
    resource = resource if isinstance(resource, dict) else {}
    if policy == 'ec2-direct-public-https-v1':
        return _ec2_direct_checks(resource, services, path)
    if policy in P5D_EDGE_TYPES:
        return _p5d_checks(policy, resource, services, path)

    if policy in POLICY_FIELDS:
        field, expected = POLICY_FIELDS[policy]
        checks = [_field(resource, field, expected, path)]
    else:
        checks = [_check('Versioned classifier observation',
                         'CONFIRMED' if outcome == 'insecure' else 'UNKNOWN',
                         'evidence_policy={}'.format(policy), path)]

    if policy == 'p3b-alb-backend-bypass-v1':
        matches = resource.get('backend_bypass_evidence')
        if isinstance(matches, list) and matches:
            valid = all(isinstance(item, dict) and all(
                isinstance(item.get(key), str) and item[key]
                for key in ('instance_id', 'target_group_arn', 'security_group_id'))
                        and type(item.get('target_port')) is int for item in matches)
            detail = '; '.join(
                'EC2={} SG={} target={} port={} health={}'.format(
                    item['instance_id'], item['security_group_id'],
                    item['target_group_arn'], item['target_port'],
                    item.get('target_health', 'unknown')) for item in matches) if valid else 'Invalid witness'
        else:
            valid, detail = False, 'No target/SG correlation witness collected'
        checks.append(_check('Linked backend bypass witnesses',
                             'CONFIRMED' if valid else 'UNKNOWN', detail,
                             path + '.backend_bypass_evidence'))
    elif policy == 'cloudwatch-security-metric-alerting-v1':
        checks.extend((
            _field(resource, 'metric_filters_collection_status', ('complete',), path),
            _field(resource, 'metric_alarms_collection_status', ('complete',), path),
            _unverified('External SIEM and delivery',
                        'EXTERNAL_UNVERIFIED: no end-to-end delivery evidence', path),
        ))
    elif policy == 'p3b-alb-hostname-cert-v1':
        checked = resource.get('https_hostnames_checked')
        missing = resource.get('https_hostname_mismatches')
        checks.extend((
            _check('Visible Route 53 hostnames',
                   'CONFIRMED' if isinstance(checked, list) and checked else 'UNKNOWN',
                   ', '.join(checked) if isinstance(checked, list) and all(
                       isinstance(v, str) for v in checked) else 'Hostname census unavailable',
                   path + '.https_hostnames_checked'),
            _check('Certificate hostname mismatches',
                   'CONFIRMED' if isinstance(missing, list) and missing else 'UNKNOWN',
                   ', '.join(missing) if isinstance(missing, list) and all(
                       isinstance(v, str) for v in missing) else 'Mismatch details unavailable',
                   path + '.https_hostname_mismatches'),
            _unverified('Production hostname inventory and active SNI',
                        'UNVERIFIED: no complete production census or TLS handshake', path),
        ))
    elif policy in IAM_CANDIDATE_POLICIES:
        checks.append(_unverified('Effective IAM authorization',
                                  'NOT_VERIFIED: no IAM simulation or SCP/session proof', path))
    elif policy.startswith('backup-') or policy == 'm10q-s3-backup-evidence-v1':
        checks.append(_unverified('Application recovery objective',
                                  'UNKNOWN: no application restore, RPO or RTO proof', path))
    elif policy in NETWORK_POLICIES:
        checks.append(_unverified('Active Internet reachability',
                                  'NOT_VERIFIED: no route/NACL/host/connection proof', path))
    return checks


def resource_identity(resource, path):
    """Preserve real identifiers in confidential reports, never raw resource bodies."""
    resource = resource if isinstance(resource, dict) else {}
    identity = {'resource_id': resource.get('id') if isinstance(resource.get('id'), str)
                else path.rsplit('.', 1)[-1]}
    for source, target in (('arn', 'resource_arn'), ('cluster_arn', 'resource_arn'),
                           ('AccessPointArn', 'resource_arn'), ('name', 'resource_name'),
                           ('account_id', 'account_id'), ('owner_id', 'owner_id')):
        value = resource.get(source)
        if isinstance(value, str):
            identity[target] = value
    return identity


def build_resource_cards(finding):
    """Assess every insecure/UNKNOWN resource independently from fixed predicates.

    COMPLETE describes the available *rule evidence scope*, not an AWS API
    pagination guarantee, exploit verification or compliance certification.
    """
    summary = finding.get('evaluation_summary')
    if not isinstance(summary, dict) or not isinstance(summary.get('observations'), list):
        return []
    baseline = finding.get('confidence_assessment') or {}
    kind = baseline.get('claim_type', 'UNCLASSIFIED_LEGACY_RULE')
    severity = {'danger': 'HIGH', 'warning': 'MEDIUM',
                'review': 'REVIEW', 'good': 'INFO'}.get(
                    finding.get('level'), str(finding.get('level', 'UNKNOWN')).upper())
    counts = summary.get('counts') or {}
    mismatch = finding.get('flagged_items', 0) != counts.get('insecure', 0)
    cards = []
    for observation in summary['observations']:
        if not isinstance(observation, dict):
            continue
        checks = observation.get('predicate_checks') or []
        required = [check for check in checks if isinstance(check, dict) and check.get('required')]
        confirmed = sum(check.get('state') == 'CONFIRMED' for check in required)
        contradicted = any(check.get('state') == 'CONTRADICTED' for check in required)
        complete = bool(required) and confirmed == len(required)
        incomplete = finding.get('assessment_status') == 'incomplete'
        outcome = observation.get('outcome')
        attrs = observation.get('observed_attributes') or {}
        classifier_only = (len(required) == 1 and
                           required[0].get('label') == 'Versioned classifier observation')
        reasons = []
        if outcome != 'insecure':
            reasons.append('RESOURCE_EVIDENCE_UNKNOWN')
        if contradicted:
            reasons.append('PREDICATE_CONTRADICTION')
        elif not complete:
            reasons.append('REQUIRED_PREDICATE_UNVERIFIED')
        if incomplete:
            reasons.append('INCOMPLETE_COLLECTION_SCOPE')
        if mismatch:
            reasons.append('RULE_AND_EVIDENCE_COUNT_DIFFERENCE')
        if classifier_only:
            reasons.append('CLASSIFIER_ONLY_NO_INDEPENDENT_WITNESS')
        if kind in ('POTENTIAL_NETWORK_EXPOSURE', 'POTENTIAL_ATTACK_PATH'):
            reasons.append('REACHABILITY_OR_AUTHORIZATION_NOT_VERIFIED')
        if kind == 'POLICY_REVIEW' and not finding.get('severity_assigned'):
            reasons.append('ORGANIZATIONAL_POLICY_REVIEW')
        if outcome != 'insecure' or not complete or contradicted:
            confidence, verification = 'UNKNOWN', 'UNKNOWN'
        elif kind in ('POTENTIAL_NETWORK_EXPOSURE', 'POTENTIAL_ATTACK_PATH'):
            confidence, verification = 'MEDIUM', 'POTENTIAL'
        elif kind == 'BACKUP_RESTORE_OBSERVATION' or kind == 'VISIBLE_HOSTNAME_CORRELATION':
            confidence, verification = 'MEDIUM', 'OBSERVED_PARTIAL_SCOPE'
        elif kind == 'RESOURCE_POLICY_REVIEW':
            confidence, verification = 'LOW', 'REVIEW'
            reasons.append('INVOKE_GRANT_IS_NOT_ROLE_ESCALATION')
        elif kind == 'POLICY_REVIEW':
            confidence = 'MEDIUM' if incomplete or classifier_only else 'HIGH'
            verification = 'POLICY_VIOLATION' if finding.get('severity_assigned') else 'REVIEW'
        else:
            confidence = 'MEDIUM' if incomplete or mismatch or classifier_only else 'HIGH'
            verification = 'CONFIRMED_CONFIGURATION'
        # The classifier is evidence for its own outcome, not proof of the
        # exact API predicate. Do not let classifier-only cards claim HIGH.
        if classifier_only and not attrs and confidence == 'MEDIUM':
            reasons.append('NO_ALLOWLISTED_TECHNICAL_ATTRIBUTES')
        if incomplete and confidence == 'HIGH':
            confidence = 'MEDIUM'
        if mismatch and confidence == 'HIGH':
            confidence = 'MEDIUM'
        collection = ('COMPLETE' if complete and not incomplete else
                      'PARTIAL' if required else 'UNKNOWN')
        evidence_quality = ('UNAVAILABLE' if not required else
                            'PARTIAL' if not complete or incomplete else 'COMPLETE')
        identity = observation.get('resource_identity') or {}
        path = observation.get('resource_path', '')
        cards.append({
            'schema_version': 1, 'resource_path': path,
            'resource_id': identity.get('resource_id', path.rsplit('.', 1)[-1]),
            'resource_name': identity.get('resource_name'),
            'resource_arn': identity.get('resource_arn'),
            'account_id': identity.get('account_id'),
            'owner_id': identity.get('owner_id'),
            'severity': severity, 'outcome': outcome, 'claim_type': kind,
            'confidence': confidence, 'verification_status': verification,
            'collection': collection, 'reachability': (
                'NOT_VERIFIED' if kind == 'POTENTIAL_NETWORK_EXPOSURE' else 'NOT_ASSESSED'),
            'evidence_quality': evidence_quality,
            'confirmed_required_conditions': confirmed, 'required_conditions': len(required),
            'reason_codes': reasons,
            'supporting_evidence': checks,
            'technical_attributes': [{'name': key, 'value': str(value)}
                                     for key, value in attrs.items()],
        })
    return cards
