"""P2 account-level EC2 policy and conservative shared-resource review signals."""


def assess_account_imds_defaults(response):
    """Account policy only: a launch-time override or AMI can change effective IMDS."""
    if not isinstance(response, dict):
        return 'unknown'
    enforced = response.get('HttpTokensEnforced')
    tokens = response.get('HttpTokens')
    if enforced == 'enabled':
        return 'required'
    if tokens == 'required':
        return 'required_default'
    if enforced == 'disabled' and tokens in ('optional', 'no-preference'):
        return 'not_required'
    return 'unknown'


def _is_running(instance):
    state = instance.get('State') if isinstance(instance, dict) else None
    if not isinstance(state, dict):
        return None
    name = state.get('Name')
    return name == 'running' if isinstance(name, str) else None


def annotate_ssh_key_reuse(vpcs):
    """Region-scoped observation, not proof of private-key material reuse or compromise."""
    buckets = {}
    seen = []
    for vpc in vpcs.values():
        for instance in vpc.get('instances', {}).values():
            running = _is_running(instance)
            key = instance.get('KeyName')
            status = ('unknown' if running is None else
                      'not_applicable' if not running or not key else
                      'unique')
            instance['ssh_key_reuse_status'] = status
            instance['ssh_key_reuse_count'] = None
            if running and isinstance(key, str) and key:
                buckets.setdefault(key, []).append(instance)
                seen.append(instance)
    for instances in buckets.values():
        count = len(instances)
        for instance in instances:
            instance['ssh_key_reuse_count'] = count
            instance['ssh_key_reuse_status'] = 'reused' if count > 1 else 'unique'


def _unrestricted_egress(group):
    """Only an explicit ALL-protocol world CIDR is a decisive wide egress signal."""
    try:
        protocols = group['rules']['egress']['protocols']
    except (KeyError, TypeError):
        return None
    if not isinstance(protocols, dict):
        return None
    if 'ALL' not in protocols:
        return False
    ports = protocols['ALL'].get('ports') if isinstance(protocols['ALL'], dict) else None
    if not isinstance(ports, dict):
        return None
    for port, record in ports.items():
        if port not in ('1-65535', '0-65535'):
            continue
        if not isinstance(record, dict):
            return None
        cidrs = record.get('cidrs', [])
        if not isinstance(cidrs, list):
            return None
        if any(isinstance(cidr, dict) and cidr.get('CIDR') in ('0.0.0.0/0', '::/0')
               for cidr in cidrs):
            return True
    return False


def annotate_egress(vpcs):
    """Scope SG policy gaps to SGs attached to at least one RUNNING instance."""
    for vpc in vpcs.values():
        groups = vpc.get('security_groups', {})
        if not isinstance(groups, dict):
            continue
        active_groups = set()
        incomplete = False
        for instance in vpc.get('instances', {}).values():
            running = _is_running(instance)
            if running is None:
                incomplete = True
                continue
            if not running:
                continue
            interfaces = instance.get('network_interfaces')
            if not isinstance(interfaces, dict) or not interfaces:
                incomplete = True
                continue
            for eni in interfaces.values():
                refs = eni.get('Groups') if isinstance(eni, dict) else None
                if not isinstance(refs, list):
                    incomplete = True
                    continue
                for ref in refs:
                    group_id = ref.get('GroupId') if isinstance(ref, dict) else None
                    if group_id:
                        active_groups.add(group_id)
                    else:
                        incomplete = True
        for group_id, group in groups.items():
            breadth = _unrestricted_egress(group)
            group['egress_world_all_protocols_status'] = (
                'unknown' if breadth is None else
                'unrestricted' if breadth and group_id in active_groups else
                'not_applicable' if group_id not in active_groups and not incomplete else
                'unknown' if incomplete and group_id not in active_groups else
                'restricted')
            group['egress_active_instance_association'] = group_id in active_groups
