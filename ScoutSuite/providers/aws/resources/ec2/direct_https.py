"""Read-only EC2 direct HTTPS exposure candidate from public ENIs and linked SGs.

The rule does not assert full Internet reachability: routes, NACLs, host firewalls,
listener state and application behavior are outside this inventory-based signal.
"""
from ipaddress import IPv6Address, AddressValueError


def _port_covers_443(key):
    if key in ('443', '1-65535', '0-65535'):
        return True
    try:
        lo, hi = (int(part) for part in str(key).split('-', 1))
        return lo <= 443 <= hi
    except (TypeError, ValueError):
        return False


def _public_ipv6(eni):
    addresses = eni.get('Ipv6Addresses', [])
    if not isinstance(addresses, list):
        return None
    for item in addresses:
        if not isinstance(item, dict):
            return None
        value = item.get('Ipv6Address')
        if not value:
            continue
        try:
            if IPv6Address(value).is_global:
                return True
        except (AddressValueError, TypeError):
            return None
    return False


def _ingress_world_https(group, ipv4, ipv6):
    if not isinstance(group, dict):
        return None
    try:
        protocols = group['rules']['ingress']['protocols']
    except (KeyError, TypeError):
        return None
    if not isinstance(protocols, dict):
        return None
    for proto in ('TCP', 'ALL'):
        if proto not in protocols:
            continue
        ports = protocols[proto].get('ports') if isinstance(protocols[proto], dict) else None
        if not isinstance(ports, dict):
            return None
        for key, port in ports.items():
            if not _port_covers_443(key):
                continue
            if not isinstance(port, dict):
                return None
            cidrs = port.get('cidrs', [])
            if not isinstance(cidrs, list):
                return None
            for entry in cidrs:
                if not isinstance(entry, dict):
                    return None
                cidr = entry.get('CIDR')
                if (ipv4 and cidr == '0.0.0.0/0') or (ipv6 and cidr == '::/0'):
                    return True
    return False


def classify_direct_public_https(instance, security_groups):
    """Return exposed / not_exposed / unknown; do not infer PASS on missing SG data."""
    if not isinstance(instance, dict) or not isinstance(security_groups, dict):
        return 'unknown'
    # Stopped/terminated instances cannot currently serve traffic. Retain
    # UNKNOWN for pending/transitional states rather than asserting exposure.
    state = instance.get('State')
    if not isinstance(state, dict) or not isinstance(state.get('Name'), str):
        return 'unknown'
    lifecycle = state['Name'].lower()
    if lifecycle in ('stopped', 'stopping', 'shutting-down', 'terminated'):
        return 'not_applicable'
    if lifecycle != 'running':
        return 'unknown'
    interfaces = instance.get('network_interfaces')
    if not isinstance(interfaces, dict) or not interfaces:
        return 'unknown'
    unknown = False
    for eni in interfaces.values():
        if not isinstance(eni, dict):
            unknown = True
            continue
        association = eni.get('Association')
        ipv4 = isinstance(association, dict) and bool(association.get('PublicIp'))
        ipv6 = _public_ipv6(eni)
        if ipv6 is None:
            unknown = True
        if not ipv4 and not ipv6:
            continue
        groups = eni.get('Groups')
        if not isinstance(groups, list) or not groups:
            unknown = True
            continue
        for ref in groups:
            group_id = ref.get('GroupId') if isinstance(ref, dict) else None
            if not group_id or group_id not in security_groups:
                unknown = True
                continue
            match = _ingress_world_https(security_groups[group_id], ipv4, ipv6 is True)
            if match is True:
                return 'exposed'
            if match is None:
                unknown = True
    return 'unknown' if unknown else 'not_exposed'
