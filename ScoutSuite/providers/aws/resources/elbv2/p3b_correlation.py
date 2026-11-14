"""P3-B: additive, read-only ALB/backend and ACM/Route53 correlations.

These signals do not establish actual external TCP reachability or TLS
handshake success: routing, NACLs, host firewall, SNI traffic and DNS outside
the visible account need independent testing. Missing data is UNKNOWN.
"""
from ipaddress import ip_address


def _dns(value):
    if not isinstance(value, str):
        return None
    out = value.lower().strip().rstrip('.')
    if out.startswith('dualstack.'):
        out = out[len('dualstack.'):]
    return out if out and ' ' not in out else None


def _hostname(value):
    name = _dns(value)
    if name is None or '*' in name or len(name) > 253 or '.' not in name:
        return None
    return name


def _san_covers(pattern, host):
    pattern = _dns(pattern)
    host = _hostname(host)
    if not pattern or not host:
        return False
    if pattern.startswith('*.'):
        suffix = pattern[2:]
        # A wildcard matches exactly one DNS label, not nested subdomains.
        return host.endswith('.' + suffix) and len(host.split('.')) == len(suffix.split('.')) + 1
    return pattern == host


def _route53_alias_hosts(services, alb_dns):
    route = (services.get('route53') or {}).get('regions') or {}
    hostnames = set()
    if not isinstance(route, dict):
        return []
    for region in route.values():
        if not isinstance(region, dict):
            continue
        for zone in (region.get('hosted_zones') or {}).values():
            if not isinstance(zone, dict):
                continue
            config = zone.get('config') or {}
            if config.get('PrivateZone') is True:
                continue
            records = zone.get('resource_record_sets')
            if not isinstance(records, list):
                continue
            for rec in records:
                if not isinstance(rec, dict) or rec.get('Type') not in ('A', 'AAAA', 'CNAME'):
                    continue
                candidates = []
                alias = rec.get('AliasTarget')
                if isinstance(alias, dict):
                    candidates.append(alias.get('DNSName'))
                for value in rec.get('ResourceRecords') or []:
                    if isinstance(value, dict):
                        candidates.append(value.get('Value'))
                if any(_dns(name) == alb_dns for name in candidates):
                    hostname = _hostname(rec.get('Name'))
                    if hostname:
                        hostnames.add(hostname)
    return sorted(hostnames)


def _certificate_host_coverage(lb, acm_region, route53_hosts):
    if lb.get('Type') != 'application' or lb.get('Scheme') != 'internet-facing':
        return 'not_applicable', []
    https = [listener for port, listener in (lb.get('listeners') or {}).items()
             if str(port) == '443' and isinstance(listener, dict)
             and listener.get('Protocol') == 'HTTPS']
    if not https:
        return 'not_applicable', []
    if not route53_hosts:
        return 'unknown', []
    if not isinstance(acm_region, dict):
        return 'unknown', []
    certs = acm_region.get('certificates')
    if not isinstance(certs, dict):
        return 'unknown', []
    attached = set()
    for listener in https:
        if listener.get('certificate_inventory_status') != 'complete':
            return 'unknown', []
        arns = listener.get('certificate_arns')
        if not isinstance(arns, list) or not arns:
            return 'unknown', []
        attached.update(arns)
    index = {c.get('arn'): c for c in certs.values()
             if isinstance(c, dict) and isinstance(c.get('arn'), str)}
    if not attached.issubset(index):
        # IAM TLS certificates, partial ACM collection or a denied ACM API.
        return 'unknown', []
    missing = []
    for host in route53_hosts:
        covered = False
        for arn in attached:
            cert = index[arn]
            names = cert.get('SubjectAlternativeNames')
            if not isinstance(names, list):
                return 'unknown', []
            if any(_san_covers(pattern, host) for pattern in names):
                covered = True
                break
        if not covered:
            missing.append(host)
    return ('mismatch' if missing else 'covered'), missing


def _port_covers(rule, port):
    try:
        if '-' in str(rule):
            lo, hi = map(int, str(rule).split('-', 1))
        else:
            lo = hi = int(rule)
        return lo <= int(port) <= hi
    except (ValueError, TypeError, OverflowError):
        return False


def _eni_public_families(eni):
    families = set()
    if not isinstance(eni, dict):
        return None
    association = eni.get('Association')
    if isinstance(association, dict) and association.get('PublicIp'):
        families.add(4)
    ipv6 = eni.get('Ipv6Addresses', [])
    if not isinstance(ipv6, list):
        return None
    for item in ipv6:
        if not isinstance(item, dict):
            return None
        value = item.get('Ipv6Address')
        if not value:
            continue
        try:
            if ip_address(value).is_global:
                families.add(6)
        except (ValueError, TypeError):
            return None
    return families


def _instance_target_exposure(instance, groups, port):
    if not isinstance(instance, dict) or not isinstance(groups, dict):
        return 'unknown', None
    state = instance.get('State')
    if not isinstance(state, dict):
        return 'unknown', None
    if state.get('Name') != 'running':
        return 'not_applicable' if state.get('Name') in (
            'stopped', 'stopping', 'shutting-down', 'terminated') else 'unknown', None
    interfaces = instance.get('network_interfaces')
    if not isinstance(interfaces, dict) or not interfaces:
        return 'unknown', None
    unknown = False
    for eni in interfaces.values():
        families = _eni_public_families(eni)
        if families is None:
            unknown = True
            continue
        if not families:
            continue
        references = eni.get('Groups')
        if not isinstance(references, list) or not references:
            unknown = True
            continue
        for ref in references:
            sg_id = ref.get('GroupId') if isinstance(ref, dict) else None
            sg = groups.get(sg_id)
            if not isinstance(sg, dict):
                unknown = True
                continue
            protocols = ((sg.get('rules') or {}).get('ingress') or {}).get('protocols')
            if not isinstance(protocols, dict):
                unknown = True
                continue
            for kind in ('TCP', 'ALL'):
                ports = (protocols.get(kind) or {}).get('ports') or {}
                if not isinstance(ports, dict):
                    unknown = True
                    continue
                for rule, detail in ports.items():
                    if not _port_covers(rule, port):
                        continue
                    if not isinstance(detail, dict):
                        unknown = True
                        continue
                    cidrs = detail.get('cidrs', [])
                    if not isinstance(cidrs, list):
                        unknown = True
                        continue
                    for cidr in cidrs:
                        value = cidr.get('CIDR') if isinstance(cidr, dict) else None
                        if value == '0.0.0.0/0' and 4 in families or value == '::/0' and 6 in families:
                            return 'exposed', sg_id
    return ('unknown' if unknown else 'not_detected'), None


def _backend_bypass(lb, ec2_vpc):
    if lb.get('Type') != 'application' or lb.get('Scheme') != 'internet-facing':
        return 'not_applicable', []
    if lb.get('waf_protection_status') not in ('aws_waf', 'external_waf_likely'):
        return ('unknown' if lb.get('waf_protection_status') == 'unknown'
                else 'not_applicable'), []
    if lb.get('target_group_inventory_status') != 'complete' or not isinstance(ec2_vpc, dict):
        return 'unknown', []
    groups = lb.get('target_groups')
    if not isinstance(groups, list):
        return 'unknown', []
    instances, sgs = ec2_vpc.get('instances'), ec2_vpc.get('security_groups')
    if not isinstance(instances, dict) or not isinstance(sgs, dict):
        return 'unknown', []
    observations, unknown, inspected = [], False, 0
    for tg in groups:
        if not isinstance(tg, dict):
            unknown = True
            continue
        targets = tg.get('registered_targets')
        if not isinstance(targets, list):
            unknown = True
            continue
        if not targets:
            continue
        if tg.get('target_type') != 'instance':
            unknown = True
            continue
        for target in targets:
            if not isinstance(target, dict):
                unknown = True
                continue
            if target.get('health_state') == 'unused':
                continue
            ident = target.get('id')
            port = target.get('port') or tg.get('port')
            if not isinstance(ident, str) or not ident or type(port) is not int:
                unknown = True
                continue
            inspected += 1
            state, sg_id = _instance_target_exposure(instances.get(ident), sgs, port)
            if state == 'exposed':
                observations.append({'instance_id': ident, 'target_group_arn': tg.get('arn'),
                                     'target_port': port, 'security_group_id': sg_id,
                                     'target_health': target.get('health_state')})
            elif state == 'unknown':
                unknown = True
    if observations:
        return 'potential_bypass', observations[:50]
    if unknown:
        return 'unknown', []
    return ('no_direct_backend_path' if inspected else 'not_applicable'), []


def correlate_p3b(services, selected):
    """Run only after AWS service collectors and WAF preprocessing are finalized."""
    elbv2 = (services.get('elbv2') or {}).get('regions') or {}
    if not isinstance(elbv2, dict):
        return
    ec2 = ((services.get('ec2') or {}).get('regions') or {}) if 'ec2' in selected else {}
    acm = ((services.get('acm') or {}).get('regions') or {}) if 'acm' in selected else {}
    has_route53 = 'route53' in selected
    for region_name, region in elbv2.items():
        for vpc_id, vpc in (region.get('vpcs') or {}).items():
            ec2_vpc = ((ec2.get(region_name) or {}).get('vpcs') or {}).get(vpc_id)
            for lb in (vpc.get('lbs') or {}).values():
                status, matches = _backend_bypass(lb, ec2_vpc)
                lb['backend_bypass_status'] = status
                lb['backend_bypass_evidence'] = matches
                hostname_sources = _route53_alias_hosts(
                    services, _dns(lb.get('DNSName'))) if has_route53 else []
                result, missing = _certificate_host_coverage(
                    lb, acm.get(region_name), hostname_sources)
                lb['https_hostname_coverage_status'] = result
                lb['https_hostnames_checked'] = hostname_sources
                lb['https_hostname_mismatches'] = missing
