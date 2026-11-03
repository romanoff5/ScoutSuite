"""RC9: classify internet-facing ALB protection from AWS WAF association and origin exposure.

waf_protection_status:
  aws_waf              an AWS WAF web ACL is associated (GetWebACLForResource)
  external_waf_likely  no AWS WAF; listener ports only accept CloudFront's origin-facing
                       prefix list or catalogued CDN/WAF proxy ranges
  restricted_origin    no AWS WAF; listener ports are not open to 0.0.0.0/0 or ::/0
  open_without_waf     no AWS WAF and a listener port is open to the whole internet, so
                       any external WAF can be bypassed by connecting to the ALB directly
  not_internet_facing  internal scheme
  not_applicable       not an Application Load Balancer, or no listeners
  unknown              WAF lookup or security-group evidence unavailable
"""
import ipaddress

from .cdn_ranges import active_catalog

WORLD = ('0.0.0.0/0', '::/0')


def cdn_catalog():
    """(catalog_version, ((provider, network), ...), {prefix_list_name: provider}) for this run."""
    catalog = active_catalog()
    return catalog['version'], catalog['ranges'], catalog['prefix_names']


def _cdn_provider_for(cidr):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None
    for name, known in cdn_catalog()[1]:
        if network.version == known.version and network.subnet_of(known):
            return name
    return None


def _covers(port_value, ports):
    if port_value in ('N/A', None):
        return False
    try:
        if '-' in str(port_value):
            low, high = (int(part) for part in str(port_value).split('-', 1))
        else:
            low = high = int(port_value)
    except ValueError:
        return False
    return any(low <= port <= high for port in ports)


def origin_exposure(lb, ports):
    """Return (exposure, sources) for TCP/ALL ingress that reaches a listener port."""
    groups = lb.get('security_groups')
    if not isinstance(groups, list) or not groups:
        return 'unknown', []  # ALBs always have security groups; none observed is missing evidence.
    prefix_names = lb.get('cdn_prefix_lists')
    catalog_prefixes = cdn_catalog()[2]
    sources, world, cdn, other = [], False, set(), False
    for group in groups:
        rules = group.get('rules', {}).get('ingress', {}).get('protocols') if isinstance(group, dict) else None
        if not isinstance(rules, dict):
            return 'unknown', []  # Security group not resolved from EC2 inventory.
        for protocol in ('TCP', 'ALL'):
            for port_value, grants in (rules.get(protocol, {}).get('ports') or {}).items():
                if not _covers(port_value, ports) or not isinstance(grants, dict):
                    continue
                for grant in grants.get('cidrs', []):
                    cidr = grant.get('CIDR')
                    provider = _cdn_provider_for(cidr)
                    sources.append({'group_id': group.get('id'), 'ports': port_value, 'source': cidr,
                                    'cdn_provider': provider})
                    if cidr in WORLD:
                        world = True
                    elif provider:
                        cdn.add(provider)
                    else:
                        other = True
                for grant in grants.get('prefix_lists', []):
                    prefix_id = grant.get('PrefixListId')
                    if prefix_names is None:
                        return 'unknown', []  # Prefix list names could not be resolved.
                    provider = catalog_prefixes.get(prefix_names.get(prefix_id))
                    sources.append({'group_id': group.get('id'), 'ports': port_value, 'source': prefix_id,
                                    'cdn_provider': provider})
                    if provider:
                        cdn.add(provider)
                    else:
                        other = True
                for grant in grants.get('security_groups', []):
                    sources.append({'group_id': group.get('id'), 'ports': port_value,
                                    'source': grant.get('GroupId'), 'cdn_provider': None})
                    other = True
    if world:
        return 'open_to_internet', sources
    if cdn and not other:
        return 'cdn_restricted', sources
    return ('restricted_sources' if sources else 'no_ingress'), sources


def classify_load_balancer(lb):
    """Set additive WAF/origin fields on an ELBv2 load balancer dict."""
    summary = active_catalog()['summary']
    lb['cdn_catalog_version'] = summary['catalog_version']
    lb['cdn_catalog_sources'] = {name: row['source'] for name, row in summary['providers'].items()}
    lb['origin_sources'] = []
    lb['origin_cdn_providers'] = []
    if lb.get('Type') != 'application':
        lb['origin_exposure'] = lb['waf_protection_status'] = 'not_applicable'
        return lb
    if lb.get('Scheme') != 'internet-facing':
        lb['origin_exposure'] = 'not_internet_facing'
        lb['waf_protection_status'] = 'not_internet_facing'
        return lb
    ports = []
    for key in (lb.get('listeners') or {}):
        try:
            ports.append(int(key))
        except (TypeError, ValueError):
            pass
    if not ports:
        lb['origin_exposure'] = lb['waf_protection_status'] = 'not_applicable'
        return lb
    exposure, sources = origin_exposure(lb, ports)
    lb['origin_exposure'], lb['origin_sources'] = exposure, sources
    lb['origin_cdn_providers'] = sorted({row['cdn_provider'] for row in sources if row['cdn_provider']})
    waf = lb.get('waf_web_acl_status')
    if waf == 'associated':
        status = 'aws_waf'
    elif waf != 'none' or exposure == 'unknown':
        status = 'unknown'
    elif exposure == 'open_to_internet':
        status = 'open_without_waf'
    elif exposure == 'cdn_restricted':
        status = 'external_waf_likely'
    else:
        status = 'restricted_origin'
    lb['waf_protection_status'] = status
    return lb
