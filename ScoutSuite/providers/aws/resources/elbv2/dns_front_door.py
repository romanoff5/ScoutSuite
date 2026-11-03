"""RC9 opt-in (--external-waf-dns): what fronts the account's domains in public DNS.

Domains come from ACM certificates (DomainName and SubjectAlternativeNames,
wildcards reduced to their base name) and --waf-domains. Each is resolved with
the system resolver only (no zone transfers, no HTTP probes, no AWS calls) and
classified by CNAME suffix and resolved address against the CDN/WAF catalog.
Every checked domain is reported, including failures.
"""
import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor, wait

from ScoutSuite.providers.utils import get_non_provider_id

from .cdn_ranges import active_catalog, bundled_document

MAX_DOMAINS = 1000
TOTAL_TIMEOUT_SECONDS = 60
HOSTNAME = re.compile(r'^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$')
ELB_SUFFIX = '.elb.amazonaws.com'


def system_resolve(name):
    """Return (cname_chain, addresses) using the operating-system resolver."""
    canonical, aliases, v4 = socket.gethostbyname_ex(name)
    addresses = list(v4)
    try:
        for row in socket.getaddrinfo(name, None, socket.AF_INET6, socket.SOCK_STREAM):
            if row[4][0] not in addresses:
                addresses.append(row[4][0])
    except OSError:
        pass
    chain = [alias.lower().rstrip('.') for alias in aliases if alias.lower().rstrip('.') != name]
    canonical = canonical.lower().rstrip('.')
    if canonical != name and canonical not in chain:
        chain.append(canonical)
    return chain, addresses


def normalize_domain(value):
    if not isinstance(value, str):
        return None
    name = value.strip().lower().rstrip('.')
    if name.startswith('*.'):
        name = name[2:]
    return name if HOSTNAME.match(name) else None


def collect_domains(services, explicit=None):
    """Return {domain: [sources]} from ACM certificates and explicit names."""
    domains = {}

    def add(value, source):
        name = normalize_domain(value)
        if name:
            sources = domains.setdefault(name, [])
            if source not in sources:
                sources.append(source)
    for region, data in ((services.get('acm') or {}).get('regions') or {}).items():
        for certificate in (data.get('certificates') or {}).values():
            add(certificate.get('DomainName'), 'acm:' + region)
            for alternative in certificate.get('SubjectAlternativeNames') or []:
                add(alternative, 'acm:' + region)
    for value in explicit or []:
        add(value, 'cli')
    return domains


def internet_facing_albs(services):
    for region in ((services.get('elbv2') or {}).get('regions') or {}).values():
        for vpc in (region.get('vpcs') or {}).values():
            for lb in (vpc.get('lbs') or {}).values():
                if lb.get('Scheme') == 'internet-facing' and isinstance(lb.get('DNSName'), str):
                    yield lb


def _strip_dualstack(name):
    return name[len('dualstack.'):] if name.startswith('dualstack.') else name


def _provider_by_name(names, suffixes):
    for name in names:
        for provider, endings in suffixes.items():
            if any(name == ending or name.endswith('.' + ending) for ending in endings):
                return provider, 'cname'
    return None, None


def _provider_by_address(addresses, ranges):
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        for provider, network in ranges:
            if ip.version == network.version and ip in network:
                return provider
    return None


def check_domains(services, explicit=None, resolver=system_resolve, timeout=TOTAL_TIMEOUT_SECONDS):
    """Resolve and classify; returns the additive elbv2 fields dns_domains and external_waf_dns."""
    domains = collect_domains(services, explicit)
    names = sorted(domains)
    truncated = len(names) > MAX_DOMAINS
    names = names[:MAX_DOMAINS]
    albs = {_strip_dualstack(lb['DNSName'].lower().rstrip('.')): lb for lb in internet_facing_albs(services)}
    targets = names + [alb for alb in albs if alb not in domains]
    pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix='waf-dns')
    futures = {name: pool.submit(resolver, name) for name in targets}
    wait(list(futures.values()), timeout=timeout)
    pool.shutdown(wait=False, cancel_futures=True)

    def outcome(name):
        future = futures[name]
        if not future.done():
            return 'timeout', [], []
        try:
            chain, addresses = future.result()
        except socket.gaierror:
            return 'unresolved', [], []
        except Exception as error:
            return 'error:' + type(error).__name__, [], []
        return 'resolved', [str(c) for c in chain], [str(a) for a in addresses]

    alb_addresses = {}
    for name in albs:
        status, _, addresses = outcome(name)
        for address in addresses if status == 'resolved' else []:
            alb_addresses[address] = name
    document = bundled_document()
    ranges = active_catalog()['ranges']
    records = {}
    for name in names:
        status, chain, addresses = outcome(name)
        record = {'name': name, 'sources': domains[name], 'resolution_status': status.split(':')[0],
                  'error_type': status.split(':')[1] if ':' in status else None,
                  'cname_chain': chain, 'addresses': addresses, 'front_door_provider': None,
                  'match_method': None, 'alb_dns_name': None, 'alb_name': None}
        if status == 'resolved':
            provider, method = _provider_by_name(chain, document['cname_suffixes'])
            if provider is None:
                provider = _provider_by_address(addresses, ranges)
                method = 'address' if provider else None
            alb = next((_strip_dualstack(c) for c in chain if _strip_dualstack(c) in albs), None)
            if alb is None:
                alb = next((alb_addresses[a] for a in addresses if a in alb_addresses), None)
            elb_other = alb is None and any(c.endswith(ELB_SUFFIX) for c in chain)
            if provider:
                record['classification'] = 'cdn_waf_fronted'
            elif alb or elb_other:
                record['classification'] = 'direct_to_alb'
            else:
                record['classification'] = 'direct_other'
            record['front_door_provider'], record['match_method'] = provider, method
            if alb:
                record['alb_dns_name'], record['alb_name'] = alb, albs[alb].get('name')
        else:
            record['classification'] = 'not_resolved'
        records[get_non_provider_id(name)] = record
    summary = {'enabled': True, 'domains_checked': len(records), 'domains_found': len(domains),
               'truncated': truncated, 'max_domains': MAX_DOMAINS,
               'catalog_version': active_catalog()['summary']['catalog_version'],
               'classification_counts': {}}
    for record in records.values():
        counts = summary['classification_counts']
        counts[record['classification']] = counts.get(record['classification'], 0) + 1
    return {'dns_domains': records, 'dns_domains_count': len(records), 'external_waf_dns': summary}


def disabled_result():
    return {'dns_domains': {}, 'dns_domains_count': 0,
            'external_waf_dns': {'enabled': False, 'reason': 'not_requested (use --external-waf-dns)'}}


def annotate_load_balancers(services):
    """Attach the domains that resolve to each ALB (by CNAME chain or address)."""
    elbv2 = services.get('elbv2') or {}
    records = elbv2.get('dns_domains') or {}
    for lb in internet_facing_albs(services):
        own = _strip_dualstack(lb['DNSName'].lower().rstrip('.'))
        lb['dns_domains'] = [{'name': r['name'], 'classification': r['classification'],
                              'front_door_provider': r['front_door_provider']}
                             for r in records.values() if r.get('alb_dns_name') == own]
