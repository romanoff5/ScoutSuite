"""CDN/WAF origin range catalog with a best-effort start-of-run refresh (RC9).

The bundled catalog is always available. refresh_cdn_catalog() fetches each
provider's official list (HTTPS GET only, bounded time and size, every entry
validated as a CIDR no broader than the catalog limits). Any failure keeps that
provider's bundled ranges and prints a warning; the scan is never stopped. The
refreshed catalog is held on the current RunContext, not in process state.
"""
import ipaddress
import json
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from ScoutSuite.core.console import print_info, print_warning
from ScoutSuite.core.run_context import get_current_run_context

CATALOG = Path(__file__).resolve().parents[2] / 'rules/catalogs/cdn-origin-ranges-2026-11.json'


@lru_cache(maxsize=1)
def bundled_document():
    return json.loads(CATALOG.read_text(encoding='utf-8'))


def build_catalog(document, cidrs, status):
    ranges = tuple((name, ipaddress.ip_network(cidr)) for name, values in cidrs.items() for cidr in values)
    prefix_names = {prefix: name for name, prefixes in document['managed_prefix_lists'].items() for prefix in prefixes}
    return {'version': document['catalog_version'], 'ranges': ranges, 'prefix_names': prefix_names,
            'summary': {'catalog_version': document['catalog_version'], 'review_date': document['review_date'],
                        'providers': status}}


@lru_cache(maxsize=1)
def bundled_catalog():
    document = bundled_document()
    status = {name: {'source': 'unavailable' if provider.get('live_only') else 'bundled',
                     'reason': 'not_refreshed', 'count': len(provider['cidrs'])}
              for name, provider in document['providers'].items()}
    return build_catalog(document, {name: p['cidrs'] for name, p in document['providers'].items()}, status)


def active_catalog():
    context = get_current_run_context()
    catalog = getattr(context, 'cdn_catalog', None) if context is not None else None
    return catalog or bundled_catalog()


def https_get(url, timeout, max_bytes):
    if not url.startswith('https://'):
        raise ValueError('Only HTTPS catalog sources are allowed')
    request = urllib.request.Request(url, headers={'User-Agent': 'ScoutSuite-cdn-range-refresh'})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec: fixed HTTPS catalog URLs
        payload = response.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise ValueError('Catalog source exceeds the size limit')
    return payload


def parse_source(source, payload):
    text = payload.decode('utf-8')
    if source['format'] == 'lines':
        return [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith('#')]
    document = json.loads(text)
    entries = []
    for key in source['keys']:
        values = document.get(key) if isinstance(document, dict) else None
        if not isinstance(values, list):
            raise ValueError('Missing key %s' % key)
        entries.extend(values)
    return entries


def validate_entries(entries, limits):
    if not entries or len(entries) > limits['max_entries']:
        raise ValueError('Unexpected number of entries')
    networks = []
    for entry in entries:
        if not isinstance(entry, str):
            raise ValueError('Non-string entry')
        network = ipaddress.ip_network(entry.strip(), strict=False)
        minimum = limits['min_ipv4_prefix'] if network.version == 4 else limits['min_ipv6_prefix']
        if network.prefixlen < minimum:
            raise ValueError('Implausibly broad range %s' % network)
        if str(network) not in networks:
            networks.append(str(network))
    return networks


def _refresh_provider(name, provider, limits, fetch):
    entries = []
    for source in provider['sources']:
        entries.extend(parse_source(source, fetch(source['url'], limits['timeout_seconds'], limits['max_bytes'])))
    return validate_entries(entries, limits)


def refresh_cdn_catalog(fetch=https_get, now=None):
    """Return a catalog of live ranges where available and bundled ranges otherwise; never raises."""
    document = bundled_document()
    limits = document['limits']
    fetched_at = (now or datetime.now(timezone.utc)).isoformat()
    providers = document['providers']
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix='cdn-ranges') as pool:
        futures = {name: pool.submit(_refresh_provider, name, provider, limits, fetch)
                   for name, provider in providers.items()}
    cidrs, status = {}, {}
    for name, provider in providers.items():
        try:
            cidrs[name] = futures[name].result()
            status[name] = {'source': 'live', 'fetched_at': fetched_at, 'count': len(cidrs[name])}
        except Exception as error:
            cidrs[name] = list(provider['cidrs'])
            live_only = provider.get('live_only', False)
            status[name] = {'source': 'unavailable' if live_only else 'bundled',
                            'reason': type(error).__name__, 'count': len(cidrs[name])}
            fallback = ('it will not be recognised in this run' if live_only else
                        'using the bundled list reviewed on ' + document['review_date'])
            print_warning('CDN range update for %s failed (%s: %s); %s' % (
                name, type(error).__name__, str(error)[:160], fallback))
    live = sorted(name for name, row in status.items() if row['source'] == 'live')
    print_info('CDN/WAF origin ranges: live for %s' % (', '.join(live) if live else 'none'))
    return build_catalog(document, cidrs, status)


def disabled_catalog():
    """Bundled catalog explicitly marked as not refreshed by request."""
    catalog = dict(bundled_catalog())
    catalog['summary'] = dict(catalog['summary'], providers={
        name: dict(row, reason='update_disabled') for name, row in catalog['summary']['providers'].items()})
    return catalog
