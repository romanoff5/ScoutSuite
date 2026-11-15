"""Phase 2: real AWS P5 facts -> IAM graph -> rule engine -> evidence ->
SQLite RESULTS -> loopback HTTP -> HTML/Playwright report.

Run OUTSIDE socket-blocked pytest, in the existing loopback-only sqlite_http
CI namespace. No AWS credentials, external network or real account artifacts.
The checked-in 33 independently pinned Phase-1 cases remain the source oracle.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
from threading import Thread
from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener
from wsgiref.simple_server import make_server, WSGIRequestHandler

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import cherrypy
from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.output.html import ScoutReport
from ScoutSuite.output.result_encoder import SqlLiteEncoder, prepare_results
from ScoutSuite.output.utils import get_filename
from ScoutSuite.core.server import Server, MAX_RESPONSE_BYTES
from ScoutSuite.providers.aws.provider import AWSProvider
from ScoutSuite.providers.aws.resources.iam.relationship_graph import build_relationship_graph
from ScoutSuite.providers.aws.resources.iam.attack_paths_p5d import annotate_p5d_attack_paths
from tests.test_p5_phase1_synthetic_aws import CASES, CATALOG, _p5_fixture

RULES = (
    'iam-p5d-user-workload-delegation.json',
    'iam-p5d-role-workload-delegation.json',
    'iam-p5d-eks-role-identity.json',
    'eks-p5d-workload-identity.json',
    's3-p5d-cross-account-bucket.json',
    's3-p5d-cross-account-access-point.json',
    'kms-p5d-cross-account-key.json',
    'awslambda-p5d-external-privileged-invoke-review.json',
)
EDGE_RULES = {
    'iam_lambda_create': ('iam-p5d-role-workload-delegation.json', 'source'),
    'iam_lambda_update': ('iam-p5d-role-workload-delegation.json', 'source'),
    'iam_ec2_create': ('iam-p5d-role-workload-delegation.json', 'source'),
    'iam_ecs_run_task': ('iam-p5d-role-workload-delegation.json', 'source'),
    'iam_ecs_register_run': ('iam-p5d-role-workload-delegation.json', 'source'),
    'eks_irsa_role': ('eks-p5d-workload-identity.json', 'source'),
    'eks_pod_identity': ('eks-p5d-workload-identity.json', 'pod_source'),
    's3_cross_account_resource_policy': ('s3-p5d-cross-account-bucket.json', 'target'),
    's3_access_point_cross_account': ('s3-p5d-cross-account-access-point.json', 'target'),
    'kms_cross_account_key_policy': ('kms-p5d-cross-account-key.json', 'target'),
    'kms_cross_account_grant': ('kms-p5d-cross-account-key.json', 'target'),
    'lambda_external_invoke_review': (
        'awslambda-p5d-external-privileged-invoke-review.json', 'target'),
}
ROLE_RULE = 'iam-p5d-eks-role-identity.json'
# ECS execution-role access is intentionally REVIEW-only graph evidence, not
# a container privilege-escalation finding.
GRAPH_ONLY_REVIEW = 'iam_ecs_execution_role_review'


class QuietHandler(WSGIRequestHandler):
    def log_message(self, *args):
        pass


def _ruleset():
    """Use the real default ruleset, Rule objects and JSON definitions."""
    rules = Ruleset('aws')
    for name in RULES:
        assert name in rules.rules, 'Default AWS ruleset missing P5-D: ' + name
        assert len(rules.rules[name]) == 1 and rules.rules[name][0].enabled
        assert rules.rules[name][0].level == 'review', name
        assert rules.rules[name][0].evidence_policy.startswith('p5d-')
    rules.rules = {name: rules.rules[name] for name in RULES}
    return rules


def _aws_provider(services):
    selected = sorted(services)
    def fake_config(credentials):
        return SimpleNamespace(credentials=credentials,
                               **{name: {} for name in selected})
    with patch('ScoutSuite.providers.aws.provider.AWSServicesConfig',
               fake_config), patch(
                   'ScoutSuite.providers.aws.provider.get_partition_name',
                   return_value='aws'), patch(
                   'ScoutSuite.providers.aws.provider.get_aws_account_id',
                   return_value=CATALOG['account_id']):
        provider = AWSProvider(credentials=SimpleNamespace(session=object()),
                               services=selected, result_format='sqlite')
    assert set(provider.service_list) == set(selected)
    provider.services = services
    provider.collection_status = {'issues': []}
    return provider


def _path_for_arn(services, arn, rule):
    if rule in ('iam-p5d-role-workload-delegation.json', ROLE_RULE):
        for name, role in services['iam'].get('roles', {}).items():
            if role.get('arn') == arn:
                return 'iam.roles.' + name
    elif rule == 'iam-p5d-user-workload-delegation.json':
        for name, user in services['iam'].get('users', {}).items():
            if user.get('arn') == arn:
                return 'iam.users.' + name
    elif rule == 's3-p5d-cross-account-bucket.json':
        for name, bucket in services['s3'].get('buckets', {}).items():
            name_match = arn == 'arn:' + arn.split(':')[1] + ':s3:::' + bucket.get('name', '')
            if name_match:
                return 's3.buckets.' + name
    elif rule == 's3-p5d-cross-account-access-point.json':
        for region, inventory in services['s3']['advanced']['regions'].items():
            for name, point in inventory.get('access_points', {}).items():
                if point.get('AccessPointArn') == arn:
                    return 's3.advanced.regions.' + region + '.access_points.' + name
    elif rule == 'kms-p5d-cross-account-key.json':
        for region, inventory in services['kms']['regions'].items():
            for name, key in inventory.get('keys', {}).items():
                if key.get('arn') == arn:
                    return 'kms.regions.' + region + '.keys.' + name
    elif rule == 'awslambda-p5d-external-privileged-invoke-review.json':
        for region, inventory in services['awslambda']['regions'].items():
            for name, fn in inventory.get('functions', {}).items():
                if fn.get('arn') == arn:
                    return 'awslambda.regions.' + region + '.functions.' + name
    elif rule == 'eks-p5d-workload-identity.json':
        for region, inventory in services['eks']['regions'].items():
            for name, cluster in inventory.get('clusters', {}).items():
                if cluster.get('cluster_arn') == arn:
                    return 'eks.regions.' + region + '.clusters.' + name
    raise AssertionError('Oracle target absent from collected facts: ' + rule + ' ' + arn)


def _expected_findings(case, services):
    """Derive *pinned* expectations only from Phase-1 oracle edges, not output."""
    expected = {name: set() for name in RULES}
    for edge in case['expected']['edges']:
        kind = edge['type']
        if kind == GRAPH_ONLY_REVIEW:
            continue
        rule, role = EDGE_RULES[kind]
        principal = (edge['source'] if role == 'source' else
                     edge['source'].rsplit('/', 2)[0] if role == 'pod_source'
                     else edge['target'])
        expected[rule].add(_path_for_arn(services, principal, rule))
        if kind in ('eks_irsa_role', 'eks_pod_identity'):
            expected[ROLE_RULE].add(
                _path_for_arn(services, edge['target'], ROLE_RULE))
    return expected


def _assert_assembled(case, provider, graph, expected):
    assert graph['status'] == case['expected']['graph_status'], case['id']
    actual_edges = {
        (edge['type'], edge['source'], edge['target'], edge['verification'])
        for edge in graph['edges'].values()
    }
    pinned_edges = {
        (e['type'], e['source'], e['target'], e['verification'])
        for e in case['expected']['edges']
    }
    assert actual_edges == pinned_edges, (case['id'], actual_edges, pinned_edges)
    for rule_name in RULES:
        service = rule_name.split('-')[0]
        if service == 'lambda':
            service = 'awslambda'
        if service not in provider.services:
            continue
        key = rule_name[:-5]
        finding = provider.services[service]['findings'][key]
        expected_paths = expected[rule_name]
        assert finding['flagged_items'] == len(expected_paths), (
            case['id'], rule_name, expected_paths, finding['items'])
        assert finding['checked_items'] >= finding['flagged_items']
        for path in expected_paths:
            assert any(item.startswith(path + '.') or item == path
                       for item in finding['items']), (case['id'], rule_name, path)
        summary = finding['evaluation_summary']
        assert summary['policy'].startswith('p5d-')
        assert summary['counts']['insecure'] == len(expected_paths), (
            case['id'], rule_name, summary['counts'])
        confidence = finding['confidence_assessment']
        assert confidence['effective_permission_verified'] is False
        assert confidence['compliance_verified'] is False
        assert confidence['confidence'] not in ('HIGH',), (case['id'], key, confidence)
        if expected_paths:
            verification = ('REVIEW' if service == 'awslambda' else 'POTENTIAL')
            assert confidence['claim_type'] == (
                'RESOURCE_POLICY_REVIEW' if service == 'awslambda'
                else 'POTENTIAL_ATTACK_PATH')
            assert confidence['verification_status'] == verification
            cards = finding['finding_cards']
            # P5-B2 also creates UNKNOWN cards for uninvolved roles. Those
            # are valuable, but are not flagged candidate findings.
            flagged_cards = [card for card in cards if card['outcome'] == 'insecure']
            assert len(flagged_cards) == len(expected_paths), (
                case['id'], key, cards)
            for card in flagged_cards:
                assert card['verification_status'] == verification
                assert card['confidence'] in ('LOW', 'MEDIUM')
                assert card['collection'] in ('COMPLETE', 'PARTIAL')
                assert any(check['label'] == 'Cross-service graph witness'
                           and check['state'] == 'CONFIRMED'
                           for check in card['supporting_evidence'])
                assert any(check['state'] == 'NOT_VERIFIED'
                           for check in card['supporting_evidence'])
        else:
            assert finding['finding_cards'] == [] or all(
                card['outcome'] == 'unknown' for card in finding['finding_cards'])
            # UNKNOWN facts never become a verified clean PASS.
            if summary['counts']['unknown'] or graph['status'] == 'partial':
                assert confidence['verification_status'] not in (
                    'NO_MATCH_OBSERVED', 'CONFIRMED_CONFIGURATION'), (
                        case['id'], key, confidence)
    assert not any('BEGIN PRIVATE KEY' in str(v) for v in provider.services.values())


def _processed_case(case, ruleset):
    services = _p5_fixture(case)
    iam = services['iam']
    role_graph = build_relationship_graph(
        iam.get('roles', {}), iam.get('policies', {}))
    iam['relationship_graph'] = role_graph
    for role in iam.get('roles', {}).values():
        if role.get('name') == 'Priv':
            assert role['p4b_admin_policy_status'] == 'admin_policy_candidate', (
                case['id'], role['p4b_admin_policy_status'])
    graph = annotate_p5d_attack_paths(services, sorted(services), CATALOG['account_id'])
    expected = _expected_findings(case, services)
    provider = _aws_provider(services)
    ProcessingEngine(ruleset).run(provider)
    _assert_assembled(case, provider, graph, expected)
    provider.postprocessing(datetime(2026, 11, 15, tzinfo=timezone.utc),
                            ruleset, {'services': provider.service_list,
                                      'offline_synthetic_fixture': case['id']})
    return provider, graph, expected


def _write_case(provider, root, report_name):
    SqlLiteEncoder(report_name=report_name, report_dir=str(root)).save_to_file(
        provider, 'RESULTS', True, False)
    filename, _ = get_filename('RESULTS', report_name, str(root),
                               file_extension='db')
    assert Path(filename).is_file(), filename
    return Path(filename)


def _request(opener, base, route, query=None, expected_status=200,
             headers=None):
    url = base + route
    if query:
        url += '?' + urlencode(query)
    req = Request(url, headers=headers or {})
    try:
        with opener.open(req, timeout=15) as response:
            status = response.status
            body = response.read(MAX_RESPONSE_BYTES + 4096)
    except HTTPError as error:
        status = error.code
        body = error.read(4096)
    assert status == expected_status, (route, status, body[:250])
    if status != 200:
        return None
    assert len(body) <= MAX_RESPONSE_BYTES + 4096
    return json.loads(body)['data']


def _browser_check(url, expected_arn, profile):
    """Real browser retrieves report/JS/SQLite endpoints through loopback."""
    from playwright.sync_api import sync_playwright
    from tools.verify_report_e2e import _launch
    problems, external, errors = [], [], []
    with sync_playwright() as play:
        context = _launch(play, profile)
        def guard(route):
            if route.request.url.startswith(url.split('/api/')[0] + '/api/'):
                route.continue_()
            else:
                external.append(route.request.url)
                route.abort()
        context.route('**/*', guard)
        page = context.new_page()
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.on('console', lambda m: m.type == 'error' and errors.append(m.text))
        try:
            page.goto(url, wait_until='domcontentloaded')
            page.wait_for_selector('#last_run .service-status', timeout=20000)
            page.goto(url + '#services.iam.findings')
            selector = '#list-iam-p5d-role-workload-delegation'
            page.locator(selector + ' .finding-badge').wait_for(timeout=10000)
            page.locator(selector + ' button.finding').click()
            card = page.locator(selector + ' .scout-evidence-card').first
            card.wait_for(state='visible', timeout=10000)
            body = card.inner_text()
            if ('Confidence:' not in body or 'Supporting evidence' not in body
                    or expected_arn not in body):
                problems.append('P5-B2 evidence missing or ARN lost: ' + body[:500])
            if page.locator('img[src="x"]').count():
                problems.append('Unexpected unescaped HTML from P5 fixture')
            if page.evaluate('window.__scoutXss') is not None:
                problems.append('Synthetic evidence executed script')
        finally:
            context.close()
    assert not (problems or external or errors), (problems, external, errors)


def run():
    assert len(CASES) == 33
    ruleset = _ruleset()
    cases = {}
    with tempfile.TemporaryDirectory(prefix='scoutsuite-p5-pipeline-') as folder:
        root = Path(folder)
        for case in CASES:
            provider, graph, expected = _processed_case(case, ruleset)
            db = _write_case(provider, root, 'p5_' + case['id'])
            cases[case['id']] = {'db': db, 'provider': provider,
                                 'graph': graph, 'expected': expected}
        reference = 'iam-lambda-passrole-allow'
        displayed = cases[reference]['provider']
        report = ScoutReport('aws', report_name='p5_phase2',
                             report_dir=str(root), result_format='sqlite')
        html = Path(report.save(displayed, {}, force_write=True))
        assert html.is_file()
        source = html.read_text(encoding='utf-8')
        assert 'p5d.attack_paths.partial' in source
        assert 'sqlite.js' in source
        assert '{{{basis}}}' not in source
        report_db, _ = get_filename('RESULTS', 'p5_phase2', str(root),
                                    file_extension='db')
        mounted = []
        tree = cherrypy._cptree.Tree()
        for case_id, item in cases.items():
            api = Server(str(item['db']))
            tree.mount(api, '/api/cases/' + case_id)
            mounted.append(api)
        browser_api = Server(report_db)
        tree.mount(browser_api, '/api')
        mounted.append(browser_api)
        opener = build_opener(ProxyHandler({}))
        with make_server('127.0.0.1', 0, tree,
                         handler_class=QuietHandler) as server:
            port = server.server_port
            cherrypy.server.socket_port = port
            base = 'http://127.0.0.1:%d/api/' % port
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for case in CASES:
                    item = cases[case['id']]
                    url = base + 'cases/' + case['id'] + '/'
                    summary = _request(opener, url, 'summary')
                    assert 'iam' in summary['services']
                    restored_graph = _request(
                        opener, url, 'full',
                        {'key': 'services¤iam¤attack_paths_p5d'})
                    assert restored_graph == prepare_results(
                        item['provider'])['services']['iam']['attack_paths_p5d']
                    assert restored_graph['edges_count'] == len(
                        case['expected']['edges'])
                    for rule_name, paths in item['expected'].items():
                        service = rule_name.split('-')[0]
                        if service == 'lambda':
                            service = 'awslambda'
                        if service not in item['provider'].services:
                            continue
                        key = rule_name[:-5]
                        finding = _request(opener, url, 'full', {
                            'key': 'services¤' + service + '¤findings¤' + key})
                        assert finding['flagged_items'] == len(paths)
                        assert finding['evaluation_summary']['counts']['insecure'] == len(paths)
                        assert finding['confidence_assessment'] == (
                            prepare_results(item['provider'])['services'][service]
                            ['findings'][key]['confidence_assessment'])
                        assert sum(c['outcome'] == 'insecure'
                                   for c in finding['finding_cards']) == len(paths)
                    roles = _request(opener, url, 'page', {
                        'key': 'services¤iam¤roles', 'page': 0, 'pagesize': 100})
                    assert isinstance(roles, dict)
                reference_url = base + 'p5_phase2.html'
                with opener.open(reference_url, timeout=15) as answer:
                    assert answer.status == 200
                    assert b'P5-D2' in answer.read()
                _request(opener, base, 'summary', headers={
                    'Origin': 'https://unauthorized.example'}, expected_status=403)
                _browser_check(reference_url,
                               'arn:aws:iam::123456789012:role/Priv',
                               root / 'browser-profile')
            finally:
                server.shutdown()
                thread.join(timeout=10)
                for api in mounted:
                    api.results.close()
                assert not thread.is_alive()
    print('P5 full pipeline: PASS (33 pinned cases; IAM graph -> real rule '
          'engine -> B/B2 evidence -> SQLite -> HTTP -> live HTML browser)',
          flush=True)


if __name__ == '__main__':
    run()
