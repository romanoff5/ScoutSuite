"""End-to-end report checks in a real browser (Playwright), offline and synthetic.

Builds an AWS report through the production path (AWSProvider -> rule engine ->
postprocessing -> ScoutReport) from synthetic services, opens it from file://,
and drives the UI the way a reviewer does. Any non-file request is aborted and
fails the gate, as does any page error or console error.

Executed as its own CI gate (outside guarded pytest, which forbids
subprocesses) under OS network isolation. Uses an installed Chrome/Edge or a
Chromium on PATH; it never downloads a browser. No credentials, cloud APIs or
customer data.
"""
import asyncio
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))  # Exercise this checkout, not an older installed wheel.

from ScoutSuite.core.processingengine import ProcessingEngine  # noqa: E402
from ScoutSuite.core.ruleset import Ruleset  # noqa: E402
from ScoutSuite.core.run_context import RunContext  # noqa: E402
from ScoutSuite.output.html import ScoutReport  # noqa: E402
from ScoutSuite.providers.aws.provider import AWSProvider  # noqa: E402
from ScoutSuite.providers.aws.resources.accessanalyzer.base import AccessAnalyzer  # noqa: E402
from ScoutSuite.providers.aws.resources.guardduty.base import GuardDutyPublic  # noqa: E402

SERVICES = ('guardduty', 'accessanalyzer', 'securityhub', 'eks', 'secretsmanager', 'awslambda', 'elbv2')
HOSTILE = '<img src=x onerror="window.__scoutXss=1">synthetic-role'
EXPECTED_STATUS = {
    'GuardDuty': ('Issues found', 'warning'),
    'Accessanalyzer': ('Incomplete', 'incomplete'),
    'Securityhub': ('Passed', 'good'),
    'EKS': ('Not in use', 'notused'),
    'Secrets Manager': ('Issues found', 'danger'),
    'Lambda': ('Issues found', 'danger'),
    'ELBV2': ('Issues found', 'warning'),
}
PLANTED_SECRET = 'Synthetic-Planted-Value-123'


def _plain(resource):
    return json.loads(json.dumps(resource, default=str))


async def _synthetic_services():
    detectors = {
        'eu-central-1': [],
        'eu-west-1': [{'detector_id': 'synthetic-detector', 'status': 'DISABLED',
                       'service_role': HOSTILE}],
    }
    guardduty = GuardDutyPublic(SimpleNamespace(
        build_region_list=AsyncMock(return_value=list(detectors)),
        guardduty=SimpleNamespace(
            get_detectors=AsyncMock(side_effect=lambda region: detectors[region]),
            detector_census={region: {'complete': True, 'count': len(rows)}
                             for region, rows in detectors.items()})))
    await guardduty.fetch_all(regions=list(detectors))
    analyzer = AccessAnalyzer(SimpleNamespace(
        build_region_list=AsyncMock(return_value=['eu-central-1']),
        accessanalyzer=SimpleNamespace(
            get_analyzers=AsyncMock(return_value=[]),
            analyzer_census={'eu-central-1': {'complete': False, 'count': 0}})))
    await analyzer.fetch_all(regions=['eu-central-1'])
    from datetime import datetime, timedelta, timezone
    from ScoutSuite.providers.aws.resources.awslambda.functions import Functions
    from ScoutSuite.providers.aws.resources.elbv2.dns_front_door import annotate_load_balancers, check_domains
    from ScoutSuite.providers.aws.resources.elbv2.waf_exposure import classify_load_balancer
    from ScoutSuite.providers.aws.resources.secretsmanager.secrets import Secrets
    now = datetime(2026, 11, 2, tzinfo=timezone.utc)
    secret_arn = 'arn:aws:secretsmanager:eu-central-1:000000000000:secret:synthetic-AbCdEf'
    _, secret = Secrets(SimpleNamespace(), 'eu-central-1')._parse_secret({
        'ARN': secret_arn, 'Name': HOSTILE, 'CreatedDate': now - timedelta(days=400),
        'LastAccessedDate': now - timedelta(days=200), '_details_status': 'complete', '_policy_status': 'present',
        'policy': {'Statement': [{'Effect': 'Allow', 'Principal': '*', 'Action': 'secretsmanager:GetSecretValue'}]}},
        now)
    function = {'name': 'synthetic-fn', 'arn': 'arn:aws:lambda:eu-central-1:000000000000:function:synthetic-fn',
                'runtime': 'python3.13', 'package_type': 'Zip', 'runtime_lifecycle_status': 'supported',
                'access_policy': {'Statement': []}, 'execution_role': None}
    Functions._add_env_variables(function, {'Variables': {'DB_PASSWORD': PLANTED_SECRET, HOSTILE: 'x'}})
    world = {'id': 'sg-0synthetic', 'name': 'web', 'rules': {'ingress': {'protocols': {'TCP': {'ports': {
        '443': {'cidrs': [{'CIDR': '0.0.0.0/0'}]}}}}, 'count': 1}, 'egress': {'protocols': {}, 'count': 0}}}
    lb = classify_load_balancer({
        'name': 'web', 'arn': 'arn:aws:elasticloadbalancing:eu-central-1:000000000000:loadbalancer/app/web/1',
        'Type': 'application', 'Scheme': 'internet-facing', 'DNSName': 'web-1.eu-central-1.elb.amazonaws.com',
        'tags': {'Name': HOSTILE}, 'listeners': {443: {'Protocol': 'HTTPS',
                                                       'SslPolicy': 'ELBSecurityPolicy-TLS13-1-2-2021-06'}},
        'listener_protocols': ['HTTPS'], 'security_groups': [world], 'waf_web_acl_status': 'none',
        'waf_web_acl': None, 'cdn_prefix_lists': {}, 'attributes': [
            {'Key': 'access_logs.s3.enabled', 'Value': 'true'},
            {'Key': 'deletion_protection.enabled', 'Value': 'true'},
            {'Key': 'routing.http.drop_invalid_header_fields.enabled', 'Value': 'true'},
            {'Key': 'routing.http.desync_mitigation_mode', 'Value': 'defensive'}]})
    elbv2 = {'regions': {'eu-central-1': {'id': 'eu-central-1', 'name': 'eu-central-1', 'region': 'eu-central-1',
                                          'vpcs': {'vpc-1': {'lbs': {'web': lb}, 'lbs_count': 1}}}},
             'regions_count': 1, 'lbs_count': 1}
    elbv2.update(check_domains({'acm': {'regions': {}}, 'elbv2': elbv2}, ['www.example.com'],
                               resolver=lambda name: ([lb['DNSName']], ['198.51.100.7'])))
    annotate_load_balancers({'elbv2': elbv2})  # Done by AWSProvider.preprocessing in a scan.
    return {
        'secretsmanager': {'regions': {'eu-central-1': {
            'id': 'eu-central-1', 'name': 'eu-central-1', 'region': 'eu-central-1',
            'secrets': {secret['id']: secret}, 'secrets_count': 1}}, 'regions_count': 1, 'secrets_count': 1},
        'awslambda': {'regions': {'eu-central-1': {
            'id': 'eu-central-1', 'name': 'eu-central-1', 'region': 'eu-central-1',
            'functions': {'synthetic-fn': function}, 'functions_count': 1}}, 'regions_count': 1,
            'functions_count': 1},
        'elbv2': _plain(elbv2),
        'guardduty': _plain(guardduty),
        'accessanalyzer': _plain(analyzer),
        'securityhub': {'regions': {'eu-central-1': {
            'id': 'eu-central-1', 'name': 'eu-central-1', 'region': 'eu-central-1',
            'hub_subscription_status': 'enabled', 'hubs': {}, 'hubs_count': 0}},
            'regions_count': 1, 'hubs_count': 0},
        'eks': {'regions': {'eu-central-1': {
            'id': 'eu-central-1', 'name': 'eu-central-1', 'region': 'eu-central-1',
            'clusters': {}, 'clusters_count': 0}}, 'regions_count': 1, 'clusters_count': 0},
    }


def build_report(directory):
    """Render a synthetic report through the same steps as a scan."""
    def fake_config(credentials):
        return SimpleNamespace(credentials=credentials, **{name: {} for name in SERVICES})

    with patch('ScoutSuite.providers.aws.provider.AWSServicesConfig', fake_config), \
            patch('ScoutSuite.providers.aws.provider.get_partition_name', return_value='aws'), \
            patch('ScoutSuite.providers.aws.provider.get_aws_account_id', return_value='000000000000'):
        provider = AWSProvider(credentials=SimpleNamespace(session=object()), services=list(SERVICES))
    context = RunContext('aws').setup()
    try:
        provider.services = asyncio.run(_synthetic_services())
        # The collector would record this for the unreadable analyzer census.
        context.record_collection_issue('denied', 'accessanalyzer', 'AccessDenied')
        ruleset = Ruleset('aws')
        ProcessingEngine(ruleset).run(provider)
        provider.collection_status = context.collection_summary(0)
        provider.postprocessing(context_time(), ruleset, {'services': list(SERVICES)})
        report = ScoutReport('aws', report_name='e2e', report_dir=str(directory), result_format='json')
        return Path(report.save(provider, {}, force_write=True))
    finally:
        context.cleanup()


def context_time():
    import datetime
    return datetime.datetime(2026, 11, 2, tzinfo=datetime.timezone.utc)


def _launch(playwright, profile):
    """Open a browser context on an installed browser; never download one.

    Current Chrome/Edge refuse DevTools automation unless the profile directory
    is explicitly non-default, so every attempt gets its own fresh directory
    under ``profile`` (seen on a Windows CI image). Only start-up is retried.
    """
    import time
    options = {'headless': True, 'accept_downloads': True, 'viewport': {'width': 1400, 'height': 900},
               'args': ['--disable-gpu', '--no-first-run', '--no-default-browser-check']}
    candidates = [{'channel': 'chrome'}, {'channel': 'msedge'}]
    for binary in ('chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable'):
        if shutil.which(binary):
            candidates.append({'executable_path': shutil.which(binary)})
    errors = []
    for attempt in range(3):
        for index, candidate in enumerate(candidates):
            directory = Path(profile) / ('profile-%d-%d' % (attempt, index))
            try:
                return playwright.chromium.launch_persistent_context(str(directory), **candidate, **options)
            except Exception as error:  # Not installed, or start-up refused.
                errors.append('%s attempt %d: %s' % (candidate, attempt + 1, str(error)[:1500]))
        time.sleep(3)
    raise RuntimeError('No usable installed Chrome/Edge/Chromium for report E2E:\n' + '\n'.join(errors))


def run_browser_checks(report, profile):
    from playwright.sync_api import sync_playwright

    problems, external, console = [], [], []
    url = report.resolve().as_uri()
    with sync_playwright() as playwright:
        context = _launch(playwright, profile)

        def guard(route):
            if route.request.url.startswith('file:'):
                route.continue_()
            else:
                external.append(route.request.url)
                route.abort()
        context.route('**/*', guard)
        page = context.new_page()
        page.on('pageerror', lambda error: console.append('pageerror: %s' % error))
        page.on('console', lambda message: message.type == 'error' and console.append(message.text))

        def check(condition, message):
            if not condition:
                problems.append(message)

        page.goto(url)
        page.wait_for_selector('#last_run .service-status')

        # Dark theme is the default, without any stored preference.
        check(page.get_attribute('#scout-theme', 'href').endswith('scoutsuite-dark.css'), 'dark theme not default')
        check(page.is_checked('#theme_checkbox'), 'theme switch does not show dark')

        # Every service row carries an explicit status that matches its evidence.
        rows = page.eval_on_selector_all('#last_run .card', '''els => els.map(e => ({
            text: e.innerText.replace(/\\s+/g, ' ').trim(),
            badge: (e.querySelector('.finding-badge') || {className: ''}).className}))''')
        for title, (label, badge) in EXPECTED_STATUS.items():
            row = next((r for r in rows if r['text'].startswith(title + ' ')), None)
            check(row is not None and label in row['text'], 'status for %s: %r' % (
                title, row or [r['text'][:24] for r in rows]))
            check(row is not None and 'finding-badge-' + badge in row['badge'], 'badge for %s: %r' % (title, row))

        # Settings menu actions survive the sanitizer and work on click.
        gear = 'a.dropdown-toggle:has(i.fa-cog)'
        for item, title in (('Execution Details', 'Execution Details'), ('Resources Details', 'Resources Details'),
                            ('About Scout', 'About Scout')):
            page.click(gear)
            page.click('a.dropdown-item:has-text("%s")' % item)
            dialog = '.modal.show:not(#please-wait-modal)'
            modal = page.wait_for_selector(dialog, state='visible', timeout=5000)
            check(title in modal.inner_text(), '%s modal content' % item)
            page.click(dialog + ' .close')
            page.wait_for_selector(dialog, state='hidden', timeout=5000)
        for item in ('Export Summary', 'Export Exceptions'):
            page.click(gear)
            with page.expect_download(timeout=5000) as download:
                page.click('a.dropdown-item:has-text("%s")' % item)
            check(download.value.suggested_filename, '%s produced no file' % item)

        # Theme switch toggles, persists across reload and switches back.
        page.click(gear)
        page.click('label.switch')
        check(page.get_attribute('#scout-theme', 'href').endswith('scoutsuite-light.css'), 'switch to light failed')
        page.reload()
        page.wait_for_selector('#last_run .service-status')
        check(page.get_attribute('#scout-theme', 'href').endswith('scoutsuite-light.css'), 'light not persisted')
        page.click(gear)
        page.click('label.switch')
        check(page.get_attribute('#scout-theme', 'href').endswith('scoutsuite-dark.css'), 'switch back to dark failed')

        # Region-level finding renders its evidence card.
        page.goto(url + '#services.guardduty.findings.guardduty-not-enabled.items')
        card = page.wait_for_selector('text=GuardDuty status:', timeout=5000)
        check('not_enabled' in card.evaluate('e => e.closest("ul").innerText'), 'GuardDuty region card evidence')

        # Incomplete evidence never renders as a pass and is hidden by the Good filter.
        page.goto(url + '#services.accessanalyzer.findings')
        page.wait_for_selector('#list-accessanalyzer-not-configured .finding-badge', timeout=5000)
        badge = page.get_attribute('#list-accessanalyzer-not-configured .finding-badge', 'class') or ''
        check('finding-badge-incomplete' in badge, 'incomplete finding badge: %r' % badge)
        page.click('#finding-title-good')
        check(not page.is_visible('#list-accessanalyzer-not-configured'), 'Good filter shows incomplete finding')

        # Untrusted resource strings are rendered as text, never as markup.
        page.goto(url + '#services.guardduty.findings.guardduty-detector-disabled.items')
        page.locator('text=synthetic-role >> visible=true').first.wait_for(timeout=5000)
        check(page.evaluate('window.__scoutXss') is None, 'hostile detector field executed')
        check(page.locator('img[src="x"]').count() == 0, 'hostile detector field injected markup')

        # P5-D2: an actual report must register the escaped attack-path modal
        # and show exact resource identifiers without interpreting hostile input.
        rendered = page.evaluate("""(hostile) => {
            const synthetic = {
                name: 'EKS cluster',
                cluster_arn: 'arn:aws:eks:eu-central-1:000000000000:cluster/sample',
                p5d_workload_identity_status: 'candidate',
                pod_identity_inventory_status: 'complete',
                pod_identity_associations_count: 1,
                pod_identity_described_count: 1,
                pod_identity_unresolved_count: 0,
                pod_identity_associations: {'pa-1': {
                    association_arn: 'arn:aws:eks:eu-central-1:000000000000:podidentityassociation/sample/pa-1',
                    namespace: 'team', service_account: 'api',
                    role_arn: 'arn:aws:iam::000000000000:role/Admin',
                    detail_collection_status: 'complete',
                    session_policy_status: 'absent'
                }},
                p5d_attack_path_details: [{
                    id: 'synthetic-edge',
                    type: 'eks_pod_identity', verification: 'POTENTIAL',
                    confidence: 'MEDIUM', source: hostile,
                    target: 'arn:aws:iam::000000000000:role/Admin',
                    action: 'sts:AssumeRole+TagSession',
                    basis: hostile, effective_permission_verified: false,
                    execution_verified: false
                }]
            };
            const template = Handlebars.compile('{{> services.eks.regions.id.clusters}}');
            const modal = document.createElement('div');
            modal.id = 'scout-p5d2-e2e';
            modal.innerHTML = template(synthetic);
            document.body.appendChild(modal);
            return modal.innerText;
        }""", HOSTILE)
        check('eks_pod_identity' in rendered, 'P5-D2 EKS edge type hidden')
        check('sts:AssumeRole+TagSession' in rendered, 'P5-D2 edge action hidden')
        check('arn:aws:iam::000000000000:role/Admin' in rendered,
              'P5-D2 role ARN lost from report')
        check('session policy: absent' in rendered, 'P5-D2 association status missing')
        check('associations retained: 1' in rendered and 'descriptions verified: 1' in rendered,
              'P5-D2 association/Describe coverage labels inaccurate')
        check(page.evaluate('window.__scoutXss') is None, 'P5-D2 hostile ARN or evidence executed')
        check(page.locator('#scout-p5d2-e2e img[src="x"]').count() == 0,
              'P5-D2 hostile data injected HTML')
        page.locator('#scout-p5d2-e2e').evaluate('(el) => el.remove()')

        # RC9 evidence views: masked secrets, Secrets Manager status, ALB WAF and DNS domains.
        page.goto(url + '#services.awslambda.findings.awslambda-function-env-secrets.items')
        page.wait_for_selector('text=Sensitive variable name with literal value', timeout=5000)
        check(PLANTED_SECRET not in page.content(), 'Lambda environment value rendered')
        page.goto(url + '#services.secretsmanager.findings.secretsmanager-secret-policy-public.items')
        card = page.wait_for_selector('text=Exposure:', timeout=5000)
        check('public' in card.evaluate('e => e.closest("div").innerText'), 'secret policy exposure evidence')

        # P5-B2: real escaped per-resource cards are visible after expansion,
        # and a hostile resource name remains literal text (not HTML).
        page.goto(url + '#services.secretsmanager.findings')
        page.wait_for_selector('#list-secretsmanager-secret-policy-public .finding-badge')
        page.click('#list-secretsmanager-secret-policy-public button.finding')
        card = page.locator('#list-secretsmanager-secret-policy-public .scout-evidence-card').first
        card.wait_for(state='visible', timeout=5000)
        check('Confidence:' in card.inner_text(), 'P5-B2 confidence not rendered')
        check('synthetic-role' in card.inner_text(), 'P5-B2 original resource name lost')
        check('Supporting evidence' in card.inner_text(), 'P5-B2 evidence not rendered')
        check(page.locator('img[src="x"]').count() == 0, 'P5-B2 injected hostile markup')
        page.goto(url + '#services.elbv2.findings.elbv2-internet-facing-alb-without-waf.items')
        card = page.wait_for_selector('text=Origin exposure:', timeout=5000)
        check('open_to_internet' in card.evaluate('e => e.closest("ul").innerText'), 'ALB origin exposure evidence')
        check('www.example.com' in card.evaluate('e => e.closest("ul").innerText'), 'ALB DNS domain link')
        page.goto(url + '#services.elbv2.dns_domains')
        page.locator('samp:text-is("direct_to_alb") >> visible=true').first.wait_for(timeout=5000)
        check(page.evaluate('window.__scoutXss') is None, 'hostile RC9 field executed')
        check(page.locator('img[src="x"]').count() == 0, 'hostile RC9 field injected markup')

        # P4-F2 UI: keyless in-memory versions, real identifiers, no JS execution.
        page.goto(url)
        page.wait_for_selector('#scout-history-toggle')
        page.click('#scout-history-toggle')
        check(page.is_visible('#scout-history-panel'), 'P4-F2 scan history panel does not open')
        check('1 versions loaded' in page.locator('#scout-history-summary').inner_text(),
              'Current report not included in history')
        prior = {
            'provider_code': 'aws', 'account_id': '000000000000',
            'report_schema_version': 1, 'collection_status': {'complete': True},
            'services': {'ec2': {
                'regions': {'eu-central-1': {'vpcs': {'vpc-test': {
                    'instances': {'i-history-test': {'imds_v2_status': 'optional'}}}}}},
                'findings': {'ec2-instance-imdsv1-enabled': {
                    'items': ['ec2.regions.eu-central-1.vpcs.vpc-test.instances.i-history-test.imds_v2_status'],
                    'flagged_items': 1, 'assessment_status': 'evaluated'}}}}
        }
        current = json.loads(json.dumps(prior))
        current['services']['ec2']['regions']['eu-central-1']['vpcs']['vpc-test'][
            'instances']['i-history-test']['imds_v2_status'] = 'required'
        current['services']['ec2']['findings']['ec2-instance-imdsv1-enabled'].update(
            items=[], flagged_items=0)
        hostile = '<img src=x onerror="window.__scoutHistoryXss=1">'
        current['services']['ec2']['findings'][hostile] = {
            'items': [hostile], 'flagged_items': 1, 'assessment_status': 'evaluated'}
        import_payload = [
            {'name': 'before.js', 'mimeType': 'text/javascript',
             'buffer': ('scoutsuite_results = ' + json.dumps(prior) + ';').encode('utf-8')},
            {'name': 'after.json', 'mimeType': 'application/json',
             'buffer': json.dumps(current).encode('utf-8')}
        ]
        page.locator('#scout-history-files').set_input_files(import_payload)
        page.wait_for_function("document.getElementById('scout-history-before').options.length === 3")
        page.select_option('#scout-history-before', '1')
        page.select_option('#scout-history-after', '2')
        check('Resolved observed: 1' in page.locator('#scout-history-summary').inner_text(),
              'History did not resolve real resource path across scan versions')
        check('i-history-test' in page.locator('#scout-history-rows').inner_text(),
              'History hid a real resource ID from unredacted reports')
        check(page.locator('#scout-history-semantic tr').count() == 27,
              'P5-C 27-rule semantic preview is not integrated')
        check('iam-p4b2-user-passrole-to-privileged-role' in
              page.locator('#scout-history-semantic').inner_text(),
              'P5-C IAM candidate preview is absent')
        check('s3-bucket-effective-public-exposure' in
              page.locator('#scout-history-semantic').inner_text(),
              'P5-C S3 exposure preview is absent')
        check(page.evaluate('window.__scoutHistoryXss') is None,
              'History imported text executed script')
        check(page.locator('img[src="x"]').count() == 0,
              'History imported text injected active markup')
        signed = {
            'format': 'scoutsuite-semantic-facts', 'schema_version': 1,
            'key_id': 'synthetic-key-id', 'source_collection_status': 'observed_complete',
            'integrity': {'sha256': 'unverified', 'hmac_sha256': 'unverified'},
            'rules': {'ec2-instance-imdsv1-enabled': {
                'scope': 'observed', 'facts': [{'token': 'hmac:' + 'a' * 40,
                                                'value': 'optional'}]}}
        }
        page.locator('#scout-history-files').set_input_files({
            'name': 'previous.p4f2.snapshot.json', 'mimeType': 'application/json',
            'buffer': json.dumps(signed).encode('utf-8')})
        page.wait_for_function("document.getElementById('scout-history-before').options.length === 4")
        page.select_option('#scout-history-after', '3')
        check('NOT authenticated' in page.locator('#scout-history-warning').inner_text(),
              'Signed snapshot preview incorrectly implied HMAC verification')
        page.click('#scout-history-reset')
        check(page.locator('#scout-history-before option').count() == 1,
              'History clearing does not remove imported data')

        context.close()
    check(not external, 'external requests: %s' % external)
    check(not console, 'console/page errors: %s' % console)
    return problems


def main():
    with tempfile.TemporaryDirectory(prefix='scoutsuite-report-e2e-') as directory:
        report = build_report(Path(directory))
        problems = run_browser_checks(report, Path(directory) / 'browser')
        stored = ''.join(path.read_text(encoding='utf-8', errors='replace')
                         for path in Path(directory).rglob('*') if path.is_file() and path.suffix in ('.js', '.json'))
        if PLANTED_SECRET in stored:
            problems.append('planted secret value stored in report data')
    for problem in problems:
        print('E2E FAILED: ' + problem, flush=True)
    if problems:
        raise SystemExit(1)
    print('Report end-to-end browser checks: PASSED', flush=True)


if __name__ == '__main__':
    os.environ.setdefault('PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD', '1')
    # Browser start-up diagnostics (stderr only; no page content or report data).
    os.environ.setdefault('DEBUG', 'pw:browser')
    print('Report E2E interpreter: ' + sys.version.split()[0], flush=True)
    main()
