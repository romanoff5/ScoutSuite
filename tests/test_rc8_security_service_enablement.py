"""RC8: an absent detective control is a finding; an unreadable one stays UNKNOWN.

Per-resource rules (guardduty-detector-disabled, accessanalyzer-analyzer-inactive)
evaluate zero objects when nothing exists, so the region-level gap needs its own
rule. Synthetic identifiers only; strict Stubber for the SDK boundary.
"""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import boto3
from botocore.stub import Stubber

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.rule_evidence import classify_accessanalyzer_region, classify_guardduty_region
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.accessanalyzer import AccessAnalyzerFacade
from ScoutSuite.providers.aws.facade.guardduty import GuardDutyPublicFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.accessanalyzer.base import AccessAnalyzer
from ScoutSuite.providers.aws.resources.guardduty.base import GuardDutyPublic

ROOT = Path(__file__).resolve().parents[1]
REGION = 'eu-central-1'
ANALYZER_ARN = 'arn:aws:access-analyzer:eu-central-1:000000000000:analyzer/synthetic'


def sdk(service):
    return boto3.client(service, region_name=REGION, aws_access_key_id='synthetic',
                        aws_secret_access_key='synthetic')


def in_context(scenario):
    async def wrapper():
        ctx = RunContext('aws').setup()
        try:
            return await scenario(), list(ctx.collection_issues)
        finally:
            await ctx.aclose()
    return asyncio.run(wrapper())


def test_guardduty_census_distinguishes_empty_inventory_from_denial():
    def run(add):
        async def scenario():
            client = sdk('guardduty')
            facade = GuardDutyPublicFacade(object())
            try:
                with Stubber(client) as stub:
                    add(stub)
                    with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                        await facade.get_detectors(REGION)
                    stub.assert_no_pending_responses()
            finally:
                client.close()
            return facade.detector_census[REGION]
        return in_context(scenario)

    census, issues = run(lambda s: s.add_response('list_detectors', {'DetectorIds': []}, {'MaxResults': 50}))
    assert census == {'complete': True, 'count': 0} and issues == []
    census, issues = run(lambda s: s.add_client_error(
        'list_detectors', service_error_code='AccessDeniedException', http_status_code=403,
        expected_params={'MaxResults': 50}))
    assert census['complete'] is False and issues[0]['status'] == 'denied'

    def detail_denied(stub):
        stub.add_response('list_detectors', {'DetectorIds': ['d1']}, {'MaxResults': 50})
        stub.add_client_error('get_detector', service_error_code='AccessDeniedException',
                              http_status_code=403, expected_params={'DetectorId': 'd1'})
    census, _ = run(detail_denied)
    assert census == {'complete': False, 'count': 0}


def test_access_analyzer_census_distinguishes_empty_inventory_from_denial():
    def run(add):
        async def scenario():
            client = sdk('accessanalyzer')
            facade = AccessAnalyzerFacade(object())
            try:
                with Stubber(client) as stub:
                    add(stub)
                    with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                        await facade.get_analyzers(REGION)
                    stub.assert_no_pending_responses()
            finally:
                client.close()
            return facade.analyzer_census[REGION]
        return in_context(scenario)

    census, issues = run(lambda s: s.add_response('list_analyzers', {'analyzers': []}, {'maxResults': 100}))
    assert census == {'complete': True, 'count': 0} and issues == []
    census, issues = run(lambda s: s.add_client_error(
        'list_analyzers', service_error_code='AccessDeniedException', http_status_code=403,
        expected_params={'maxResults': 100}))
    assert census['complete'] is False and issues[0]['status'] == 'denied'


def guardduty_region(rows, census):
    async def scenario():
        source = SimpleNamespace(
            build_region_list=AsyncMock(return_value=[REGION]),
            guardduty=SimpleNamespace(get_detectors=AsyncMock(return_value=rows),
                                      detector_census={REGION: census} if census else {}))
        resources = GuardDutyPublic(source)
        await resources.fetch_all(regions=[REGION])
        return resources['regions'][REGION]
    return in_context(scenario)[0]


def test_guardduty_region_states_and_classifier():
    enabled = {'detector_id': 'd1', 'status': 'ENABLED'}
    disabled = {'detector_id': 'd2', 'status': 'DISABLED'}
    cases = [
        ([], {'complete': True, 'count': 0}, 'not_enabled', True, 'insecure'),
        ([enabled], {'complete': True, 'count': 1}, 'enabled', False, 'secure'),
        ([disabled], {'complete': True, 'count': 1}, 'detector_disabled', False, 'secure'),
        ([], {'complete': False, 'count': 0}, 'unknown', False, 'unknown'),
        ([], None, 'unknown', False, 'unknown'),
        # A detector the normaliser rejected means the census is not complete.
        ([{'detector_id': 'd3', 'status': 'BROKEN'}], {'complete': True, 'count': 1}, 'unknown', False, 'unknown'),
    ]
    for rows, census, status, flag, verdict in cases:
        region = guardduty_region(rows, census)
        assert region['guardduty_status'] == status, (rows, census)
        assert region['guardduty_not_enabled'] is flag
        assert classify_guardduty_region(region) == verdict


def analyzer_region(rows, census):
    async def scenario():
        source = SimpleNamespace(
            build_region_list=AsyncMock(return_value=[REGION]),
            accessanalyzer=SimpleNamespace(get_analyzers=AsyncMock(return_value=rows),
                                           analyzer_census={REGION: census} if census else {}))
        resources = AccessAnalyzer(source)
        await resources.fetch_all(regions=[REGION])
        return resources['regions'][REGION]
    return in_context(scenario)[0]


def test_access_analyzer_region_states_and_classifier():
    active = {'arn': ANALYZER_ARN, 'status': 'ACTIVE', 'name': 'synthetic'}
    failed = {'arn': ANALYZER_ARN + '-2', 'status': 'FAILED', 'name': 'synthetic-2'}
    cases = [
        ([], {'complete': True, 'count': 0}, 'not_configured', True, 'insecure'),
        ([active], {'complete': True, 'count': 1}, 'active', False, 'secure'),
        ([failed], {'complete': True, 'count': 1}, 'inactive_only', False, 'secure'),
        ([], {'complete': False, 'count': 0}, 'unknown', False, 'unknown'),
        ([], None, 'unknown', False, 'unknown'),
    ]
    for rows, census, status, flag, verdict in cases:
        region = analyzer_region(rows, census)
        assert region['analyzer_status'] == status, (rows, census)
        assert region['analyzer_not_configured'] is flag
        assert classify_accessanalyzer_region(region) == verdict


def test_region_rules_flag_only_verified_absence(tmp_path):
    selected = {'about': 'Synthetic RC8 rules', 'rules': {
        'guardduty-not-enabled.json': [{'enabled': True, 'level': 'warning'}],
        'accessanalyzer-not-configured.json': [{'enabled': True, 'level': 'warning'}]}}
    rules = tmp_path / 'rules.json'
    rules.write_text(json.dumps(selected), encoding='utf-8')
    gd = {'eu-central-1': guardduty_region([], {'complete': True, 'count': 0}),
          'eu-west-1': guardduty_region([{'detector_id': 'd1', 'status': 'ENABLED'}], {'complete': True, 'count': 1}),
          'eu-north-1': guardduty_region([], {'complete': False, 'count': 0})}
    aa = {'eu-central-1': analyzer_region([], {'complete': True, 'count': 0}),
          'eu-north-1': analyzer_region([], None)}
    for regions in (gd, aa):
        for name, data in regions.items():
            data.update(id=name, name=name, region=name)
    provider = SimpleNamespace(services={'guardduty': {'regions': gd}, 'accessanalyzer': {'regions': aa}},
                               service_list=['guardduty', 'accessanalyzer'])
    context = RunContext('aws').setup()
    try:
        ProcessingEngine(Ruleset('aws', filename=str(rules))).run(provider)
        guardduty = provider.services['guardduty']['findings']['guardduty-not-enabled']
        analyzer = provider.services['accessanalyzer']['findings']['accessanalyzer-not-configured']
    finally:
        context.cleanup()
    assert guardduty['items'] == ['guardduty.regions.eu-central-1.NotEnabled']
    assert guardduty['evaluation_summary']['counts'] == {
        'secure': 1, 'insecure': 1, 'unknown': 1, 'not_applicable': 0}
    assert guardduty['assessment_status'] == 'incomplete'
    assert analyzer['items'] == ['accessanalyzer.regions.eu-central-1.NotConfigured']
    assert analyzer['evaluation_summary']['counts']['unknown'] == 1


def test_every_partial_registration_selects_its_own_template():
    """A single-escaped '\\.' selector silently registers an undefined partial."""
    import re
    pattern = re.compile(r'registerPartial\("([^"]+)",\s*\$\("#([^"]+)"\)\.html\(\)\)')

    def selector_target(text, selector):
        # In the JS string '\\.' becomes '\.', i.e. a literal dot in the id.
        unescaped = selector.replace('\\\\.', '.')
        if '\\' in unescaped:
            return None
        return unescaped if 'id="%s"' % unescaped in text else None

    checked = 0
    for path in (ROOT / 'ScoutSuite/output/data/html/partials').rglob('*.html'):
        text = path.read_text(encoding='utf-8')
        for name, selector in pattern.findall(text):
            assert selector_target(text, selector), (path.name, name, selector)
            checked += 1
    assert checked > 100
    broken = '<script id="services.x.regions.partial"></script>'
    assert selector_target(broken, 'services\\.x\\.regions\\.partial') is None


def test_rules_enabled_by_default_with_escaped_region_templates():
    for ruleset in ('default.json', 'detailed.json'):
        rules = json.loads((ROOT / 'ScoutSuite/providers/aws/rules/rulesets' / ruleset).read_text())['rules']
        for name in ('guardduty-not-enabled.json', 'accessanalyzer-not-configured.json'):
            assert rules[name] == [{'enabled': True, 'level': 'warning'}], (ruleset, name)
    metadata = json.loads((ROOT / 'ScoutSuite/providers/aws/metadata.json').read_text())['security']
    assert metadata['guardduty']['resources']['regions']['path'] == 'services.guardduty.regions'
    assert metadata['accessanalyzer']['resources']['regions']['path'] == 'services.accessanalyzer.regions'
    partials = ROOT / 'ScoutSuite/output/data/html/partials/aws'
    for name, field in (('guardduty', 'guardduty_status'), ('accessanalyzer', 'analyzer_status')):
        text = (partials / ('services.%s.regions.html' % name)).read_text(encoding='utf-8')
        assert '{{{' not in text and 'onclick' not in text
        assert '<samp>{{%s}}</samp>' % field in text
        assert 'Handlebars.registerPartial("services.%s.regions"' % name in text
