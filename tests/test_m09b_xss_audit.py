"""M09-B adversarial audit of all legacy Handlebars templates and renderer sinks.

Browser coverage is added when a local Chromium/Chrome binary is available;
pure-JS command parser tests use the runner's Node runtime, without network.
"""
import html
import json
import re
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'ScoutSuite' / 'output' / 'data'
TEMPLATES = ASSETS / 'html'
SANITIZER = ASSETS / 'inc-scoutsuite' / 'report_sanitizer.js'
SCOUT = ASSETS / 'inc-scoutsuite' / 'scoutsuite.js'


class ScriptProbe(HTMLParser):
    def __init__(self):
        super().__init__()
        self.executable = False
        self.unsafe = []

    def handle_starttag(self, tag, attrs):
        if tag == 'script':
            kind = dict(attrs).get('type')
            self.executable = kind not in ('text/x-handlebars-template',)

    def handle_data(self, data):
        if self.executable and '{{' in data:
            self.unsafe.append(data[:120])

    def handle_endtag(self, tag):
        if tag == 'script':
            self.executable = False


def test_all_legacy_handlebars_templates_are_scanned_for_unsafe_contexts():
    paths = sorted(TEMPLATES.rglob('*.html'))
    assert len(paths) >= 225, 'Report template inventory unexpectedly contracted'
    raw_interpolations = []
    script_interpolations = []
    direct_link_values = []
    inline_event_interpolations = []
    for path in paths:
        source = path.read_text(encoding='utf-8')
        for expression in re.findall(r'\{\{\{(.*?)\}\}\}', source, re.DOTALL):
            if not expression.strip().startswith('good_bad_icon '):
                raw_interpolations.append((str(path.relative_to(ROOT)), expression[:80]))
        for value in re.findall(r'\bhref\s*=\s*(["\'])(.*?)\1', source, re.I | re.S):
            href = value[1].strip()
            if href.startswith('{{') and not href.startswith('{{safe_report_href '):
                direct_link_values.append((str(path.relative_to(ROOT)), href))
        for line in source.splitlines():
            if re.search(r'\bon\w+\s*=\s*["\'][^"\']*\{\{', line, re.I):
                inline_event_interpolations.append((str(path.relative_to(ROOT)), line.strip()))
        probe = ScriptProbe()
        probe.feed(source)
        if probe.unsafe:
            script_interpolations.append((str(path.relative_to(ROOT)), probe.unsafe))
    assert not raw_interpolations, raw_interpolations
    assert not script_interpolations, script_interpolations
    assert not direct_link_values, direct_link_values
    assert not inline_event_interpolations, inline_event_interpolations


def test_every_rendered_html_sink_uses_a_sanitizer_and_no_eval():
    js = SCOUT.read_text(encoding='utf-8')
    report = (TEMPLATES / 'report.html').read_text(encoding='utf-8')
    guard = SANITIZER.read_text(encoding='utf-8')
    assert report.index('inc-scoutsuite/report_sanitizer.js') < report.index(
        'inc-scoutsuite/scoutsuite.js')
    assert 'sanitizeReportHTML(compiledTemplate({items: list}))' in js
    assert "html(sanitizeReportHTML(content))" in js
    for dynamic_name in ('last_run_details_template(runResults)',
                         'resources_details_template(runResults)'):
        assert 'sanitizeReportHTML(' + dynamic_name + ')' in js
    assert 'template.textContent' in js
    assert 'eval(' not in js
    assert 'eval(' not in (ASSETS / 'inc-scoutsuite/helpers.js').read_text(
        encoding='utf-8')
    assert 'DANGEROUS_TAGS' in guard and 'DANGEROUS_TAGS.has(tag)' in guard
    assert "name.startsWith('on')" in guard
    assert "element.removeAttribute(attribute.name)" in guard
    assert "parseScoutAction(value)" in guard
    assert "allowedAsset(value)" in guard
    assert 'new Function' not in guard
    assert 'eval(' not in guard
    assert "showIAMPolicy(Object.assign({}, data, {policy_id: policyId}))" in js
    assert "Object.assign({}, getResource(path))" in js


def check_legacy_js_action_parser_rejects_code_injection_and_malicious_urls():
    node = shutil.which('node')
    if not node:
        raise RuntimeError('Node is required for JS action parser security verification')
    script = r"""
    const assert = require('assert');
    require(process.argv[1]);
    const parse = globalThis.parseScoutAction;
    const safe = globalThis.scoutSafeHref;
    assert.deepStrictEqual(JSON.parse(JSON.stringify(parse(
        "javascript:showObject('services.ec2.instances.safe')"
    ))), {name:'showObject', args:['services.ec2.instances.safe']});
    assert.deepStrictEqual(JSON.parse(JSON.stringify(parse(
        "javascript:showObject('services.iam.users', 'name', 'safe')"
    ))), {name:'showObject', args:['services.iam.users', 'name', 'safe']});
    assert.deepStrictEqual(JSON.parse(JSON.stringify(parse(
        "javascript:showNamespacedResources(" +
        String.fromCharCode(96) + "services.kubernetes.pods" +
        String.fromCharCode(96) + ")"
    ))), {name:'showNamespacedResources', args:['services.kubernetes.pods']});
    const attacks = [
        "javascript:alert('XSS')",
        "javascript:showObject('safe');alert(1)//",
        "javascript:showObject('safe');globalThis.pwned=1;//')",
        "javascript:showObject('a\\' + ');alert(1)//')",
        "javascript:showObject('a\\u0027);alert(1);//')",
        "javascript:showObject('a' + alert(1))",
        "javascript:showObject((()=>alert(1))())",
        "javascript:showObject('safe', window.alert(1))",
        "javascript:showObject('safe') // bypass",
        "javascript:constructor('payload')",
        "javascript:showObject('a" + String.fromCharCode(10) + "b')",
        "data:text/html,<script>alert(1)</script>"
    ];
    for (const attack of attacks) assert.strictEqual(parse(attack), null, attack);
    assert.strictEqual(safe('javascript:alert(1)'), false);
    assert.strictEqual(safe('JaVaScRiPt:alert(1)'), false);
    assert.strictEqual(safe('data:text/html,payload'), false);
    assert.strictEqual(safe('//evil.example/path'), false);
    assert.strictEqual(safe('../../sensitive-data'), false);
    assert.strictEqual(safe('https://docs.aws.amazon.com/'), true);
    assert.strictEqual(safe('#services.iam.users'), true);
    assert.strictEqual(safe('mailto:security@example.org'), true);
    """
    proc = subprocess.run([node, '-e', script, str(SANITIZER)], capture_output=True,
                          text=True, timeout=15, check=False)
    assert proc.returncode == 0, proc.stdout + '\n' + proc.stderr


def check_compiled_markup_blocks_dom_xss_in_real_chromium_when_available(tmp_path):
    chrome = next((shutil.which(binary) for binary in (
        'chromium', 'chromium-browser', 'google-chrome', 'chrome')
        if shutil.which(binary)), None)
    if not chrome:
        return False
    malicious = (
        '<img src="x" onerror="document.body.dataset.pwned=1">'
        '<svg onload="document.body.dataset.pwned=1"></svg>'
        '<div id="badcss" style="background-image:image-set(url(https://example.invalid/x) 1x)">bad CSS</div>'
        '<div id="goodcss" style="text-align: center; display: none">safe CSS</div>'
        '<a id="bad" href="javascript:alert(1)">bad</a>'
        '<a id="attack" href="javascript:showObject('
        '\'evil&#39;);alert(1);//\')">injected</a>'
        '<a id="data" href="data:text/html,payload">data</a>'
        '<a id="safe" href="javascript:showObject('
        '\'services.iam.users.safe\')">safe</a>'
    )
    sanitizer_source = SANITIZER.read_text(encoding='utf-8')
    payload = json.dumps(malicious).replace('</', '<\\/')
    page = (
        '<!doctype html><html><body><div id="sink"></div>'
        '<output id="audit-result"></output><script>'
        + sanitizer_source + '</script><script>'
        "window.showObject = function (name) { window.calledRoute = name; };"
        "document.getElementById('sink').innerHTML = sanitizeReportHTML("
        + payload + ");"
        "document.getElementById('safe').click();"
        "setTimeout(function () {"
        " const root = document.getElementById('sink');"
        " document.getElementById('audit-result').textContent = JSON.stringify({"
        "   called:window.calledRoute, fired:document.body.dataset.pwned || null,"
        "   badHref:root.querySelector('#bad').getAttribute('href'),"
        "   attackAction:root.querySelector('#attack').getAttribute('data-scout-action'),"
        "   dataHref:root.querySelector('#data').getAttribute('href'),"
        "   badStyle:root.querySelector('#badcss').getAttribute('style'),"
        "   goodStyle:root.querySelector('#goodcss').getAttribute('style'),"
        "   scripts:root.querySelectorAll('script,svg,iframe').length,"
        "   errorHandler:root.querySelector('img').hasAttribute('onerror')"
        " });"
        "},150);"
        "</script></body></html>"
    )
    page_path = tmp_path / 'adversarial.html'
    page_path.write_text(page, encoding='utf-8')
    run = subprocess.run([
        chrome, '--headless', '--no-sandbox', '--disable-gpu',
        '--disable-dev-shm-usage', '--no-first-run',
        '--virtual-time-budget=1500', '--dump-dom', page_path.as_uri(),
    ], capture_output=True, text=True, timeout=30, check=False)
    assert run.returncode == 0, run.stderr[-2000:]
    match = re.search(r'<output id="audit-result">(.*?)</output>', run.stdout, re.S)
    assert match, run.stdout[-2500:]
    result = json.loads(html.unescape(match.group(1)))
    assert result == {
        'called': 'services.iam.users.safe', 'fired': None,
        'badHref': None, 'attackAction': None, 'dataHref': None,
        'badStyle': None, 'goodStyle': 'text-align: center; display: none',
        'scripts': 0, 'errorHandler': False,
    }
    return True
