"""M09-B: execute isolated legacy JS helpers with hostile synthetic report data."""
import shutil
import subprocess

from tests.fixtures import ROOT


NODE = shutil.which('node')
def evaluate(script, *paths):
    assert NODE is not None, 'M09-B JavaScript security tests require Node.js'
    command = [NODE, '-e', script, *[str(ROOT / p) for p in paths]]
    result = subprocess.run(command, text=True, capture_output=True, check=False,
                            timeout=15)
    assert result.returncode == 0, result.stderr


def test_iam_policy_and_rule_helper_escapes_payload_without_mutation():
    script = r"""
const fs = require('fs'), vm = require('vm'), assert = require('assert');
let helpers = {};
const handlebars = {
  registerHelper: (name, f) => { helpers[name] = f },
  Utils: { escapeExpression: value => String(value).replace(/[&<>"'\u0060=]/g,
    char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#x27;','=':'&#x3D;','\u0060':'&#x60;'}[char] || char)) }
};
const ctx = vm.createContext({Handlebars: handlebars, console: console});
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), ctx, {timeout: 3000});
const input = {'Statement':[{'Effect':'Allow',
  'Resource':'</span><img src=x onerror=alert(1)>'}],
  '<svg onload=alert(1)>':'<script>alert(1)</script>'};
const original = JSON.stringify(input);
const html = helpers.displayPolicy(input);
assert(html.includes('&lt;img'));
assert(!html.includes('<img'));
assert(!html.includes('<svg'));
assert(!html.includes('<script>'));
assert(html.includes('<br/>'));
assert.strictEqual(JSON.stringify(input), original);
const jsonInput = {description:'keep',args:[1],name:'a'};
assert.strictEqual(helpers.jsonStringify(jsonInput).includes('description'), false);
assert.strictEqual(jsonInput.description, 'keep');
assert.deepStrictEqual(jsonInput.args, [1]);
ctx.runResults = {rule_definitions:{'x.json':{
  file_path:'private', description:'Do not mutate', key:'x'}}};
const output = helpers.get_rule('x.json', '');
assert.strictEqual(output.file_path, undefined);
assert.strictEqual(ctx.runResults.rule_definitions['x.json'].file_path, 'private');
assert(!fs.readFileSync(process.argv[1], 'utf8').includes('eval('));
"""
    evaluate(script, 'ScoutSuite/output/data/inc-scoutsuite/helpers.js')


def test_account_id_uses_dom_text_nodes_not_data_interpreted_as_markup():
    script = r"""
const fs = require('fs'), vm = require('vm'), assert = require('assert');
const children = [];
const account = {
  firstChild: null,
  removeChild: () => {throw Error('No stale children expected')},
  appendChild: node => {children.push(node); return node},
  set innerHTML(v) {throw Error('HTML insertion reached')},
};
const document = {
  getElementById: id => (id === 'account_id' ? account : null),
  createElement: tag => ({tagName:tag, className:''}),
  createTextNode: text => ({textContent:text}),
};
const jq = () => ({ready: () => {}});
const ctx = vm.createContext({window:{$:jq, location:{hash:''}},
  document:document, console:console});
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), ctx, {timeout:3000});
ctx.runResults = {provider_name:'AWS<img src=x onerror=alert(1)>',
                  account_id:'<svg onload=alert(1)>',organization:{}};
vm.runInContext('loadAccountId()', ctx, {timeout:3000});
assert(children.some(x => x.textContent && x.textContent.includes('<img')));
assert(children.some(x => x.textContent && x.textContent.includes('<svg')));
assert.strictEqual(children.filter(x => x.tagName).length, 2);
assert(!fs.readFileSync(process.argv[1], 'utf8').includes('eval(JSON.stringify(entities))'));
"""
    evaluate(script, 'ScoutSuite/output/data/inc-scoutsuite/scoutsuite.js')


def test_js_and_legacy_templates_contain_no_external_resource_fallback():
    shell = (ROOT / 'ScoutSuite/output/data/html/report.html').read_text(encoding='utf8')
    assert 'use.fontawesome.com' not in shell
    assert 'oss.maxcdn.com' not in shell
    js = (ROOT / 'ScoutSuite/output/data/inc-scoutsuite/sqlite.js').read_text(encoding='utf8')
    assert 'X-Scout-Viewer-Token' in js
    assert 'window.scoutViewerSession' in js


def test_csv_export_does_not_emit_executable_spreadsheet_formulas():
    script = r"""
const fs = require('fs'), vm = require('vm'), assert = require('assert');
let csvBlob;
const document = {};
const jq = () => ({ready: () => {}});
const ctx = vm.createContext({
  window:{$:jq, location:{hash:''}},
  document:document, console:console, Blob:Blob,
  navigator:{msSaveBlob:blob => {csvBlob = blob}}
});
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), ctx, {timeout:3000});
vm.runInContext('downloadAsCsv("test.csv", [["field"],["=1+1"],["\\t@SUM(A1)"],["safe"]])',
                ctx, {timeout:3000});
assert(csvBlob, 'Expected offline CSV export Blob');
csvBlob.text().then(csv => {
  assert(csv.includes("'=1+1"));
  assert(csv.includes("'\t@SUM(A1)"));
  assert(csv.includes('safe'));
  assert(!csv.includes('\n=1+1\n'));
}).catch(err => {console.error(err);process.exitCode=1});
"""
    evaluate(script, 'ScoutSuite/output/data/inc-scoutsuite/scoutsuite.js')


def test_iam_link_uses_data_attribute_and_safe_delegated_navigation():
    partial = (ROOT / 'ScoutSuite/output/data/html/partials/aws/services.iam.managed_policies.html'
               ).read_text(encoding='utf8')
    assert 'javascript:showObject(' not in partial
    assert 'data-scout-object-path=' in partial
    script = r"""
const fs = require('fs'), vm = require('vm'), assert = require('assert');
let onReady, click, navigated, prevented = false;
const doc = {addEventListener: (type, handler) => {
  if(type === 'click') click = handler;
}};
const jq = () => ({ready: handler => {onReady = handler}});
const ctx = vm.createContext({
  window:{$:jq, location:{hash:''}}, document:doc, console:console
});
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), ctx, {timeout:3000});
ctx.onPageLoad = () => {};
ctx.showObject = path => {navigated = path};
onReady();
assert(click);
const malicious = "services.iam.roles.fake');alert(1);//";
click({target:{closest: () => ({
   getAttribute: () => malicious
})}, preventDefault: () => {prevented = true}});
assert.strictEqual(navigated, malicious);
assert.strictEqual(prevented, true);
assert.strictEqual(typeof ctx.alert, 'undefined');
"""
    evaluate(script, 'ScoutSuite/output/data/inc-scoutsuite/scoutsuite.js')
