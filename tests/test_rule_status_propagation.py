"""Post-RC9: a finding's incomplete status must not depend on the order rules are evaluated in.

A collection gap known before rule evaluation marks every rule of its service incomplete; an
issue raised while evaluating one rule stays with that rule. Synthetic data only, no SDK or network.
"""
import copy
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from ScoutSuite.core import processingengine
from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext


ORDERS = ('as_loaded', 'reversed')
IMDS = 'ec2-instance-imdsv1-enabled'
EBS = 'ec2-ebs-volume-not-encrypted'
SNAPSHOT = 'ec2-ebs-snapshot-not-encrypted'

# Each pair of independent rules flags exactly one synthetic resource.
CASES = {
    'aws': ('ec2', (EBS, SNAPSHOT), lambda: {'ec2': {'regions': {'us-east-1': {
        'volumes': {'vol-plain': {'Encrypted': False}, 'vol-sealed': {'Encrypted': True}},
        'snapshots': {'snap-plain': {'encrypted': False}, 'snap-sealed': {'encrypted': True}},
    }}}}),
    'azure': ('appservice', ('appservice-ftp-deployment-enabled', 'appservice-client-certificates-disabled'),
              lambda: {'appservice': {'subscriptions': {'sub-a': {'web_apps': {
                  'app-a': {'ftp_deployment_enabled': True, 'client_cert_enabled': False}}}}}}),
    'gcp': ('cloudsql', ('cloudsql-instance-backups-disabled', 'cloudsql-postgresql-instances-log-checkpoints-off'),
            lambda: {'cloudsql': {'projects': {'project-a': {'instances': {'db-a': {
                'automatic_backup_enabled': False, 'is_failover_replica': False,
                'log_checkpoints_on': False}}}}}}),
}


def run_engine(tmp_path, provider_code, rule_names, provider, order, evidence=None):
    """Evaluate the rules in loaded or fully reversed order; return the rule keys in evaluation order."""
    rules = tmp_path / ('rules-%s-%s.json' % (provider_code, order))
    rules.write_text(json.dumps({'about': 'Synthetic rule order', 'rules': {
        name + '.json': [{'enabled': True, 'level': 'warning'}] for name in rule_names}}), encoding='utf-8')
    engine = ProcessingEngine(Ruleset(cloud_provider=provider_code, filename=str(rules)))
    if order == 'reversed':
        engine.rules = {path: list(reversed(group)) for path, group in reversed(list(engine.rules.items()))}
    seen = []
    evaluate = evidence or processingengine.evaluate_rule_evidence

    def record(rule, services):
        seen.append(rule.key)
        return evaluate(rule, services)

    with patch.object(processingengine, 'evaluate_rule_evidence', side_effect=record):
        engine.run(provider)
    return seen


def assert_flagged_once(finding):
    assert finding['flagged_items'] == 1
    assert finding['checked_items'] >= 1
    assert finding.get('assessment_status') is None


def test_rule_evidence_gap_stays_with_its_rule_in_any_order(tmp_path):
    findings, evaluated = {}, {}
    for order in ORDERS:
        services = CASES['aws'][2]()
        # No metadata_options, so the IMDS evidence policy cannot classify the instance.
        services['ec2']['regions']['us-east-1']['vpcs'] = {'vpc-a': {'instances': {
            'i-a': {'imds_v2_status': 'unknown'}}}}
        provider = SimpleNamespace(services=services, service_list=['ec2'])
        context = RunContext('aws').setup()
        try:
            evaluated[order] = run_engine(tmp_path, 'aws', (IMDS, EBS, SNAPSHOT), provider, order)
            assert context.collection_issues == [{
                'status': 'partial', 'scope': 'ec2', 'reason_code': 'RuleEvidenceUnknown'}]
        finally:
            context.cleanup()
        result = provider.services['ec2']['findings']
        assert result[IMDS]['assessment_status'] == 'incomplete'
        assert result[IMDS]['evaluation_summary']['counts']['unknown'] == 1
        assert_flagged_once(result[EBS])
        assert_flagged_once(result[SNAPSHOT])
        findings[order] = copy.deepcopy(result)
    assert evaluated['as_loaded'] == list(reversed(evaluated['reversed']))
    assert findings['as_loaded'] == findings['reversed']


@pytest.mark.parametrize('order', ORDERS)
@pytest.mark.parametrize('provider_code', sorted(CASES))
def test_rule_evaluation_failure_stays_with_failing_rule(tmp_path, provider_code, order):
    service, (failing, healthy), services = CASES[provider_code]
    real = processingengine.evaluate_rule_evidence

    def evidence(rule, services):
        if rule.key == failing:
            raise ValueError('synthetic evaluation failure')
        return real(rule, services)

    provider = SimpleNamespace(services=services(), service_list=[service])
    context = RunContext(provider_code).setup()
    try:
        assert len(run_engine(tmp_path, provider_code, (failing, healthy), provider, order, evidence)) == 2
        assert context.collection_issues == [{'status': 'failed', 'scope': service, 'reason_code': 'RuleEvaluation'}]
    finally:
        context.cleanup()
    findings = provider.services[service]['findings']
    assert findings[failing]['assessment_status'] == 'incomplete'
    assert findings[failing]['items'] == [] and findings[failing]['flagged_items'] == 0
    assert_flagged_once(findings[healthy])


@pytest.mark.parametrize('order', ORDERS)
@pytest.mark.parametrize('provider_code', sorted(CASES))
@pytest.mark.parametrize('scope, marked', [('service', True), ('assessment', True), ('unrelated', False)])
def test_collection_gap_before_rules_marks_every_rule_of_its_scope(tmp_path, provider_code, order, scope, marked):
    service, rule_names, services = CASES[provider_code]
    scope = {'service': service, 'unrelated': 'otherservice'}.get(scope, scope)
    provider = SimpleNamespace(services=services(), service_list=[service])
    context = RunContext(provider_code).setup()
    try:
        context.record_collection_issue('denied', scope, 'AccessDenied')
        run_engine(tmp_path, provider_code, rule_names, provider, order)
    finally:
        context.cleanup()
    for name in rule_names:
        finding = provider.services[service]['findings'][name]
        assert finding['flagged_items'] == 1  # Partial evidence is still reported.
        assert finding.get('assessment_status') == ('incomplete' if marked else None)


@pytest.mark.parametrize('order', ORDERS)
@pytest.mark.parametrize('issue, marked', [
    ({'status': 'partial', 'scope': 'ec2', 'reason_code': 'RuleEvidenceUnknown'}, False),
    ({'status': 'failed', 'scope': 'ec2', 'reason_code': 'RuleEvaluation'}, False),
    ({'status': 'denied', 'scope': 'ec2', 'reason_code': 'AccessDenied'}, True),
    ({'status': 'denied', 'scope': 'ec2'}, True),  # Legacy issue without a reason code.
])
def test_saved_status_without_run_context_propagates_only_collection_gaps(tmp_path, order, issue, marked):
    service, rule_names, services = CASES['aws']
    provider = SimpleNamespace(services=services(), service_list=[service],
                               collection_status={'version': 1, 'issues': [issue]})
    run_engine(tmp_path, 'aws', rule_names, provider, order)
    for name in rule_names:
        assert provider.services[service]['findings'][name].get('assessment_status') == (
            'incomplete' if marked else None)
