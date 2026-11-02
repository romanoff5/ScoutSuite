"""RC1 runtime failures reproduced with synthetic inventories and active RunContext."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.rule_evidence import evaluate_rule_evidence, SCOPED_POLICIES
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext, safe_collection_issue_code
from ScoutSuite.providers.aws.facade.networkfirewall import NetworkFirewallFacade
from ScoutSuite.providers.aws.facade.ssm_public import SSMPublicFacade


ROOT = Path(__file__).resolve().parents[1]
FINDINGS = ROOT / 'ScoutSuite/providers/aws/rules/findings'


def rule(filename):
    data = json.loads((FINDINGS / filename).read_text(encoding='utf-8'))
    return SimpleNamespace(filename=filename, **data)


def inventory(definition, resource):
    current = resource
    for part in reversed(definition.path.split('.')):
        current = {'synthetic' if part == 'id' else part: current}
    return current


def test_every_published_evidence_policy_executes_on_empty_inventory():
    for path in FINDINGS.glob('*.json'):
        definition = rule(path.name)
        summary = evaluate_rule_evidence(definition, {})
        if getattr(definition, 'evidence_policy', None):
            assert summary['assessment_status'] == 'not_applicable', path.name
            assert summary['compliance_verified'] is False


SCOPED = [(policy, filename, field) for policy, rules in SCOPED_POLICIES.items()
          for filename, (_, field) in rules.items()]


@pytest.mark.parametrize('policy,filename,field', SCOPED)
def test_scoped_rules_preserve_positive_and_unknown_evidence(policy, filename, field):
    definition = rule(filename)
    positive = {field: True, 'detail_complete': True, 'logging_complete': True,
                'logging_verified': True, 'detail_verified': True,
                'routing_status': 'no_endpoint_routes' if field == 'no_endpoint_routes'
                else 'inactive_or_unready'}
    result = evaluate_rule_evidence(definition, inventory(definition, positive))
    assert result['counts']['insecure'] == 1
    assert result['policy'] == policy
    for missing in ({}, {field: False}, None):
        result = evaluate_rule_evidence(definition, inventory(definition, missing))
        assert result['counts']['unknown'] == 1
        assert result['assessment_status'] == 'incomplete'
        assert result['compliance_verified'] is False


@pytest.mark.parametrize('filename,resource,expected', [
    ('networkfirewall-logging-disabled.json',
     {'logging_complete': True, 'logging_disabled': False, 'logging_destinations': [{'LogType': 'FLOW'}]}, 'secure'),
    ('networkfirewall-stateless-default-pass.json',
     {'detail_complete': True, 'stateless_default_actions': ['aws:forward_to_sfe']}, 'secure'),
    ('networkfirewall-fragment-default-pass.json',
     {'detail_complete': True, 'stateless_fragment_default_actions': ['aws:drop']}, 'secure'),
    ('networkfirewall-no-route-references.json', {'routing_status': 'endpoint_referenced'}, 'secure'),
    ('networkfirewall-routes-not-ready.json', {'routing_status': 'endpoint_referenced'}, 'secure'),
    ('networkfirewall-broad-pass-rule.json', {'detail_complete': True, 'broad_pass': False}, 'unknown'),
    ('bedrock-invocation-logging-review.json',
     {'logging_verified': True, 'logging_config': {'text_enabled': True}}, 'secure'),
    ('bedrock-agent-no-explicit-guardrail-review.json',
     {'detail_verified': True, 'guardrail_identifier': 'synthetic-guardrail'}, 'secure'),
    ('macie-session-not-enabled.json', {'session_verified': True, 'session_status': 'PAUSED'}, 'insecure'),
    ('macie-session-not-enabled.json', {'session_verified': True, 'session_status': 'ENABLED'}, 'secure'),
    ('macie-session-not-enabled.json', {'session_status': 'NOT_ENABLED'}, 'unknown'),
    ('macie-no-classification-configured.json',
     {'session_verified': True, 'session_status': 'ENABLED', 'automated_discovery_verified': True,
      'automated_discovery_status': 'DISABLED', 'jobs_complete': True, 'jobs_count': 0}, 'insecure'),
    ('macie-no-classification-configured.json',
     {'session_verified': True, 'session_status': 'NOT_ENABLED'}, 'not_applicable'),
    ('macie-no-classification-configured.json', {}, 'unknown'),
    ('macie-bucket-coverage-issue.json', {'coverage_status': 'ERROR'}, 'insecure'),
    ('macie-bucket-coverage-issue.json', {'coverage_status': 'RECENT_ACTIVITY'}, 'unknown'),
    ('macie-job-stale.json', {'type': 'SCHEDULED', 'stale': True}, 'insecure'),
    ('macie-job-stale.json', {'type': 'SCHEDULED', 'last_run_age_days': 2}, 'secure'),
    ('macie-job-stale.json', {'type': 'ONE_TIME'}, 'not_applicable'),
    ('macie-job-stale.json', {'type': 'SCHEDULED', 'stale': False}, 'unknown'),
    ('macie-job-execution-issue.json', {'execution_issue': True}, 'insecure'),
    ('macie-job-execution-issue.json', {'execution_success_evidence': True}, 'secure'),
    ('macie-job-execution-issue.json', {'execution_issue': False}, 'unknown'),
])
def test_observed_secure_insecure_inapplicable_and_missing_cases(filename, resource, expected):
    definition = rule(filename)
    result = evaluate_rule_evidence(definition, inventory(definition, resource))
    assert result['counts'][expected] == 1
    assert result['compliance_verified'] is False


def test_default_processing_keeps_all_thirteen_findings_instead_of_rule_errors():
    async def scenario():
        context = RunContext('aws').setup()
        try:
            ruleset = Ruleset('aws', filename='default.json')
            ruleset.rules = {name: entries for name, entries in ruleset.rules.items()
                             if name.startswith(('networkfirewall-', 'macie-', 'bedrock-'))}
            services = {}
            for name, entries in ruleset.rules.items():
                definition = entries[0]
                field = definition.conditions[1][0]
                resource = {field: True, 'detail_complete': True, 'logging_complete': True,
                            'logging_verified': True, 'detail_verified': True,
                            'routing_status': 'no_endpoint_routes' if field == 'no_endpoint_routes'
                            else 'inactive_or_unready', 'session_verified': True,
                            'session_status': 'PAUSED', 'coverage_status': 'ERROR',
                            'type': 'SCHEDULED'}
                # Separate resources prevent one rule's candidate overwriting another.
                current = services
                parts = definition.path.split('.')
                for part in parts[:-1]:
                    current = current.setdefault('synthetic' if part == 'id' else part, {})
                current[name if parts[-1] == 'id' else parts[-1]] = resource
            provider = SimpleNamespace(services=services, service_list=list(services))
            ProcessingEngine(ruleset).run(provider)
            findings = [finding for value in services.values() for finding in value['findings'].values()]
            assert len(findings) == 13
            assert all('evaluation_summary' in finding for finding in findings)
            assert all(finding['flagged_items'] >= 1 for finding in findings)
            assert not context.errors
            assert not any(issue['reason_code'] == 'RuleEvaluation' for issue in context.collection_issues)
        finally:
            await context.aclose()
    asyncio.run(scenario())


@pytest.mark.parametrize('facade,method,operation', [
    (SSMPublicFacade, 'call', 'describe_instance_information'),
    (NetworkFirewallFacade, 'one', 'describe_firewall'),
])
def test_denied_api_with_active_context_records_issue_without_secondary_exception(facade, method, operation):
    async def scenario():
        context = RunContext('aws').setup()
        try:
            client = Mock()
            getattr(client, operation).side_effect = ClientError(
                {'Error': {'Code': 'AccessDeniedException', 'Message': 'synthetic-message-must-not-leak'}}, operation)
            collector = facade(object()) if facade is SSMPublicFacade else facade(object(), '000000000000')
            assert await getattr(collector, method)(client, operation) is None
            assert context.collection_issues == [{'status': 'denied',
                'scope': 'ssm' if facade is SSMPublicFacade else 'networkfirewall',
                'reason_code': operation + '_AccessDeniedException'}]
            assert context.collection_summary()['complete'] is False
            assert 'synthetic-message' not in json.dumps(context.collection_summary())
        finally:
            await context.aclose()
    asyncio.run(scenario())


def test_diagnostic_code_stays_bounded_distinct_and_schema_valid():
    a = safe_collection_issue_code('operation:' + 'x' * 100 + 'A')
    b = safe_collection_issue_code('operation:' + 'x' * 100 + 'B')
    assert len(a) == len(b) == 64 and a != b
    context = RunContext('aws')
    context.record_collection_issue('partial', 'ssm', a)
    assert safe_collection_issue_code('') == 'UnknownError'
    with pytest.raises(ValueError, match='Unsafe collection'):
        context.record_collection_issue('partial', 'ssm', 'still:rejected')


@pytest.mark.parametrize('facade', [SSMPublicFacade, NetworkFirewallFacade])
def test_malformed_page_with_active_context_keeps_partial_status(facade):
    async def scenario():
        context = RunContext('aws').setup()
        try:
            client = Mock()
            client.list_items.return_value = {'Items': 'malformed'}
            collector = facade(object()) if facade is SSMPublicFacade else facade(object(), '000000000000')
            assert await collector.pages(client, 'list_items', 'Items') == ([], False)
            assert context.collection_issues[0]['status'] == 'partial'
            assert context.collection_issues[0]['reason_code'] == 'list_items_MalformedPage'
        finally:
            await context.aclose()
    asyncio.run(scenario())
