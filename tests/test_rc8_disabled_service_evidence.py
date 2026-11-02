"""RC8: disabled-service evidence must work with the responses AWS actually returns.

Field responses (synthetic identifiers here): DescribeHub answers an unsubscribed
account with InvalidAccessException "not subscribed"; an audit role may be IAM
denied GetMacieSession while ListFindings answers "Macie is not enabled.";
ListModelCustomizationJobs is not offered in every Bedrock Region.
"""
import asyncio
from unittest.mock import Mock, patch

import boto3
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from ScoutSuite.core.rule_evidence import classify_macie_session, classify_securityhub_subscription
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.bedrock import PAGE_SIZE, BedrockFacade
from ScoutSuite.providers.aws.facade.macie import MacieFacade
from ScoutSuite.providers.aws.facade.securityhub import SecurityHubPublicFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils

REGION = 'eu-central-1'
ACCOUNT = '000000000000'
ROLE_DENIAL = ('User: arn:aws:sts::000000000000:assumed-role/SyntheticAudit/session is not '
               'authorized to perform: {} on resource: arn:aws:{}:eu-central-1:000000000000:* '
               'because no identity-based policy allows the {} action')


def sdk(service):
    return boto3.client(service, region_name=REGION, aws_access_key_id='synthetic',
                        aws_secret_access_key='synthetic')


def error(code, message, operation):
    return ClientError({'Error': {'Code': code, 'Message': message}}, operation)


def run_with_context(scenario):
    async def wrapper():
        ctx = RunContext('aws').setup()
        try:
            return await scenario(), list(ctx.collection_issues)
        finally:
            await ctx.aclose()
    return asyncio.run(wrapper())


def describe_hub(code, message):
    async def scenario():
        hub = sdk('securityhub')
        facade = SecurityHubPublicFacade(object())
        try:
            with Stubber(hub) as stub:
                stub.add_client_error('describe_hub', service_error_code=code,
                                      service_message=message, http_status_code=401,
                                      expected_params={})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=hub):
                    assert await facade.get_hub(REGION) is None
                stub.assert_no_pending_responses()
        finally:
            hub.close()
        return facade.hub_states[REGION]
    return run_with_context(scenario)


def test_securityhub_invalid_access_not_subscribed_message_is_verified_not_subscribed():
    for message in ('Account %s is not subscribed to AWS Security Hub CSPM' % ACCOUNT,
                    'Account %s is not subscribed to AWS Security Hub' % ACCOUNT,
                    '  account %s is NOT subscribed to AWS Security Hub CSPM. ' % ACCOUNT):
        state, issues = describe_hub('InvalidAccessException', message)
        assert state == 'not_subscribed', message
        assert issues == [], message
        region = {'hub_subscription_status': state}
        assert classify_securityhub_subscription(region) == 'insecure'


def test_securityhub_other_invalid_access_stays_denied_unknown():
    for message in (ROLE_DENIAL.format('securityhub:DescribeHub', 'securityhub', 'securityhub:DescribeHub'),
                    'Account is not subscribed to AWS Security Hub',
                    'Account %s is not subscribed to AWS Security Hub; see delegated admin' % ACCOUNT,
                    ''):
        state, issues = describe_hub('InvalidAccessException', message)
        assert state == 'unknown', message
        assert [(i['status'], i['reason_code']) for i in issues] == [('denied', 'DescribeHubDenied')]
        assert classify_securityhub_subscription({'hub_subscription_status': state}) == 'unknown'


def macie_region(list_findings):
    async def scenario():
        client = Mock()
        client.get_macie_session.side_effect = error(
            'AccessDeniedException',
            ROLE_DENIAL.format('macie2:GetMacieSession', 'macie2', 'macie2:GetMacieSession'),
            'GetMacieSession')
        client.list_findings.side_effect = list_findings
        with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
            result = await MacieFacade(object()).get_region(REGION)
        return result, client
    return run_with_context(scenario)


def test_macie_iam_denied_session_uses_classify_only_list_findings_probe():
    (result, client), issues = macie_region(
        error('AccessDeniedException', 'Macie is not enabled.', 'ListFindings'))
    client.list_findings.assert_called_once_with(maxResults=1)
    assert result['session_status'] == 'NOT_ENABLED'
    assert result['session_verified'] is True
    assert result['session_status_source'] == 'ListFindings'
    assert issues == []
    assert classify_macie_session(result) == 'insecure'
    # Disabled Macie has no jobs/buckets to enumerate; no further calls.
    client.list_classification_jobs.assert_not_called()
    client.describe_buckets.assert_not_called()


def test_macie_probe_never_retains_findings_or_guesses_disabled():
    outcomes = (
        {'findingIds': ['synthetic-finding-id-should-never-be-kept']},
        error('AccessDeniedException',
              ROLE_DENIAL.format('macie2:ListFindings', 'macie2', 'macie2:ListFindings'), 'ListFindings'),
        error('ResourceNotFoundException', 'synthetic', 'ListFindings'),
        error('ThrottlingException', 'Rate exceeded', 'ListFindings'),
        RuntimeError('synthetic transport failure'),
    )
    for outcome in outcomes:
        mock_outcome = {'return_value': outcome} if isinstance(outcome, dict) else {'side_effect': outcome}

        async def scenario():
            client = Mock()
            client.get_macie_session.side_effect = error(
                'AccessDeniedException',
                ROLE_DENIAL.format('macie2:GetMacieSession', 'macie2', 'macie2:GetMacieSession'),
                'GetMacieSession')
            client.list_findings.configure_mock(**mock_outcome)
            with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                return await MacieFacade(object()).get_region(REGION)
        result, issues = run_with_context(scenario)
        assert result['session_status'] == 'UNKNOWN', outcome
        assert result['session_verified'] is False
        assert result['session_status_source'] is None
        assert 'synthetic-finding-id' not in repr(result)
        assert [(i['status'], i['reason_code']) for i in issues] == [('denied', 'GetMacieSessionDenied')]
        assert classify_macie_session(result) == 'unknown'


def test_macie_probe_only_after_iam_denial_not_other_session_errors():
    async def scenario():
        client = Mock()
        client.get_macie_session.side_effect = error('ThrottlingException', 'Rate exceeded', 'GetMacieSession')
        with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
            result = await MacieFacade(object()).get_region(REGION)
        client.list_findings.assert_not_called()
        return result
    result, issues = run_with_context(scenario)
    assert result['session_status'] == 'UNKNOWN'
    assert issues and issues[0]['reason_code'] == 'GetMacieSessionFailed'


def bedrock_inventory(model_jobs_error, extra=None):
    async def scenario():
        control, agent = sdk('bedrock'), sdk('bedrock-agent')
        try:
            with Stubber(control) as s, Stubber(agent) as a:
                s.add_response('get_model_invocation_logging_configuration', {}, {})
                for operation, key in (('list_guardrails', 'guardrails'),
                                       ('list_inference_profiles', 'inferenceProfileSummaries'),
                                       ('list_provisioned_model_throughputs', 'provisionedModelSummaries')):
                    if extra and extra[0] == operation:
                        s.add_client_error(operation, service_error_code=extra[1],
                                           http_status_code=400, expected_params={'maxResults': PAGE_SIZE})
                    else:
                        s.add_response(operation, {key: []}, {'maxResults': PAGE_SIZE})
                s.add_client_error('list_model_customization_jobs', service_error_code=model_jobs_error,
                                   http_status_code=400, expected_params={'maxResults': PAGE_SIZE})
                if model_jobs_error != 'UnknownOperationException' or extra:
                    s.add_response('list_enforced_guardrails_configuration', {'guardrailsConfig': []}, {})
                for operation, key in (('list_agents', 'agentSummaries'),
                                       ('list_knowledge_bases', 'knowledgeBaseSummaries'),
                                       ('list_flows', 'flowSummaries'),
                                       ('list_prompts', 'promptSummaries')):
                    a.add_response(operation, {key: []}, {'maxResults': PAGE_SIZE})
                with patch.object(AWSFacadeUtils, 'get_client',
                                  side_effect=lambda name, *_: control if name == 'bedrock' else agent):
                    result = await BedrockFacade(object()).inventory(REGION)
                s.assert_no_pending_responses()
                a.assert_no_pending_responses()
        finally:
            control.close()
            agent.close()
        return result
    return run_with_context(scenario)


def test_bedrock_region_without_model_customization_lets_sparse_deferral_work():
    result, issues = bedrock_inventory('UnknownOperationException')
    assert result['regional_availability'] == {'model_jobs': 'operation_not_available_in_region'}
    assert result['collection']['model_jobs'] is True and result['model_jobs'] == []
    # PR #26 deferral now applies: no restricted enforced-guardrail call was made
    # (the strict Stubber has no response queued for it) and status stays explicit.
    assert result['enforced_guardrails_evidence_status'] == 'deferred_no_customer_workload_evidence'
    assert result['collection']['enforced_guardrails'] is False
    assert issues == []


def test_bedrock_unknown_operation_elsewhere_or_denied_model_jobs_stay_incomplete():
    result, issues = bedrock_inventory('AccessDeniedException')
    assert result['collection']['model_jobs'] is False
    assert result['regional_availability'] == {}
    assert result['enforced_guardrails_evidence_status'] == 'verified'
    assert ('denied', 'list_model_customization_jobs_AccessDeniedException') in {
        (i['status'], i['reason_code']) for i in issues}
    # The exemption is limited to model customization, not other operations.
    result, issues = bedrock_inventory(
        'UnknownOperationException', extra=('list_provisioned_model_throughputs', 'UnknownOperationException'))
    assert result['collection']['provisioned_models'] is False
    assert result['regional_availability'] == {'model_jobs': 'operation_not_available_in_region'}
    assert ('unsupported', 'list_provisioned_model_throughputs_UnknownOperationException') in {
        (i['status'], i['reason_code']) for i in issues}


def test_reports_show_where_disabled_state_and_regional_absence_came_from():
    from pathlib import Path
    partials = Path(__file__).resolve().parents[1] / 'ScoutSuite/output/data/html/partials/aws'
    macie = (partials / 'services.macie.regions.html').read_text(encoding='utf-8')
    bedrock = (partials / 'services.bedrock.regions.html').read_text(encoding='utf-8')
    assert '<samp>{{session_status_source}}</samp>' in macie
    assert '<samp>{{regional_availability.model_jobs}}</samp>' in bedrock
    assert '{{{' not in macie + bedrock


def test_service_summary_counts_incomplete_rules_for_the_dashboard():
    from datetime import datetime, timezone
    from types import SimpleNamespace
    from ScoutSuite.providers.base.provider import BaseProvider

    provider = SimpleNamespace(services={
        'securityhub': {'findings': {
            'not-subscribed': {'checked_items': 1, 'flagged_items': 0, 'level': 'warning', 'items': [],
                               'assessment_status': 'incomplete'},
            'standards': {'checked_items': 0, 'flagged_items': 0, 'level': 'warning', 'items': []}},
            'regions_count': 1},
        'iam': {'findings': {
            'root-mfa': {'checked_items': 1, 'flagged_items': 0, 'level': 'danger', 'items': []}},
            'users_count': 2},
        'legacy': None})
    ruleset = SimpleNamespace(name='synthetic', about='synthetic')
    BaseProvider._update_last_run(provider, datetime(2026, 11, 2, tzinfo=timezone.utc), ruleset, {})
    summary = provider.last_run['summary']
    assert summary['securityhub']['incomplete_rules'] == 1
    assert summary['iam']['incomplete_rules'] == 0
    assert summary['legacy']['incomplete_rules'] == 0
    assert summary['iam']['resources_count'] == 2


def test_templates_pass_assessment_state_to_status_colour():
    from pathlib import Path
    html = Path(__file__).resolve().parents[1] / 'ScoutSuite/output/data/html'
    dashboard = (html / 'partials/dashboard.html').read_text(encoding='utf-8')
    report = (html / 'report.html').read_text(encoding='utf-8')
    assert dashboard.count('dashboard_color level checked_items flagged_items assessment_status') == 2
    assert 'Assessment status: {{assessment_status}}' in dashboard
    assert 'with unknown evidence: {{evaluation_summary.counts.unknown}}' in dashboard
    assert 'dashboard_color max_level checked_items flagged_items incomplete_rules' in report
    assert '{{{' not in dashboard


def test_dark_report_default_and_menu_actions_survive_sanitizer():
    import re
    from pathlib import Path
    data = Path(__file__).resolve().parents[1] / 'ScoutSuite/output/data'
    report = (data / 'html/report.html').read_text(encoding='utf-8')
    theme = (data / 'inc-scoutsuite/theme.js').read_text(encoding='utf-8')
    sanitizer = (data / 'inc-scoutsuite/report_sanitizer.js').read_text(encoding='utf-8')
    assert 'id="bootstrap-theme" href="inc-bootstrap/css/bootstrap-dark.min.css"' in report
    assert 'id="scout-theme" href="inc-scoutsuite/css/scoutsuite-dark.css"' in report
    assert "!== 'false'" in theme and "$(document).on('change', '#theme_checkbox', toggleTheme)" in theme
    # Compiled templates pass through the sanitizer, which strips inline on*
    # handlers: they would silently become dead controls.
    for partial in (data / 'html/partials').rglob('*.html'):
        assert not re.search(r'\son[a-z]+\s*=', partial.read_text(encoding='utf-8')), partial.name
    metadata = (data / 'html/partials/metadata.html').read_text(encoding='utf-8')
    for action in re.findall(r'href="javascript:([A-Za-z_]+)\(', metadata):
        assert "'" + action + "'" in sanitizer, action
