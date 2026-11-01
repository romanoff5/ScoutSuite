"""M08 remaining: dated AWS evidence, unknown/NA handling, and stable rule IDs."""
import json
from datetime import date
from types import SimpleNamespace

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.rule_evidence import (
    classify_imds_v2, classify_lambda_runtime, classify_classic_elb_policy,
)
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.core.ruleset import Ruleset
from tests.fixtures import ROOT


def test_imds_v2_explicit_four_states():
    assert classify_imds_v2({'metadata_options': {'HttpEndpoint': 'enabled', 'HttpTokens': 'required'}}) == 'secure'
    assert classify_imds_v2({'metadata_options': {'HttpEndpoint': 'enabled', 'HttpTokens': 'optional'}}) == 'insecure'
    assert classify_imds_v2({'metadata_options': {'HttpEndpoint': 'disabled', 'HttpTokens': 'optional'}}) == 'not_applicable'
    assert classify_imds_v2({'metadata_options': {}}) == 'unknown'
    assert classify_imds_v2({'metadata_options': {'HttpTokens': 'required', 'State': 'pending'}}) == 'unknown'


def test_lambda_dated_lifecycle_and_container_exclusion():
    assert classify_lambda_runtime({'runtime': 'python3.10', 'package_type': 'Zip'},
                                   as_of=date(2026, 10, 30)) == 'secure'
    assert classify_lambda_runtime({'runtime': 'python3.10', 'package_type': 'Zip'},
                                   as_of=date(2026, 11, 1)) == 'insecure'
    assert classify_lambda_runtime({'runtime': 'python3.14', 'package_type': 'Zip'},
                                   as_of=date(2026, 11, 1)) == 'secure'
    assert classify_lambda_runtime({'runtime': 'python3.9'},
                                   as_of=date(2026, 11, 1)) == 'insecure'
    assert classify_lambda_runtime({'package_type': 'Image'}) == 'not_applicable'
    assert classify_lambda_runtime({'package_type': 'Zip'}) == 'unknown'
    assert classify_lambda_runtime({'runtime': 'python3.50', 'package_type': 'Zip'}) == 'unknown'


def test_classic_elb_predefined_custom_and_denied():
    def policy(name, attributes=None, kind='SSLNegotiationPolicyType'):
        return {'PolicyName': name, 'PolicyTypeName': kind,
                'PolicyAttributeDescriptions': attributes or []}
    assert classify_classic_elb_policy(policy('ELBSecurityPolicy-TLS-1-2-2017-01')) == 'secure'
    assert classify_classic_elb_policy(policy('ELBSecurityPolicy-2016-08')) == 'insecure'
    assert classify_classic_elb_policy(policy('unknown-new-policy')) == 'unknown'
    assert classify_classic_elb_policy({'PolicyName': 'missing-attributes',
                                        'PolicyTypeName': 'SSLNegotiationPolicyType'}) == 'unknown'
    assert classify_classic_elb_policy(policy('other', kind='BackendServerAuthenticationPolicyType')) == 'not_applicable'
    assert classify_classic_elb_policy(policy('custom', [
        {'AttributeName': 'Protocol-TLSv1', 'AttributeValue': 'true'}])) == 'insecure'
    assert classify_classic_elb_policy(policy('custom-modern', [
        {'AttributeName': n, 'AttributeValue': 'false'} for n in (
            'Protocol-SSLv3', 'Protocol-TLSv1', 'Protocol-TLSv1.1')
    ] + [{'AttributeName': 'Protocol-TLSv1.2', 'AttributeValue': 'true'}])) == 'secure'


def test_catalog_provenance_and_legacy_ruleset_still_available():
    prefix = ROOT / 'ScoutSuite/providers/aws/rules'
    for name in ('lambda-runtimes-2026-11', 'classic-elb-tls-2026-11'):
        catalog = json.loads((prefix / 'catalogs' / (name + '.json')).read_text(encoding='utf8'))
        assert catalog['schema_version'] == 1
        assert catalog['catalog_version'] == '2026.11.0'
        assert catalog['review_date'] == '2026-11-01'
        assert catalog['owner']
        assert all(x.startswith('https://docs.aws.amazon.com/') for x in catalog['reference_urls'])
    old = json.loads((prefix / 'rulesets' / 'cis-1.2.0.json').read_text(encoding='utf8'))
    assert 'iam-root-account-no-mfa.json' in old['rules']
    default = json.loads((prefix / 'rulesets' / 'default.json').read_text(encoding='utf8'))
    assert default['rules']['ec2-instance-imdsv1-enabled.json'][0]['enabled']
    assert default['rules']['awslambda-function-deprecated-runtime.json'][0]['enabled']


def test_rule_engine_reports_insecure_only_and_marks_unknown(tmp_path):
    cases = [
        ('ec2-instance-imdsv1-enabled.json', 'ec2',
         {'regions': {'us-east-1': {'vpcs': {'vpc-1': {'instances': {
             'safe': {'imds_v2_status': 'required', 'metadata_options': {'HttpTokens': 'required'}},
             'bad': {'imds_v2_status': 'optional', 'metadata_options': {'HttpTokens': 'optional'}},
             'denied': {'imds_v2_status': 'unknown', 'metadata_options': {}},
             'disabled': {'imds_v2_status': 'disabled', 'metadata_options': {'HttpEndpoint': 'disabled'}},
         }}}}}},
         'ec2.regions.us-east-1.vpcs.vpc-1.instances.bad.imds_v2_status'),
        ('awslambda-function-deprecated-runtime.json', 'lambda',
         {'regions': {'us-east-1': {'functions': {
             'safe': {'runtime_lifecycle_status': 'supported', 'runtime': 'python3.14', 'package_type': 'Zip'},
             'bad': {'runtime_lifecycle_status': 'deprecated', 'runtime': 'python3.9', 'package_type': 'Zip'},
             'denied': {'runtime_lifecycle_status': 'unknown', 'package_type': 'Zip'},
             'disabled': {'runtime_lifecycle_status': 'image', 'package_type': 'Image'},
         }}}},
         'lambda.regions.us-east-1.functions.bad.runtime_lifecycle_status'),
        ('elb-older-ssl-policy.json', 'elb',
         {'regions': {'us-east-1': {'elb_policies': {
             'safe': {'reference_security_policy': 'modern', 'name': 'ELBSecurityPolicy-TLS-1-2-2017-01', 'PolicyTypeName': 'SSLNegotiationPolicyType', 'PolicyAttributeDescriptions': []},
             'bad': {'reference_security_policy': 'legacy', 'name': 'ELBSecurityPolicy-2016-08', 'PolicyTypeName': 'SSLNegotiationPolicyType', 'PolicyAttributeDescriptions': []},
             'denied': {'reference_security_policy': 'unknown', 'name': 'new-policy', 'PolicyTypeName': 'SSLNegotiationPolicyType', 'PolicyAttributeDescriptions': []},
             'disabled': {'reference_security_policy': 'not_applicable', 'PolicyTypeName': 'OtherPolicy', 'PolicyAttributeDescriptions': []},
         }}}},
         'elb.regions.us-east-1.elb_policies.bad.reference_security_policy'),
    ]
    for rule_name, service, resources, expected in cases:
        chosen = tmp_path / (service + '.json')
        chosen.write_text(json.dumps({
            'about': 'Synthetic M08 isolated rule',
            'rules': {rule_name: [{'enabled': True, 'level': 'warning'}]}
        }), encoding='utf8')
        provider = SimpleNamespace(services={service: resources}, service_list=[service])
        context = RunContext('aws').setup()
        try:
            ProcessingEngine(Ruleset('aws', filename=str(chosen))).run(provider)
            key = rule_name[:-5]
            finding = provider.services[service]['findings'][key]
            assert finding['items'] == [expected]
            assert finding['flagged_items'] == 1
            assert finding['evaluation_summary']['counts'] == {
                'secure': 1, 'insecure': 1, 'unknown': 1, 'not_applicable': 1
            }
            assert finding['assessment_status'] == 'incomplete'
            assert context.collection_issues == [{'status':'partial', 'scope':service,
                                                  'reason_code':'RuleEvidenceUnknown'}]
        finally:
            context.cleanup()
