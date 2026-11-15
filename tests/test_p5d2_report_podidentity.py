"""P5-D2: Pod Identity API parity and per-resource report regression."""
import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ScoutSuite.providers.aws.facade.eks_public import EKSPublicFacade
from ScoutSuite.providers.aws.resources.iam.attack_paths_p5d import annotate_p5d_attack_paths
from ScoutSuite.core.finding_cards import build_observation_checks, build_resource_cards
from ScoutSuite.core.finding_confidence import build_finding_confidence

ACCOUNT = '123456789012'
CLUSTER = 'arn:aws:eks:eu-central-1:123456789012:cluster/sample'
ROLE = 'arn:aws:iam::123456789012:role/Admin'
ASSOC = 'arn:aws:eks:eu-central-1:123456789012:podidentityassociation/sample/pa-1'
OTHER_ROLE = 'arn:aws:iam::222222222222:role/CrossAccount'


def listed(ident='pa-1'):
    return {'associationId': ident, 'associationArn': ASSOC,
            'clusterName': 'sample', 'namespace': 'team',
            'serviceAccount': 'api'}


def described(**changes):
    result = {'associationId': 'pa-1', 'associationArn': ASSOC,
              'clusterName': 'sample', 'namespace': 'team',
              'serviceAccount': 'api', 'roleArn': ROLE,
              'disableSessionTags': False}
    result.update(changes)
    return {'association': result}


def collect(client):
    with patch('ScoutSuite.providers.aws.facade.eks_public.AWSFacadeUtils.get_client',
               return_value=client):
        return asyncio.run(EKSPublicFacade(SimpleNamespace(), ACCOUNT)
                           .get_pod_identity_associations('eu-central-1', 'sample'))


def role():
    return {'arn': ROLE, 'p4b_admin_policy_status': 'admin_policy_candidate',
            'assume_role_policy': {'PolicyDocument': {'Statement': [{
                'Effect': 'Allow',
                'Principal': {'Service': 'pods.eks.amazonaws.com'},
                'Action': ['sts:AssumeRole', 'sts:TagSession']}]}}}


def graph(assoc):
    cluster = {'cluster_arn': CLUSTER, 'oidc_issuer': None,
               'pod_identity_inventory_status': 'complete',
               'pod_identity_associations': {'pa-1': assoc}}
    services = {
        'iam': {'roles': {'r': role()}, 'users': {}, 'groups': {}, 'policies': {}},
        'eks': {'regions': {'eu-central-1': {'clusters': {'sample': cluster}}}},
    }
    paths = annotate_p5d_attack_paths(services, ['iam', 'eks'], ACCOUNT)
    return paths, cluster, services


def pod_edges(paths):
    return [e for e in paths['edges'].values() if e['type'] == 'eks_pod_identity']


def test_list_summary_never_contains_role_but_describe_resolves_it():
    class Client:
        def __init__(self):
            self.described = []
        def list_pod_identity_associations(self, **kwargs):
            return {'associations': [listed()]}
        def describe_pod_identity_association(self, **kwargs):
            self.described.append(kwargs)
            return described()
    client = Client()
    result = collect(client)
    assert result['status'] == 'complete'
    assert len(result['associations']) == 1
    assoc = result['associations'][0]
    assert assoc['role_arn'] == ROLE
    assert assoc['detail_collection_status'] == 'complete'
    assert assoc['session_policy_status'] == 'absent'
    assert client.described == [{'clusterName': 'sample', 'associationId': 'pa-1'}]
    paths, cluster, _ = graph(assoc)
    assert len(pod_edges(paths)) == 1  # OIDC is intentionally unavailable.
    assert cluster['p5d_workload_identity_status'] == 'candidate'


def test_pod_identity_restrictions_and_role_chaining_suppress_claim():
    class Client:
        def list_pod_identity_associations(self, **kwargs):
            return {'associations': [listed()]}
        def describe_pod_identity_association(self, **kwargs):
            return described(targetRoleArn=OTHER_ROLE, policy='{"Version":"2012-10-17"}')
    result = collect(Client())
    assert result['status'] == 'complete'
    assoc = result['associations'][0]
    assert assoc['target_role_arn'] == OTHER_ROLE
    assert assoc['session_policy_present'] is True
    assert 'policy' not in assoc
    paths, _, _ = graph(assoc)
    assert not pod_edges(paths)
    assoc['target_role_arn'] = None
    paths, _, _ = graph(assoc)
    assert not pod_edges(paths)  # Restrictive session policy still suppresses.


def test_pod_identity_list_only_incomplete_never_claims_role():
    class Client:
        def list_pod_identity_associations(self, **kwargs):
            return {'associations': [listed()]}
        def describe_pod_identity_association(self, **kwargs):
            raise PermissionError('Describe AccessDenied')
    result = collect(Client())
    assert result['status'] == 'partial'
    assert result['associations'][0]['role_arn'] is None
    assert result['associations'][0]['detail_collection_status'] == 'unknown'
    paths, cluster, _ = graph(result['associations'][0])
    assert not pod_edges(paths)
    assert cluster['p5d_workload_identity_status'] == 'unknown'


def test_description_wrong_namespace_and_cross_account_primary_fail_closed():
    class Client:
        def __init__(self, **updates):
            self.updates = updates
        def list_pod_identity_associations(self, **kwargs):
            return {'associations': [listed()]}
        def describe_pod_identity_association(self, **kwargs):
            return described(**self.updates)
    for change in ({'namespace': 'other'}, {'roleArn': OTHER_ROLE},
                   {'associationId': 'other'}):
        result = collect(Client(**change))
        assert result['status'] == 'partial'
        assert result['associations'][0]['role_arn'] is None


def test_list_pagination_and_duplicate_summary_are_not_accepted_as_complete():
    class Client:
        def list_pod_identity_associations(self, **kwargs):
            if not kwargs.get('nextToken'):
                return {'associations': [listed()], 'nextToken': 'next'}
            return {'associations': [listed()]}
        def describe_pod_identity_association(self, **kwargs):
            return described()
    result = collect(Client())
    assert result['status'] == 'partial'
    assert len(result['associations']) == 1
    assert result['associations'][0]['role_arn'] == ROLE


def test_list_denied_without_any_summary_remains_unknown_not_empty_pass():
    class Client:
        def list_pod_identity_associations(self, **kwargs):
            raise PermissionError('List AccessDenied')
    result = collect(Client())
    assert result['status'] == 'partial'
    assert result['associations'] == []


def test_p5d_edge_is_in_resource_and_eks_modal_projection():
    assoc = {'id': 'pa-1', 'role_arn': ROLE, 'namespace': 'team',
             'service_account': 'api', 'association_arn': ASSOC,
             'detail_collection_status': 'complete',
             'session_policy_present': False, 'target_role_arn': None}
    paths, cluster, services = graph(assoc)
    edge = pod_edges(paths)[0]
    assert cluster['p5d_attack_path_details'][0]['id'] == edge['id']
    target = services['iam']['roles']['r']
    assert target['p5d_attack_path_details'][0]['target'] == ROLE
    assert edge['effective_permission_verified'] is False
    assert edge['execution_verified'] is False


def test_finding_card_requires_status_and_matching_graph_witness():
    assoc = {'id': 'pa-1', 'role_arn': ROLE, 'namespace': 'team',
             'service_account': 'api', 'detail_collection_status': 'complete',
             'session_policy_present': False, 'target_role_arn': None}
    paths, cluster, services = graph(assoc)
    path = 'eks.regions.eu-central-1.clusters.sample'
    checks = build_observation_checks('p5d-eks-cluster-v1', cluster,
                                      services, path, 'insecure')
    assert len([c for c in checks if c['required'] and c['state'] == 'CONFIRMED']) == 2
    assert any('iam.attack_paths_p5d.edges.' in c['source'] for c in checks)
    checks = build_observation_checks('p5d-eks-cluster-v1', {
        **cluster, 'p5d_attack_path_details': []}, services, path, 'insecure')
    assert any(c['state'] == 'UNKNOWN' and c['required'] for c in checks)
    # Graph without an edge must not be labelled high-confidence or confirmed.
    services['iam']['attack_paths_p5d']['edges'].clear()
    checks = build_observation_checks('p5d-eks-cluster-v1', cluster, services, path, 'insecure')
    assert any(c['state'] == 'UNKNOWN' and c['required'] for c in checks)


def test_external_invoke_is_low_confidence_review_not_escalation():
    rule = SimpleNamespace(evidence_policy='p5d-external-invoke-review-v1')
    finding = {'flagged_items': 1, 'evaluation_summary': {
        'counts': {'secure': 0, 'insecure': 1, 'unknown': 0, 'not_applicable': 0},
        'observations': []}}
    assessed = build_finding_confidence(rule, finding)
    assert assessed['claim_type'] == 'RESOURCE_POLICY_REVIEW'
    assert assessed['verification_status'] == 'REVIEW'
    assert assessed['confidence'] == 'LOW'
    assert assessed['effective_permission_verified'] is False


def test_attack_path_ui_uses_escaped_fields_without_unsafe_html_insertion():
    root = Path(__file__).resolve().parents[1]
    panel = (root / 'ScoutSuite/output/data/html/partials/aws/p5d.attack_paths.html').read_text()
    for marker in ('{{source}}', '{{target}}', '{{action}}', '{{basis}}',
                   '{{confidence}}', '{{verification}}', '{{id}}'):
        assert marker in panel
    assert '{{{' not in panel
    assert 'innerHTML' not in panel
    assert '<script' in panel
    for name in ('services.iam.roles', 'services.iam.users',
                 'services.eks.regions.id.clusters', 'services.s3.buckets',
                 'services.kms.regions.id.keys',
                 'services.s3.advanced.regions.id.access_points',
                 'services.awslambda.regions.id.functions'):
        template = (root / ('ScoutSuite/output/data/html/partials/aws/' + name + '.html')).read_text()
        assert '{{> p5d.attack_paths}}' in template
