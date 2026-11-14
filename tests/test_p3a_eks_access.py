"""P3-A read-only source-to-finding tests using production Scout Suite rule traversal."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ScoutSuite.core.utils import recurse
from ScoutSuite.core.rule_evidence import evaluate_rule_evidence
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils

ROOT = Path(__file__).resolve().parents[1] / 'ScoutSuite/providers/aws/rules/findings'
REGION = 'eu-central-1'


def rule_result(filename, services):
    raw = json.loads((ROOT / filename).read_text(encoding='utf-8'))
    rule = SimpleNamespace(filename=filename, path=raw['path'],
                           conditions=raw['conditions'],
                           evidence_policy=raw['evidence_policy'],
                           checked_items=0)
    hits = recurse(services, services, rule.path.split('.'), [], rule, True)
    return hits, evaluate_rule_evidence(rule, services)

from ScoutSuite.providers.aws.facade.eks_public import EKSPublicFacade
from ScoutSuite.providers.aws.resources.eks_public.clusters import Clusters
from ScoutSuite.providers.aws.resources.eks_public.access_review import classify_eks_cluster_admin

CLUSTER_POLICY = 'arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy'
ADMIN_POLICY = 'arn:aws:eks::aws:cluster-access-policy/AmazonEKSAdminPolicy'
READ_ONLY = 'arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy'
PRINCIPAL = 'arn:aws:iam::123456789012:role/security-admin'


def client(policy=CLUSTER_POLICY, scope='cluster'):
    return SimpleNamespace(
        list_access_entries=lambda **kwargs: {'accessEntries': [PRINCIPAL]},
        list_associated_access_policies=lambda **kwargs: {
            'associatedAccessPolicies': [
                {'policyArn': policy, 'accessScope': {'type': scope}}]})


def test_eks_api_access_grants_and_scope():
    facade = EKSPublicFacade(object(), '123456789012')
    with patch.object(AWSFacadeUtils, 'get_client', return_value=client()):
        result = asyncio.run(facade.get_access_entries(REGION, 'alpha', 'API'))
    assert result['status'] == 'complete'
    assert classify_eks_cluster_admin(result['entries'][0]['policies'],
                                      result['entries'][0]['policy_collection_status']) == 'cluster_admin'
    for policy,scope,expected in [(ADMIN_POLICY,'cluster','admin'),
                                  (CLUSTER_POLICY,'namespace','not_detected'),
                                  (READ_ONLY,'cluster','not_detected')]:
        with patch.object(AWSFacadeUtils, 'get_client', return_value=client(policy, scope)):
            data = asyncio.run(facade.get_access_entries(REGION, 'alpha', 'API_AND_CONFIG_MAP'))
        assert classify_eks_cluster_admin(data['entries'][0]['policies'],
                                          data['entries'][0]['policy_collection_status']) == expected


def test_eks_config_map_not_inappropriately_cleared():
    facade = EKSPublicFacade(object(), '123456789012')
    assert asyncio.run(facade.get_access_entries(
        REGION, 'alpha', 'CONFIG_MAP')) == {'status': 'not_applicable', 'entries': []}
    assert asyncio.run(facade.get_access_entries(REGION, 'alpha', None))['status'] == 'unknown'


def test_eks_denied_policy_lookup_is_unknown_and_not_flagged():
    c = client()
    c.list_associated_access_policies = lambda **kw: (_ for _ in ()).throw(
        PermissionError('denied'))
    facade = EKSPublicFacade(object(), '123456789012')
    with patch.object(AWSFacadeUtils, 'get_client', return_value=c):
        result = asyncio.run(facade.get_access_entries(REGION, 'alpha', 'API'))
    assert result['status'] == 'partial'
    assert result['entries'][0]['policy_collection_status'] == 'partial'
    assert classify_eks_cluster_admin(result['entries'][0]['policies'], 'partial') == 'unknown'


def test_eks_real_cluster_normalization_and_admin_finding():
    async def get_clusters(region):
        return [{'arn': f'arn:aws:eks:{REGION}:123456789012:cluster/alpha',
                 'name': 'alpha', 'resourcesVpcConfig': {
                     'endpointPublicAccess': False},
                 'accessConfig': {'authenticationMode': 'API_AND_CONFIG_MAP'}}]
    async def entry_result(region, cluster, mode):
        return {'status': 'complete', 'entries': [{
            'principal_arn': PRINCIPAL, 'policy_collection_status': 'complete',
            'policies': [{'policy_arn': CLUSTER_POLICY, 'scope': 'cluster'}]}]}
    resources = Clusters.__new__(Clusters)
    resources.region = REGION
    resources.facade = SimpleNamespace(eks=SimpleNamespace(
        get_clusters=get_clusters, get_access_entries=entry_result))
    asyncio.run(resources.fetch_all())
    cluster = next(iter(resources.values()))
    assert cluster['access_entry_inventory_status'] == 'complete'
    assert cluster['access_authentication_mode'] == 'API_AND_CONFIG_MAP'
    services = {'eks': {'regions': {REGION: {'clusters': dict(resources)}}}}
    hits, evidence = rule_result('eks-access-entry-cluster-admin.json', services)
    assert len(hits) == 1
    assert evidence['counts']['insecure'] == 1
    hits, evidence = rule_result('eks-access-entry-cluster-wide-admin.json', services)
    assert hits == [] and evidence['counts']['not_applicable'] == 1


def test_eks_access_entry_incomplete_is_unknown_in_rule():
    async def get_clusters(region):
        return [{'arn': 'arn:aws:eks:eu-central-1:123456789012:cluster/alpha',
                 'name': 'alpha',
                 'accessConfig': {'authenticationMode': 'API'}}]
    async def entry_result(region, cluster, mode):
        return {'status': 'partial', 'entries': [{
            'principal_arn': PRINCIPAL, 'policy_collection_status': 'partial',
            'policies': []}]}
    resources = Clusters.__new__(Clusters)
    resources.region = REGION
    resources.facade = SimpleNamespace(eks=SimpleNamespace(
        get_clusters=get_clusters, get_access_entries=entry_result))
    asyncio.run(resources.fetch_all())
    services = {'eks': {'regions': {REGION: {'clusters': dict(resources)}}}}
    hits, evidence = rule_result('eks-access-entry-cluster-admin.json', services)
    assert hits == [] and evidence['counts']['unknown'] == 1
