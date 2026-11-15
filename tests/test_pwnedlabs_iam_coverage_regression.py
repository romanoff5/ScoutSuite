"""Regressions derived from the 2026-11-15 PwnedLabs partial AWS scan.

Synthetic operation counters only: no account IDs, ARNs, keys or raw reports.
"""
import asyncio
from types import SimpleNamespace

import pytest

from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.coverage_matrix import build_aws_coverage_matrix
from ScoutSuite.providers.aws.resources.iam.base import IAM
from ScoutSuite.providers.aws.resources.iam.collection_completeness import (
    IDENTITY_LISTS, iam_identity_inventory,
)
from ScoutSuite.providers.aws.resources.iam.attack_paths_p5d import (
    annotate_p5d_attack_paths,
)


REQUIRED = tuple(IDENTITY_LISTS.values())


def context_with(*outcomes):
    ctx = RunContext(provider='aws')
    for operation, outcome in outcomes:
        ctx.record_aws_api('iam', 'global', operation, outcome)
    return ctx


def census(ctx):
    return iam_identity_inventory(ctx)


@pytest.mark.parametrize('denied', REQUIRED)
def test_single_denied_listing_never_proves_empty_iam_graph(denied):
    ctx = context_with(*[(op, 'denied' if op == denied else 'success')
                         for op in REQUIRED])
    observed = census(ctx)
    assert observed['status'] == 'partial'
    assert observed['components'][next(key for key, value in
        IDENTITY_LISTS.items() if value == denied)] == 'denied'
    iam = IAM(SimpleNamespace(iam=SimpleNamespace(), partition='aws'))
    iam.update({'roles': {}, 'users': {}, 'groups': {}, 'policies': {}})
    with ctx.lifecycle():
        asyncio.run(iam.finalize())
    assert iam['identity_inventory']['status'] == 'partial'
    assert iam['relationship_graph']['status'] != 'complete'
    services = {'iam': iam}
    annotate_p5d_attack_paths(services, ['iam'], '123456789012')
    attack = iam['attack_paths_p5d']
    assert attack['collection']['iam'] == 'partial'
    assert attack['status'] != 'complete'
    assert (attack['nodes_count'], attack['edges_count']) == (0, 0)


def test_all_denied_and_unobserved_have_separate_unknown_states():
    denied = context_with(*[(op, 'denied') for op in REQUIRED])
    assert census(denied)['status'] == 'denied'
    assert census(RunContext(provider='aws'))['status'] == 'unknown'
    services = {'iam': {'roles': {}, 'users': {}, 'groups': {},
                        'policies': {}, 'identity_inventory': census(denied)}}
    annotate_p5d_attack_paths(services, ['iam'], '123456789012')
    assert services['iam']['attack_paths_p5d']['collection']['iam'] == 'denied'
    assert services['iam']['attack_paths_p5d']['status'] == 'unknown'


def test_genuine_empty_census_requires_four_successful_operations():
    ctx = context_with(*[(op, 'success') for op in REQUIRED])
    assert census(ctx)['status'] == 'complete'
    iam = IAM(SimpleNamespace(iam=SimpleNamespace(), partition='aws'))
    iam.update({'roles': {}, 'users': {}, 'groups': {}, 'policies': {}})
    with ctx.lifecycle():
        asyncio.run(iam.finalize())
    assert iam['relationship_graph']['status'] == 'complete'
    annotate_p5d_attack_paths({'iam': iam}, ['iam'], '123456789012')
    assert iam['attack_paths_p5d']['collection']['iam'] == 'complete'


@pytest.mark.parametrize('later', ('denied', 'failed'))
def test_later_page_failure_after_success_is_partial(later):
    ctx = context_with(*[(op, 'success') for op in REQUIRED],
                       ('ListRoles', later))
    assert census(ctx)['components']['roles'] == 'partial'
    assert census(ctx)['status'] == 'partial'


def test_policy_version_failure_and_paginator_issue_fail_closed():
    ctx = context_with(*[(op, 'success') for op in REQUIRED],
                       ('GetPolicyVersion', 'denied'))
    assert census(ctx)['components']['policies'] == 'partial'
    ctx = context_with(*[(op, 'success') for op in REQUIRED])
    ctx.record_collection_issue('failed', 'iam', 'MalformedPage')
    assert census(ctx)['status'] == 'partial'


def test_credential_report_denied_does_not_mask_verified_identity_enumeration():
    ctx = context_with(*[(op, 'success') for op in REQUIRED],
                       ('GenerateCredentialReport', 'denied'))
    result = census(ctx)
    assert result['status'] == 'complete'
    assert result['credential_report_status'] == 'denied'
    assert result['complete']


def test_rule_display_names_do_not_generate_phantom_skipped_rows():
    ctx = context_with(('ListRoles', 'denied'))
    services = {'iam': {'roles': {}, 'users': {}, 'groups': {}, 'policies': {}},
                'awslambda': {'regions': {'us-east-1': {}}},
                'secretsmanager': {'regions': {'us-east-1': {}}},
                'ssm': {'regions': {'us-east-1': {}}}}
    matrix = build_aws_coverage_matrix(
        ['iam', 'awslambda', 'secretsmanager', 'ssm'], services, ctx,
        requested_regions=['us-east-1'],
        enabled_rule_counts={'IAM': 3, 'iam': 2, 'Lambda': 4,
                             'awslambda': 2, 'Secrets Manager': 5,
                             'Systems Manager': 7})
    assert matrix['rows_count'] == 4
    assert len({(r['service'], r['region']) for r in matrix['rows']}) == 4
    assert {row['service'] for row in matrix['rows']} == set(services)
    assert all(row['status'] != 'SKIPPED' for row in matrix['rows'])
    assert all(row['skipped_checks'] == 0 for row in matrix['rows'])
    assert next(r for r in matrix['rows'] if r['service'] == 'iam')['status'] == 'DENIED'


def test_explicit_skip_aliases_are_preserved_and_rule_counts_aggregated():
    ctx = RunContext(provider='aws')
    matrix = build_aws_coverage_matrix(
        ['EC2'], {'ec2': {'regions': {'us-east-1': {}}}}, ctx,
        skipped_services=['S3'], requested_regions=['us-east-1'],
        enabled_rule_counts={'S3': 7, 's3': 4, 'EC2': 2})
    assert matrix['rows_count'] == 2
    assert next(r for r in matrix['rows'] if r['service'] == 's3')[
        'skipped_checks'] == 11
    assert next(r for r in matrix['rows'] if r['service'] == 's3')[
        'status'] == 'SKIPPED'
    assert next(r for r in matrix['rows'] if r['service'] == 'ec2')[
        'status'] != 'SKIPPED'
