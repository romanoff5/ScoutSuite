"""P3-A Backup restore testing: status, validation, recency and incomplete evidence."""
import asyncio
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from types import SimpleNamespace

from ScoutSuite.core.utils import recurse
from ScoutSuite.core.rule_evidence import evaluate_rule_evidence
from ScoutSuite.providers.aws.facade.backup import BoundedResults
from ScoutSuite.providers.aws.resources.backup.base import BackupPublic
from ScoutSuite.providers.aws.resources.backup.restore_assurance import (
    assess_restore_testing_plan)

ROOT = Path(__file__).resolve().parents[1] / 'ScoutSuite/providers/aws/rules/findings'
REGION = 'eu-central-1'
PLAN_ARN = 'arn:aws:backup:eu-central-1:123456789012:restore-testing-plan:alpha'
NOW = datetime(2026, 11, 14, tzinfo=timezone.utc)


def plan(created_days=90, last_days=2):
    p = {'RestoreTestingPlanArn': PLAN_ARN,
         'RestoreTestingPlanName': 'alpha',
         'CreationTime': (NOW-timedelta(days=created_days)).isoformat(),
         'selection_collection_complete': True}
    if last_days is not None:
        p['LastExecutionTime'] = (NOW-timedelta(days=last_days)).isoformat()
    return p


def job(state='COMPLETED', validation=None, age=1, job_id='job1'):
    row = {'RestoreJobId': job_id, 'Status': state,
           'CreationDate': (NOW-timedelta(days=age)).isoformat(),
           'CompletionDate': (NOW-timedelta(days=age)+timedelta(minutes=183)).isoformat(),
           'CreatedBy': {'RestoreTestingPlanArn': PLAN_ARN},
           'SourceResourceArn': 'arn:aws:rds:eu-central-1:123456789012:db:db1'}
    if validation is not None:
        row['ValidationStatus'] = validation
    return row


def rule_result(filename, data):
    raw = json.loads((ROOT / filename).read_text(encoding='utf-8'))
    rule = SimpleNamespace(filename=filename, path=raw['path'],
                           conditions=raw['conditions'], checked_items=0,
                           evidence_policy=raw['evidence_policy'])
    services = {'backup': {'regions': {REGION: {
        'restore_testing_plans': {'p': data}}}}}
    matches = recurse(services, services, rule.path.split('.'), [], rule, True)
    return matches, evaluate_rule_evidence(rule, services)


def test_failed_latest_restore_outcome_and_complete_rule():
    report = assess_restore_testing_plan(plan(), [
        job('COMPLETED', 'SUCCESSFUL', age=4, job_id='old'),
        job('FAILED', age=1, job_id='recent')], 'complete', now=NOW)
    assert report['latest_restore_job_status'] == 'failed'
    assert report['last_observed_restore_job_id'] == 'recent'
    assert report['latest_validation_status'] == 'unknown'
    hits, evidence = rule_result('backup-restore-testing-latest-job-failed.json', report)
    assert len(hits) == 1 and evidence['counts']['insecure'] == 1


def test_validation_failure_and_duration_are_separate_from_rto():
    report = assess_restore_testing_plan(plan(), [
        job('COMPLETED', 'FAILED')], 'complete', now=NOW)
    assert report['latest_restore_job_status'] == 'completed'
    assert report['latest_validation_status'] == 'failed'
    assert report['last_observed_restore_duration_minutes'] == 183
    assert report['rto_assessment_status'] == 'not_evaluated_no_threshold'
    hits, evidence = rule_result('backup-restore-testing-latest-validation-failed.json', report)
    assert len(hits) == 1 and evidence['counts']['insecure'] == 1
    report = assess_restore_testing_plan(plan(), [
        job('COMPLETED', 'SUCCESSFUL')], 'complete', now=NOW)
    hits, evidence = rule_result('backup-restore-testing-latest-validation-failed.json', report)
    assert hits == [] and evidence['counts']['secure'] == 1


def test_stale_and_never_executed_45_day_review_rules():
    for value in (plan(last_days=60), plan(last_days=None)):
        report = assess_restore_testing_plan(value, [], 'complete', now=NOW)
        assert report['restore_testing_schedule_status'] in ('stale','never_executed_stale')
        hits, evidence = rule_result('backup-restore-testing-stale-execution.json', report)
        assert len(hits) == 1 and evidence['counts']['insecure'] == 1
    current = assess_restore_testing_plan(plan(last_days=1), [], 'complete', now=NOW)
    assert current['latest_restore_job_status'] == 'no_observed_jobs'
    assert current['restore_testing_schedule_status'] == 'recent'
    hits, evidence = rule_result('backup-restore-testing-latest-job-failed.json', current)
    assert hits == [] and evidence['counts']['unknown'] == 1
    new = assess_restore_testing_plan(plan(created_days=1, last_days=None), [],
                                      'complete', now=NOW)
    assert new['restore_testing_schedule_status'] == 'not_yet_due'


def test_partial_restore_history_does_not_claim_latest_job_failed_or_successful():
    report = assess_restore_testing_plan(plan(), [job('FAILED')], 'partial', now=NOW)
    assert report['latest_restore_job_status'] == 'unknown'
    assert report['latest_validation_status'] == 'unknown'
    hits, evidence = rule_result('backup-restore-testing-latest-job-failed.json', report)
    assert hits == [] and evidence['counts']['unknown'] == 1


def test_actual_backup_resource_enrichment_and_rule():
    # Drive the real BackupPublic regional enrichment, not just a test helper.
    now = datetime.now(timezone.utc)
    current = {
        'RestoreTestingPlanArn': PLAN_ARN,
        'RestoreTestingPlanName': 'alpha',
        'LastExecutionTime': (now-timedelta(days=2)).isoformat(),
        'CreationTime': (now-timedelta(days=100)).isoformat(),
        'selection_collection_complete': True, 'selections': []}
    failed = job('FAILED')
    failed['CreationDate'] = (now-timedelta(days=1)).isoformat()
    async def protected(region):
        return BoundedResults([{
            'ResourceArn': 'arn:aws:rds:eu-central-1:123456789012:db:db1'}])
    async def backup_jobs(region):
        return BoundedResults([])
    async def restore_jobs(region):
        return BoundedResults([failed])
    async def testing_plans(region):
        return BoundedResults([current])
    facade = SimpleNamespace(backup=SimpleNamespace(
        get_protected_resources=protected,
        get_backup_jobs=backup_jobs,
        get_restore_jobs=restore_jobs,
        get_restore_testing_plans=testing_plans,
        discovery_complete={REGION: {'plans': True, 'vaults': True}}))
    resource = BackupPublic.__new__(BackupPublic)
    resource.facade = facade
    region_data = {'vaults': {}, 'plans': {}}
    asyncio.run(resource._enrich_region(REGION, region_data))
    assert region_data['backup_inventory_status']['restore_jobs'] == 'complete'
    values = list(region_data['restore_testing_plans'].values())
    assert len(values) == 1
    assert values[0]['latest_restore_job_status'] == 'failed'
    services = {'backup': {'regions': {REGION: region_data}}}
    raw = json.loads((ROOT / 'backup-restore-testing-latest-job-failed.json').read_text())
    rule = SimpleNamespace(filename='backup-restore-testing-latest-job-failed.json',
                           path=raw['path'], conditions=raw['conditions'],
                           evidence_policy=raw['evidence_policy'], checked_items=0)
    hits = recurse(services, services, rule.path.split('.'), [], rule, True)
    assert len(hits) == 1
    assert evaluate_rule_evidence(rule, services)['counts']['insecure'] == 1
