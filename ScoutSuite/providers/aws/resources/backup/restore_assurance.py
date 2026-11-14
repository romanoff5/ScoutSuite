"""Evidence-limited AWS Backup restore testing observations, not RTO/SLA certification.

AWS Backup restore jobs are only available for a limited history window
(typically 30 days). A recent successful restore does not prove application
validation or contractual recovery objectives were achieved.
"""
from datetime import datetime, timezone

MAX_EXECUTION_AGE_DAYS = 45


def _instant(value):
    if isinstance(value, datetime):
        stamp = value
    elif isinstance(value, str) and value:
        try:
            stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            return None
    else:
        return None
    return stamp.replace(tzinfo=timezone.utc) if stamp.tzinfo is None else stamp.astimezone(timezone.utc)


def assess_restore_testing_plan(plan, jobs, collection_status, now=None):
    """Compute only outcomes supported by a complete per-plan job inventory."""
    result = {
        'latest_restore_job_status': 'unknown',
        'latest_validation_status': 'unknown',
        'restore_testing_schedule_status': 'unknown',
        'last_observed_restore_job_id': None,
        'last_observed_restore_duration_minutes': None,
        'rto_assessment_status': 'not_evaluated_no_threshold',
        'restore_assurance_basis': 'recent_job_history_only',
    }
    if not isinstance(plan, dict) or not isinstance(jobs, list):
        return result
    now = _instant(now) or datetime.now(timezone.utc)
    created, last = _instant(plan.get('CreationTime')), _instant(plan.get('LastExecutionTime'))
    if last is not None and now >= last:
        age = (now - last).total_seconds() / 86400
        result['restore_testing_schedule_status'] = (
            'stale' if age > MAX_EXECUTION_AGE_DAYS else 'recent')
    elif last is None and created is not None and now >= created:
        age = (now - created).total_seconds() / 86400
        result['restore_testing_schedule_status'] = (
            'never_executed_stale' if age > MAX_EXECUTION_AGE_DAYS else
            'not_yet_due')
    if collection_status != 'complete':
        return result
    if not jobs:
        result['latest_restore_job_status'] = 'no_observed_jobs'
        return result
    candidates = []
    for item in jobs:
        if not isinstance(item, dict) or not isinstance(item.get('RestoreJobId'), str):
            return result
        created_at = _instant(item.get('CreationDate'))
        if created_at is None:
            return result
        candidates.append((created_at, item['RestoreJobId'], item))
    latest = max(candidates, key=lambda row: (row[0], row[1]))[2]
    result['last_observed_restore_job_id'] = latest['RestoreJobId']
    state = latest.get('Status')
    if state in ('FAILED', 'ABORTED'):
        result['latest_restore_job_status'] = 'failed'
    elif state == 'COMPLETED':
        result['latest_restore_job_status'] = 'completed'
    elif state in ('PENDING', 'RUNNING'):
        result['latest_restore_job_status'] = 'in_progress'
    validation = latest.get('ValidationStatus')
    if state == 'COMPLETED':
        result['latest_validation_status'] = (
            'failed' if validation in ('FAILED', 'TIMED_OUT') else
            'successful' if validation == 'SUCCESSFUL' else 'unknown')
        started = _instant(latest.get('CreationDate'))
        finished = _instant(latest.get('CompletionDate'))
        if started is not None and finished is not None and finished >= started:
            result['last_observed_restore_duration_minutes'] = round(
                (finished - started).total_seconds() / 60, 2)
    return result
