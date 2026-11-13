"""Conservative, read-only CloudWatch security metric-filter alarm correlation.

No local CloudWatch metric-filter alarm proves absence of coverage from an
organization account, EventBridge, or external SIEM. Nor does a configured alarm
prove successful notification delivery.
"""


def _transform_pairs(metric_filter):
    """Return metric namespace/name pairs; None for incomplete transformations."""
    if not isinstance(metric_filter, dict):
        return None
    raw = metric_filter.get('metric_transformations')
    if not isinstance(raw, list) or not raw:
        return None
    pairs = set()
    for item in raw:
        if not isinstance(item, dict):
            return None
        namespace, name = item.get('metricNamespace'), item.get('metricName')
        if not isinstance(namespace, str) or not namespace:
            return None
        if not isinstance(name, str) or not name:
            return None
        pairs.add((namespace, name))
    return pairs


def _alarm_pairs(alarm):
    """Simple alarms only; metric-math expression correlation needs manual review."""
    if not isinstance(alarm, dict) or alarm.get('Metrics') is not None:
        return None
    namespace, name = alarm.get('Namespace'), alarm.get('MetricName')
    if not isinstance(namespace, str) or not namespace:
        return None
    if not isinstance(name, str) or not name:
        return None
    return {(namespace, name)}


def assess_security_metric_alerting(filters, alarms):
    """Return missing, unlinked_security_filters, review_required, or unrecognized_filter_patterns."""
    if not isinstance(filters, dict) or not isinstance(alarms, dict):
        return 'unknown'
    # Explicitly empty, completely collected inventories are a meaningful gap.
    if not filters or not alarms:
        return 'missing'
    actions = []
    unverified_alarm = False
    for alarm in alarms.values():
        if not isinstance(alarm, dict):
            return 'unknown'
        enabled, targets = alarm.get('ActionsEnabled'), alarm.get('AlarmActions')
        if not isinstance(enabled, bool) or not isinstance(targets, list):
            unverified_alarm = True
            continue
        if enabled and any(isinstance(target, str) and target for target in targets):
            actions.append(alarm)
    if not actions:
        return 'review_required' if unverified_alarm else 'missing'

    recognized = []
    for metric_filter in filters.values():
        if not isinstance(metric_filter, dict):
            return 'unknown'
        categories = metric_filter.get('security_pattern_categories', [])
        if not isinstance(categories, list):
            return 'unknown'
        if categories:
            recognized.append(metric_filter)
    if not recognized:
        # Exact-string patterns are only a known subset of equivalent valid
        # CloudWatch filter syntax; never call unrecognized syntax a missing filter.
        return 'unrecognized_filter_patterns'

    pairs = set()
    for metric_filter in recognized:
        transformation = _transform_pairs(metric_filter)
        if transformation is None:
            return 'review_required'
        pairs.update(transformation)
    for alarm in actions:
        alarm_metrics = _alarm_pairs(alarm)
        if alarm_metrics is None:
            return 'review_required'
        if pairs.intersection(alarm_metrics):
            return 'review_required'  # Configured chain; delivery still unverified.
    if unverified_alarm:
        return 'review_required'
    return 'unlinked_security_filters'
