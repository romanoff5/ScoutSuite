"""P3-A read-only RDS Proxy backend health: configuration evidence, not SLA proof."""


def classify_proxy_targets(proxy_status, collection, targets):
    """Only a fully enumerated target set can prove empty/degraded/healthy."""
    if not isinstance(collection, dict) or collection.get('status') != 'complete':
        return 'unknown'
    if not isinstance(proxy_status, str) or proxy_status.lower() != 'available':
        return 'not_applicable' if proxy_status in ('deleting', 'deleted') else 'unknown'
    targets = collection.get('targets')
    if not isinstance(targets, list):
        return 'unknown'
    if not targets:
        return 'no_targets'
    states = []
    for target in targets:
        if not isinstance(target, dict):
            return 'unknown'
        health = target.get('TargetHealth')
        state = health.get('State') if isinstance(health, dict) else None
        if state not in ('AVAILABLE', 'UNAVAILABLE', 'REGISTERING', 'UNUSED'):
            return 'unknown'
        states.append(state)
    if all(state == 'UNAVAILABLE' for state in states):
        return 'all_unavailable'
    if all(state == 'AVAILABLE' for state in states):
        return 'healthy'
    if 'AVAILABLE' in states and 'UNAVAILABLE' in states:
        return 'degraded'
    return 'transitioning'


def summarize_proxy_targets(collection):
    """Persist only non-secret identifiers and AWS state/reason, never descriptions."""
    targets = collection.get('targets') if isinstance(collection, dict) else None
    if not isinstance(targets, list):
        return []
    return [
        {
            'target_arn': item.get('TargetArn'),
            'rds_resource_id': item.get('RdsResourceId'),
            'type': item.get('Type'),
            'role': item.get('Role'),
            'health_state': item.get('TargetHealth', {}).get('State'),
            'health_reason': item.get('TargetHealth', {}).get('Reason'),
        }
        for item in targets if isinstance(item, dict)
        and isinstance(item.get('TargetHealth'), dict)
    ]
