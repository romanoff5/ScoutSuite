"""Detailed EC2 CloudWatch monitoring is a running-instance governance review."""
def classify_detailed_monitoring(raw):
    if not isinstance(raw, dict):
        return 'unknown'
    lifecycle = raw.get('State')
    state = lifecycle.get('Name') if isinstance(lifecycle, dict) else None
    if state in ('stopped', 'stopping', 'shutting-down', 'terminated'):
        return 'not_applicable'
    if state != 'running':
        return 'unknown'
    monitoring = raw.get('Monitoring')
    mode = monitoring.get('State') if isinstance(monitoring, dict) else None
    return 'detailed' if mode == 'enabled' else 'basic' if mode == 'disabled' else 'unknown'
