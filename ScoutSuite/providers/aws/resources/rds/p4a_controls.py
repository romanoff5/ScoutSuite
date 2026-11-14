"""RDS standalone observability/auth controls; partial data cannot become PASS."""
IAM_AUTH_ENGINES = frozenset(('mysql', 'mariadb', 'postgres', 'aurora-mysql', 'aurora-postgresql'))


def classify_rds_instance_controls(raw):
    fields = ('enhanced_monitoring_status', 'detailed_query_metrics_status',
              'iam_db_auth_status', 'monitoring_auth_baseline_status')
    unknown = dict.fromkeys(fields, 'unknown')
    if not isinstance(raw, dict):
        return unknown
    status = raw.get('DBInstanceStatus')
    if status in ('stopped', 'stopping', 'deleting', 'deleted'):
        return dict.fromkeys(fields, 'not_applicable')
    if status not in ('available', 'backing-up', 'modifying', 'storage-optimization'):
        return unknown
    membership = raw.get('DBClusterIdentifier')
    if isinstance(membership, str) and membership:
        return dict.fromkeys(fields, 'not_applicable')
    if membership is not None:
        return unknown
    interval = raw.get('MonitoringInterval')
    monitoring = ('enabled' if type(interval) is int and interval > 0 else
                  'disabled' if type(interval) is int and interval == 0 else 'unknown')
    mode = raw.get('DatabaseInsightsMode')
    pi = raw.get('PerformanceInsightsEnabled')
    detail = ('enabled' if mode == 'advanced' or pi is True else
              'disabled' if mode in (None, 'standard') and pi is False else 'unknown')
    engine = raw.get('Engine')
    iam_auth = raw.get('IAMDatabaseAuthenticationEnabled')
    auth = ('not_applicable' if isinstance(engine, str) and engine not in IAM_AUTH_ENGINES else
            'enabled' if engine in IAM_AUTH_ENGINES and iam_auth is True else
            'disabled' if engine in IAM_AUTH_ENGINES and iam_auth is False else 'unknown')
    states = (monitoring, detail, auth)
    composite = ('not_applicable' if auth == 'not_applicable' else
                 'all_disabled' if all(s == 'disabled' for s in states) else
                 'not_all_disabled' if any(s == 'enabled' for s in states) else 'unknown')
    return dict(zip(fields, (monitoring, detail, auth, composite)))
