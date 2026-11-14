"""P3-D: regional RDS monitoring evidence for DB instances and clusters.

This only evaluates CloudWatch metric alarms and RDS SNS event subscriptions
visible in the audited account/Region. EventBridge, external SIEM, Datadog,
cross-account alarms and SNS deliverability are NOT verified.
"""


def _metrics(alarm):
    if not isinstance(alarm, dict):
        return [], True
    entries, ambiguous = [], False
    if alarm.get('Namespace') == 'AWS/RDS':
        entries.append((alarm.get('Dimensions'), alarm.get('MetricName')))
    queries = alarm.get('Metrics', [])
    if not isinstance(queries, list):
        return entries, True
    for query in queries:
        if not isinstance(query, dict):
            ambiguous = True
            continue
        pair = query.get('MetricStat')
        if isinstance(pair, dict) and isinstance(pair.get('Metric'), dict):
            metric = pair['Metric']
            if metric.get('Namespace') == 'AWS/RDS':
                entries.append((metric.get('Dimensions'), metric.get('MetricName')))
        expression = query.get('Expression')
        if isinstance(expression, str) and 'AWS/RDS' in expression:
            ambiguous = True
    return entries, ambiguous


def _alarm_for_database(alarm, ident, dimension):
    entries, unknown = _metrics(alarm)
    relevant = False
    for dims, _metric in entries:
        if not isinstance(dims, list):
            unknown = True
            continue
        if any(not isinstance(row, dict) for row in dims):
            unknown = True
            continue
        if any(row.get('Name') == dimension and row.get('Value') == ident for row in dims):
            relevant = True
    return relevant, unknown


def _alarm_status(alarms, inventory_status, ident, dimension):
    if inventory_status != 'complete' or not isinstance(alarms, dict):
        return 'unknown', []
    found, uncertain = [], False
    for alarm in alarms.values():
        relevant, unknown = _alarm_for_database(alarm, ident, dimension)
        uncertain |= unknown
        if not relevant:
            continue
        actions = alarm.get('AlarmActions')
        enabled = alarm.get('ActionsEnabled')
        status = ('actionable' if enabled is True and isinstance(actions, list) and actions
                  else 'non_actionable' if enabled is False or isinstance(actions, list) and not actions
                  else 'unknown')
        if status == 'unknown':
            uncertain = True
        found.append({
            'name': alarm.get('name'), 'arn': alarm.get('arn'),
            'metric': alarm.get('MetricName'), 'namespace': alarm.get('Namespace'),
            'dimensions': alarm.get('Dimensions'), 'actions_enabled': enabled,
            'alarm_actions': actions, 'classification': status
        })
    if any(x['classification'] == 'actionable' for x in found):
        return 'actionable', found
    if uncertain:
        return 'unknown', found
    if found:
        return 'no_action', found
    return 'missing', []


def _event_status(subscriptions, inventory_status, ident, kind):
    if inventory_status != 'complete' or not isinstance(subscriptions, list):
        return 'unknown', []
    found, uncertain = [], False
    for item in subscriptions:
        if not isinstance(item, dict):
            uncertain = True
            continue
        source_type = item.get('SourceType')
        if source_type is None:
            uncertain = True
            continue
        if source_type != kind:
            continue
        ids = item.get('SourceIds')
        if ids is not None and not isinstance(ids, list):
            uncertain = True
            continue
        if ids and ident not in ids:
            continue
        enabled = item.get('Enabled')
        state = item.get('Status')
        if type(enabled) is not bool or not isinstance(state, str):
            uncertain = True
            continue
        classification = ('active' if enabled and state.lower() == 'active'
                          else 'inactive' if not enabled or state.lower() in
                          ('deleting', 'creating', 'modifying') else 'unknown')
        if classification == 'unknown':
            uncertain = True
        found.append({
            'id': item.get('CustSubscriptionId'), 'arn': item.get('EventSubscriptionArn'),
            'sns_topic_arn': item.get('SnsTopicArn'),
            'source_type': source_type, 'source_ids': ids,
            'enabled': enabled, 'status': state,
            'event_categories': item.get('EventCategoriesList'),
            'classification': classification
        })
    if any(x['classification'] == 'active' for x in found):
        return 'active', found
    if uncertain:
        return 'unknown', found
    if found:
        return 'inactive', found
    return 'missing', []


def correlate_rds_monitoring(services, selected):
    rds = (services.get('rds') or {}).get('regions') or {}
    cw = ((services.get('cloudwatch') or {}).get('regions') or {}) if 'cloudwatch' in selected else {}
    for region_name, region in rds.items():
        cw_region = cw.get(region_name)
        alarms = cw_region.get('alarms') if isinstance(cw_region, dict) else None
        alarms_status = (cw_region.get('metric_alarms_collection_status')
                         if isinstance(cw_region, dict) else 'unknown')
        subscriptions = region.get('event_subscriptions')
        subscriptions_status = region.get('event_subscriptions_inventory_status')
        cluster_members = set()
        for cluster in (region.get('clusters') or {}).values():
            if not isinstance(cluster, dict):
                continue
            members = cluster.get('DBClusterMembers')
            if isinstance(members, list):
                cluster_members.update(x for x in members if isinstance(x, str))
            identifier = cluster.get('DBClusterIdentifier')
            if not isinstance(identifier, str) or not identifier:
                cluster['rds_alarm_status'] = 'unknown'
                cluster['rds_event_subscription_status'] = 'unknown'
                continue
            a, matching = _alarm_status(alarms, alarms_status, identifier, 'DBClusterIdentifier')
            e, matching_events = _event_status(subscriptions, subscriptions_status, identifier, 'db-cluster')
            cluster['rds_alarm_status'] = a
            cluster['rds_alarm_evidence'] = matching
            cluster['rds_event_subscription_status'] = e
            cluster['rds_event_subscription_evidence'] = matching_events
        for vpc in (region.get('vpcs') or {}).values():
            for instance in (vpc.get('instances') or {}).values():
                identifier = instance.get('name')
                if not isinstance(identifier, str) or not identifier:
                    instance['rds_alarm_status'] = 'unknown'
                    instance['rds_event_subscription_status'] = 'unknown'
                    continue
                # Aurora cluster-level monitoring is evaluated at the cluster
                # resource, avoiding spurious duplicate instance findings.
                if identifier in cluster_members:
                    instance['rds_alarm_status'] = 'not_applicable'
                    instance['rds_event_subscription_status'] = 'not_applicable'
                    continue
                a, matching = _alarm_status(alarms, alarms_status, identifier, 'DBInstanceIdentifier')
                e, matching_events = _event_status(subscriptions, subscriptions_status, identifier, 'db-instance')
                instance['rds_alarm_status'] = a
                instance['rds_alarm_evidence'] = matching
                instance['rds_event_subscription_status'] = e
                instance['rds_event_subscription_evidence'] = matching_events
