"""P3-D: interpreted ELBv2 target health, not a guess about the application.

Read-only AWS DescribeTargetGroups/DescribeTargetHealth have already been
collected by P3-B. No network probes; the returned AWS reason is preserved.
"""

TRANSIENT = {'initial', 'draining', 'unused', 'unavailable'}


def annotate_alb_health(services):
    for region in (services.get('elbv2') or {}).get('regions', {}).values():
        for vpc in (region.get('vpcs') or {}).values():
            for lb in (vpc.get('lbs') or {}).values():
                lb['p3d_target_health_status'] = 'unknown'
                lb['p3d_health_mismatch_status'] = 'unknown'
                lb['p3d_unhealthy_status'] = 'unknown'
                lb['p3d_unhealthy_target_evidence'] = []
                if lb.get('Type') != 'application':
                    lb['p3d_health_mismatch_status'] = 'not_applicable'
                    lb['p3d_unhealthy_status'] = 'not_applicable'
                    continue
                if lb.get('target_group_inventory_status') != 'complete':
                    continue
                groups = lb.get('target_groups')
                if not isinstance(groups, list):
                    continue
                count, unexpected, suspicious = 0, False, []
                failures = []
                for group in groups:
                    if not isinstance(group, dict):
                        unexpected = True
                        continue
                    rows = group.get('registered_targets')
                    if not isinstance(rows, list):
                        unexpected = True
                        continue
                    for row in rows:
                        if not isinstance(row, dict):
                            unexpected = True
                            continue
                        state = row.get('health_state')
                        if state not in {'healthy', 'unhealthy', *TRANSIENT}:
                            unexpected = True
                            continue
                        count += 1
                        if state in TRANSIENT:
                            unexpected = True
                            continue
                        if state != 'unhealthy':
                            continue
                        reason = row.get('health_reason')
                        if reason not in ('Target.ResponseCodeMismatch', 'Target.Timeout',
                                          'Target.FailedHealthChecks', 'Elb.InternalError'):
                            unexpected = True
                        evidence = {
                            'target_group_arn': group.get('arn'),
                            'target_group_name': group.get('name'),
                            'target_id': row.get('id'), 'target_port': row.get('port'),
                            'health_state': state, 'reason': reason,
                            'description': row.get('health_description'),
                            'target_protocol': group.get('protocol'),
                            'health_check': group.get('health_check'),
                        }
                        failures.append(evidence)
                        if reason == 'Target.ResponseCodeMismatch':
                            suspicious.append(evidence)
                # Never convert a partially understood target census into PASS.
                lb['p3d_unhealthy_target_evidence'] = failures
                if suspicious:
                    lb['p3d_health_mismatch_status'] = 'response_mismatch'
                    lb['p3d_health_mismatch_evidence'] = suspicious
                elif not unexpected and count:
                    lb['p3d_health_mismatch_status'] = 'not_observed'
                if failures and not suspicious:
                    lb['p3d_unhealthy_status'] = 'other_unhealthy'
                elif not unexpected and count:
                    lb['p3d_unhealthy_status'] = 'not_observed'
                if not count and not unexpected:
                    lb['p3d_health_mismatch_status'] = 'not_applicable'
                    lb['p3d_unhealthy_status'] = 'not_applicable'
                lb['p3d_target_health_status'] = (
                    'unhealthy' if failures else 'unknown' if unexpected else
                    'healthy' if count else 'no_registered_targets')
