"""M10-O: non-mutating AWS Systems Manager Patch Manager evidence.

A blank or old Patch Manager state is not evidence of patched EC2 hosts.
All inventory calls are bounded and report incomplete AWS API results.
"""
import asyncio
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError
from ScoutSuite.core.run_context import get_current_run_context, safe_collection_issue_code
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently

MAX_PAGES = 1000
MAX_ITEMS = 100000
SSM_PAGE_SIZE = 50
EC2_PAGE_SIZE = 1000
SCAN_MAX_AGE_DAYS = 7
AGENT_MAX_PING_AGE_HOURS = 24
PATCH_DETAIL_MAX_PAGES = 20
PATCH_DETAIL_MAX_ITEMS = 1000
DENIED = frozenset(('AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation'))


def json_safe(value):
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def as_datetime(value):
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            return None
    else:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def assessment(node, now=None):
    """Assess evidence only; missing agent/report/scan never becomes a clean PASS."""
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    patch = node.get('patch_state') or {}
    last = as_datetime(patch.get('OperationEndTime'))
    is_scan = patch.get('Operation') == 'Scan'
    age = (now - last).total_seconds() / 86400 if last else None
    successful = as_datetime(node.get('last_successful_scan_at'))
    success_age = (now - successful).total_seconds() / 86400 if successful else None
    confirmed = bool(node.get('successful_scan_confirmed') is True
                     and success_age is not None and 0 <= success_age <= SCAN_MAX_AGE_DAYS)
    recent = bool(is_scan and age is not None and 0 <= age <= SCAN_MAX_AGE_DAYS)
    counts = ('MissingCount', 'FailedCount', 'InstalledPendingRebootCount',
              'InstalledRejectedCount', 'CriticalNonCompliantCount',
              'SecurityNonCompliantCount', 'OtherNonCompliantCount')
    known = all(type(patch.get(k)) is int and patch[k] >= 0 for k in counts)
    bad = known and any(patch[k] > 0 for k in counts)
    critical = any(type(patch.get(k)) is int and patch[k] > 0
                   for k in ('CriticalNonCompliantCount', 'SecurityNonCompliantCount'))
    managed = node.get('ssm_managed') is True
    ping = node.get('ping_status')
    ping_time = as_datetime(node.get('last_ping_at'))
    ping_age_hours = ((now - ping_time).total_seconds() / 3600
                      if ping_time is not None else None)
    node['agent_ping_age_hours'] = (round(ping_age_hours, 2)
                                    if ping_age_hours is not None else None)
    node['agent_ping_fresh'] = (
        ping == 'Online' and ping_age_hours is not None
        and 0 <= ping_age_hours <= AGENT_MAX_PING_AGE_HOURS)
    online = managed and node['agent_ping_fresh']
    node['last_patch_operation_at'] = json_safe(last) if last else None
    node['last_reported_scan_at'] = json_safe(last) if is_scan and last else None
    node['scan_age_days'] = round(age, 2) if is_scan and age is not None else None
    node['scan_fresh'] = recent
    node['scan_stale'] = bool(is_scan and age is not None and age > SCAN_MAX_AGE_DAYS)
    node['scan_unverified'] = managed and not (recent and confirmed)
    node['agent_not_online'] = managed and ping == 'ConnectionLost'
    node['agent_ping_unverified'] = managed and not node['agent_ping_fresh']
    node['security_noncompliant'] = critical
    node['missing_or_failed_patches'] = bool(bad)
    node['unmanaged_running_ec2'] = (node.get('ec2_state') == 'running'
                                     and node.get('ssm_managed') is False)
    node['compliance_evidence_complete'] = bool(
        online and recent and confirmed and known
        and node.get('patch_state_observed') is True
        and node.get('inventory_evidence_complete', True) is True)
    if node['unmanaged_running_ec2']:
        node['patch_assessment'] = 'unmanaged_running_ec2'
    elif not managed:
        node['patch_assessment'] = 'not_managed_or_not_reporting'
    elif critical:
        node['patch_assessment'] = 'security_noncompliant'
    elif bad:
        node['patch_assessment'] = 'noncompliant'
    elif not online:
        node['patch_assessment'] = 'agent_offline_or_unverified'
    elif not recent:
        node['patch_assessment'] = 'patch_scan_unknown_or_stale'
    elif not confirmed:
        node['patch_assessment'] = 'successful_scan_unverified'
    elif not known:
        node['patch_assessment'] = 'patch_counts_unknown'
    elif not node.get('inventory_evidence_complete', True):
        node['patch_assessment'] = 'inventory_incomplete'
    else:
        node['patch_assessment'] = 'recent_scan_no_reported_noncompliance'
    # AWS reports a completed scan operation, not independent proof of
    # successful patch installation or security update coverage.
    node['fully_patched_verified'] = False
    node['patch_compliant_evidence'] = (
        node['compliance_evidence_complete'] and not bad)
    return node


class SSMPublicFacade(AWSBaseFacade):
    def __init__(self, session):
        super().__init__(session)

    @staticmethod
    def issue(status, reason):
        ctx = get_current_run_context()
        if ctx is not None:
            ctx.record_collection_issue(status, 'ssm', safe_collection_issue_code(reason))

    def failure(self, name, exc):
        code = (exc.response.get('Error', {}).get('Code')
                if isinstance(exc, ClientError) else type(exc).__name__)
        status = 'denied' if code in DENIED else 'failed'
        self.issue(status, name + ':' + str(code))

    async def call(self, client, method, **params):
        try:
            return await run_concurrently(lambda: getattr(client, method)(**params))
        except Exception as exc:
            self.failure(method, exc)
            return None

    async def pages(self, client, method, key, size=SSM_PAGE_SIZE, *,
                    max_pages=MAX_PAGES, max_items=MAX_ITEMS, **fixed):
        """Return (rows, complete), never silently accept truncated data."""
        rows, seen, token = [], set(), None
        for _ in range(max_pages):
            params = dict(fixed)
            params['MaxResults'] = size
            if token is not None:
                params['NextToken'] = token
            response = await self.call(client, method, **params)
            if not isinstance(response, dict):
                return rows, False
            batch = response.get(key)
            if (not isinstance(batch, list) or len(batch) > size
                    or any(not isinstance(x, dict) for x in batch)):
                self.issue('partial', method + ':MalformedPage')
                return rows, False
            if len(rows) + len(batch) > max_items:
                rows.extend(batch[:max_items - len(rows)])
                self.issue('partial', method + ':ItemLimit')
                return rows, False
            rows.extend(batch)
            nxt = response.get('NextToken')
            if nxt in (None, ''):
                return rows, True
            if (not isinstance(nxt, str) or len(nxt) > 4096
                    or nxt in seen):
                self.issue('partial', method + ':RepeatedOrInvalidToken')
                return rows, False
            seen.add(nxt)
            token = nxt
        self.issue('partial', method + ':PageLimit')
        return rows, False

    async def patch_states(self, client, managed_ids):
        results, complete, seen = {}, True, set()
        for start in range(0, len(managed_ids), 50):
            ids = managed_ids[start:start + 50]
            rows, ok = await self.pages(
                client, 'describe_instance_patch_states',
                'InstancePatchStates', size=50, InstanceIds=ids)
            complete = complete and ok
            for record in rows:
                rid = record.get('InstanceId')
                if rid not in ids or rid in seen:
                    complete = False
                    self.issue('partial', 'DescribeInstancePatchStates:InvalidIdentity')
                    continue
                seen.add(rid)
                results[rid] = record
        # A successful API response can contain no state for a managed node:
        # this means no collected scan result, not patch compliance.
        return results, complete


    async def successful_scan_commands(self, client, managed_ids):
        """Corroborate Scan via successful per-node Run Command invocations.

        Lack of accessible command history is unknown, not a clean scan. Scan
        histories in other mechanisms/accounts can be outside these APIs.
        """
        if not managed_ids:
            return {}, True
        since = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        commands, complete = await self.pages(
            client, 'list_commands', 'Commands',
            Filters=[{'key': 'DocumentName', 'value': 'AWS-RunPatchBaseline'},
                     {'key': 'InvokedAfter', 'value': since}])
        eligible = []
        for command in commands:
            operation = (command.get('Parameters') or {}).get('Operation')
            if (command.get('DocumentName') == 'AWS-RunPatchBaseline'
                    and operation == ['Scan']
                    and isinstance(command.get('CommandId'), str)):
                eligible.append(command['CommandId'])
        observed = {}
        selected_ids = set(managed_ids)
        async def get_invocations(cid):
            rows, ok = await self.pages(
                client, 'list_command_invocations', 'CommandInvocations',
                CommandId=cid, Details=True)
            return cid, rows, ok

        # Fixed-size fan-out: never launch a task for every command at once.
        for start in range(0, len(eligible), 8):
            batch = await asyncio.gather(*(
                get_invocations(cid) for cid in eligible[start:start + 8]))
            for cid, invocations, ok in batch:
                complete = complete and ok
                for invocation in invocations:
                    rid = invocation.get('InstanceId')
                    if rid not in selected_ids:
                        continue
                    if (invocation.get('CommandId') != cid
                            or invocation.get('DocumentName') not in
                            (None, 'AWS-RunPatchBaseline')):
                        self.issue('partial', 'MismatchedScanInvocation')
                        complete = False
                        continue
                    if (invocation.get('Status') != 'Success'
                            or invocation.get('StatusDetails') not in
                            (None, 'Success')):
                        continue
                    plugins = invocation.get('CommandPlugins') or []
                    times = [as_datetime(item.get('ResponseFinishDateTime'))
                             for item in plugins if isinstance(item, dict)
                             and item.get('Status') == 'Success']
                    finished = max((t for t in times if t is not None),
                                   default=None)
                    if finished is None:
                        # No completion timestamp: do not fabricate one from
                        # RequestedDateTime (which precedes the execution).
                        continue
                    if rid not in observed or finished > observed[rid]:
                        observed[rid] = finished
        return {rid: timestamp.isoformat() for rid, timestamp in observed.items()}, complete

    async def patch_details(self, client, node):
        state = node.get('patch_state') or {}
        if not any(type(state.get(k)) is int and state[k] > 0
                   for k in ('MissingCount', 'FailedCount', 'CriticalNonCompliantCount',
                             'SecurityNonCompliantCount',
                             'InstalledPendingRebootCount', 'InstalledRejectedCount')):
            node['missing_patches'] = []
            node['missing_patches_collection_complete'] = (
                node.get('patch_state_observed') is True)
            return
        rows, complete = await self.pages(
            client, 'describe_instance_patches', 'Patches',
            InstanceId=node['instance_id'],
            max_pages=PATCH_DETAIL_MAX_PAGES,
            max_items=PATCH_DETAIL_MAX_ITEMS,
            Filters=[{'Key': 'State', 'Values': [
                'Missing', 'Failed', 'InstalledPendingReboot',
                'InstalledRejected', 'AvailableSecurityUpdate']}])
        node['missing_patches'] = json_safe(rows)
        node['missing_patches_collection_complete'] = complete
        node['security_related_missing_patches'] = [
            patch for patch in node['missing_patches']
            if ('security' in str(patch.get('Classification', '')).lower()
                or patch.get('Severity') in ('Critical', 'Important')
                or bool(patch.get('CVEIds')))]
        # Patch classification is platform-specific. AWS non-compliant counters
        # are authoritative for severity classification, not this heuristic.

    async def inventory(self, region):
        ssm = AWSFacadeUtils.get_client('ssm', self.session, region)
        ec2 = AWSFacadeUtils.get_client('ec2', self.session, region)
        if ssm is None:
            self.issue('failed', 'SSMClientConstruction')
        if ec2 is None:
            self.issue('failed', 'EC2ClientConstruction')
        if ssm is None:
            return {'managed_nodes': [], 'patch_baselines': [], 'patch_groups': [],
                    'collection': {'managed_nodes': False, 'ec2': False,
                                   'patch_states': False, 'patch_baselines': False,
                                   'patch_groups': False}, 'ec2_comparison_complete': False}

        (managed, managed_ok), (baselines, baseline_ok), (groups, groups_ok), (reservations, ec2_ok) = (
            await asyncio.gather(
                self.pages(ssm, 'describe_instance_information', 'InstanceInformationList'),
                self.pages(ssm, 'describe_patch_baselines', 'BaselineIdentities'),
                self.pages(ssm, 'describe_patch_groups', 'Mappings'),
                self.pages(ec2, 'describe_instances', 'Reservations',
                           size=EC2_PAGE_SIZE) if ec2 is not None
                else asyncio.sleep(0, result=([], False))))

        # AWS default patch baselines exist even if Patch Manager has never
        # managed a node. The summaries are retained, but avoid GetPatchBaseline
        # on every AWS-managed baseline when complete inventories establish
        # zero managed nodes AND zero patch group associations. This does not
        # assert that EC2 instances are patched; the EC2/SSM comparison below
        # still emits unmanaged-instance findings.
        defer_baseline_details = bool(
            managed_ok and not managed and groups_ok and not groups)
        baseline_records = []
        seen_baselines = set()
        for summary in baselines:
            bid = summary.get('BaselineId')
            if not isinstance(bid, str) or not bid or bid in seen_baselines:
                baseline_ok = False
                self.issue('partial', 'InvalidPatchBaselineId')
                continue
            seen_baselines.add(bid)
            if defer_baseline_details:
                baseline_records.append({
                    **summary, 'detail': None, 'detail_complete': False,
                    'detail_status': 'not_required_no_managed_nodes'})
                continue
            detail = await self.call(ssm, 'get_patch_baseline', BaselineId=bid)
            if not isinstance(detail, dict) or detail.get('BaselineId') != bid:
                baseline_ok = False
                self.issue('partial', 'MissingPatchBaselineDetail:' + bid)
            baseline_records.append({
                **summary, 'detail': json_safe(detail) if isinstance(detail, dict) else None,
                'detail_complete': isinstance(detail, dict) and detail.get('BaselineId') == bid,
                'detail_status': 'verified' if isinstance(detail, dict)
                and detail.get('BaselineId') == bid else 'incomplete'})

        nodes, managed_ids = {}, []
        for entry in managed:
            rid = entry.get('InstanceId')
            if (not isinstance(rid, str) or not rid.startswith(('i-', 'mi-'))
                    or rid in nodes):
                managed_ok = False
                self.issue('partial', 'InvalidOrDuplicateManagedNodeId')
                continue
            nodes[rid] = {
                'instance_id': rid, 'name': entry.get('ComputerName') or rid,
                'ssm_managed': True, 'ping_status': entry.get('PingStatus'),
                'last_ping_at': json_safe(entry.get('LastPingDateTime')),
                'managed_node_information': json_safe(entry),
                'patch_state': None, 'patch_state_observed': False,
                'patch_baseline_id': None,
                'patch_group': entry.get('ResourceType'),
                'ec2_state': None, 'region': region,
            }
            managed_ids.append(rid)

        ec2_records = {}
        for reservation in reservations:
            instances = reservation.get('Instances')
            if not isinstance(instances, list):
                ec2_ok = False
                self.issue('partial', 'MalformedEC2Reservation')
                continue
            for entry in instances:
                rid = entry.get('InstanceId') if isinstance(entry, dict) else None
                if not isinstance(rid, str) or not rid or rid in ec2_records:
                    ec2_ok = False
                    self.issue('partial', 'InvalidOrDuplicateEC2InstanceId')
                    continue
                status = (entry.get('State') or {}).get('Name')
                if status in ('terminated', 'shutting-down'):
                    continue
                ec2_records[rid] = json_safe(entry)
                if rid in nodes:
                    node = nodes[rid]
                elif managed_ok and ec2_ok:
                    node = {
                        'instance_id': rid, 'ssm_managed': False,
                        'ping_status': None, 'last_ping_at': None,
                        'managed_node_information': None, 'patch_state': None,
                        'patch_state_observed': False, 'patch_baseline_id': None,
                        'region': region,
                    }
                    nodes[rid] = node
                else:
                    # Unknown SSM coverage must not be reported as agent missing.
                    continue
                tags = entry.get('Tags') or []
                name = next((tag.get('Value') for tag in tags
                             if isinstance(tag, dict) and tag.get('Key') == 'Name'), None)
                node.update({
                    'name': name or node.get('name') or rid,
                    'ec2_state': status,
                    'ec2_instance': json_safe(entry),
                    'private_ip_address': entry.get('PrivateIpAddress'),
                    'instance_type': entry.get('InstanceType')})

        (states, states_ok), (successful_scans, commands_ok) = await asyncio.gather(
            self.patch_states(ssm, managed_ids),
            self.successful_scan_commands(ssm, managed_ids))
        for rid, record in states.items():
            nodes[rid]['patch_state'] = json_safe(record)
            nodes[rid]['patch_state_observed'] = True
            nodes[rid]['patch_baseline_id'] = record.get('BaselineId')

        # EC2 census is complete only when both source inventories were complete.
        comparison = bool(ec2_ok and managed_ok)
        if not comparison:
            for rid, node in list(nodes.items()):
                if node.get('ssm_managed') is False:
                    del nodes[rid]

        for node in nodes.values():
            rid = node['instance_id']
            node['last_successful_scan_at'] = successful_scans.get(rid)
            node['successful_scan_confirmed'] = rid in successful_scans
            node['scan_command_history_complete'] = commands_ok
            assessment(node)
        # Query patch details for noncompliant nodes only, with bounded fanout.
        for start in range(0, len(managed_ids), 8):
            await asyncio.gather(*(self.patch_details(ssm, nodes[rid])
                                   for rid in managed_ids[start:start + 8]))
        available_baselines = {
            row['BaselineId'] for row in baseline_records
            if row.get('detail_complete') is True}
        details_ok = True
        for rid in managed_ids:
            node = nodes[rid]
            baseline_id = node.get('patch_baseline_id')
            node['baseline_resolution_status'] = (
                'resolved' if baseline_id in available_baselines and baseline_ok
                else 'unknown')
            detail_ok = node.get('missing_patches_collection_complete') is True
            details_ok = details_ok and detail_ok
            node['inventory_evidence_complete'] = (
                bool(managed_ok and baseline_ok and groups_ok and states_ok and commands_ok)
                and detail_ok and node['baseline_resolution_status'] == 'resolved')
            # Reclassify after joining the full baseline + patch-details census.
            # Without complete inventory, zero reported missing patches are UNKNOWN.
            assessment(node)
        return {
            'managed_nodes': list(nodes.values()),
            'patch_baselines': json_safe(baseline_records),
            'patch_groups': json_safe(groups),
            'collection': {
                'managed_nodes': managed_ok, 'ec2': ec2_ok,
                'patch_states': states_ok, 'patch_baselines': baseline_ok,
                'patch_baseline_details': ('not_required_no_managed_nodes'
                                           if defer_baseline_details else
                                           'complete' if baseline_ok else 'partial'),
                'patch_groups': groups_ok, 'scan_command_history': commands_ok,
                'patch_details': details_ok},
            'ec2_comparison_complete': comparison,
            'scan_freshness_days': SCAN_MAX_AGE_DAYS,
            'scan_success_independently_verified': False,
        }
