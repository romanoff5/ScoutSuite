"""M10-O: Systems Manager patch compliance inventory without mutation.

The observed patch operation is not proof of a successful scan. Successful
scan evidence is independently correlated with SSM command invocations.
"""
import asyncio
from datetime import datetime, timezone
from botocore.exceptions import ClientError

from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently

PAGE_SIZE = 50
MAX_PAGES = 2000
MAX_ITEMS = 100000
PATCH_DETAIL_PAGES = 20       # bounded per-node: 1000 patches
INVOCATION_PAGES = 3          # bounded per-node: 150 recent commands
PATCH_STALE_DAYS = 7
AGENT_STALE_HOURS = 24
DENIED = {'AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation'}
PATCH_STATES = ('Missing', 'Failed', 'InstalledPendingReboot', 'InstalledRejected')


def iso(value):
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()
    return None


def age_hours(value, now):
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return max(0.0, (now - value.astimezone(timezone.utc)).total_seconds() / 3600)


class SSMPatchFacade(AWSBaseFacade):
    def __init__(self, session):
        super().__init__(session)

    @staticmethod
    def issue(status, reason):
        ctx = get_current_run_context()
        if ctx is not None:
            ctx.record_collection_issue(status, 'ssm', reason)

    def failure(self, action, error):
        code = error.response.get('Error', {}).get('Code', '') if isinstance(
            error, ClientError) else type(error).__name__
        status = 'denied' if code in DENIED else 'failed'
        self.issue(status, action + ':' + code)
        return 'partial'

    async def call(self, client, action, **params):
        try:
            return await run_concurrently(lambda: getattr(client, action)(**params)), 'complete'
        except Exception as exc:
            return None, self.failure(action, exc)

    async def pages(self, client, action, key, params=None, *, max_pages=MAX_PAGES,
                    max_items=MAX_ITEMS):
        rows, seen, token = [], set(), None
        for _ in range(max_pages):
            request = dict(params or {})
            if token is not None:
                request['NextToken'] = token
            page, status = await self.call(client, action, **request)
            if status != 'complete':
                return rows, 'partial'
            values = page.get(key) if isinstance(page, dict) else None
            if not isinstance(values, list):
                self.issue('partial', action + ':MalformedPage')
                return rows, 'partial'
            if len(rows) + len(values) > max_items:
                rows.extend(values[:max_items-len(rows)])
                self.issue('partial', action + ':ItemLimit')
                return rows, 'partial'
            rows.extend(values)
            next_token = page.get('NextToken')
            if next_token in (None, ''):
                return rows, 'complete'
            if not isinstance(next_token, str) or not next_token or next_token in seen:
                self.issue('partial', action + ':InvalidToken')
                return rows, 'partial'
            seen.add(next_token)
            token = next_token
        self.issue('partial', action + ':PageLimit')
        return rows, 'partial'

    async def _scan_evidence(self, client, instance_id):
        """Only confirmed successful AWS-RunPatchBaseline Scan qualifies.

        Command request timestamp is retained as an approximate timestamp,
        separately identified from completion; no success is inferred from
        OperationEndTime or mere presence of a patch-state snapshot.
        """
        invocations, completeness = await self.pages(
            client, 'list_command_invocations', 'CommandInvocations',
            {'InstanceId': instance_id, 'Details': True, 'MaxResults': PAGE_SIZE},
            max_pages=INVOCATION_PAGES, max_items=PAGE_SIZE * INVOCATION_PAGES)
        candidates = []
        cache = {}
        for item in invocations:
            if not isinstance(item, dict):
                completeness = 'partial'
                self.issue('partial', 'MalformedCommandInvocation')
                continue
            if item.get('DocumentName') != 'AWS-RunPatchBaseline' or item.get('Status') != 'Success':
                continue
            command_id = item.get('CommandId')
            if not isinstance(command_id, str) or not command_id:
                completeness = 'partial'
                continue
            if command_id not in cache:
                command, state = await self.call(client, 'list_commands', CommandId=command_id)
                commands = command.get('Commands', []) if isinstance(command, dict) else None
                if (state != 'complete' or not isinstance(commands, list)
                        or len(commands) != 1 or commands[0].get('CommandId') != command_id):
                    completeness = 'partial'
                    self.issue('partial', 'ScanCommandParametersUnknown')
                    cache[command_id] = None
                else:
                    cache[command_id] = commands[0]
            command = cache[command_id]
            if not command:
                continue
            parameters = command.get('Parameters') or {}
            operation = parameters.get('Operation', [])
            if (not isinstance(operation, list) or operation != ['Scan']
                    or command.get('DocumentName') != 'AWS-RunPatchBaseline'):
                continue
            # Invocation-level success, not aggregate command status, matters.
            finished = [
                p.get('ResponseFinishDateTime') for p in item.get('CommandPlugins', [])
                if isinstance(p, dict) and p.get('Status') == 'Success'
                and isinstance(p.get('ResponseFinishDateTime'), datetime)
            ]
            timestamp = max(finished) if finished else item.get('RequestedDateTime')
            if isinstance(timestamp, datetime):
                candidates.append((timestamp, bool(finished), command_id))
        if not candidates:
            return {'last_successful_scan_at': None, 'scan_evidence': 'unverified',
                    'scan_command_id': None, 'scan_evidence_collection': completeness,
                    'scan_timestamp_source': None}
        timestamp, completion, command_id = max(candidates, key=lambda row: row[0])
        return {'last_successful_scan_at': iso(timestamp), 'scan_evidence': 'confirmed',
                'scan_command_id': command_id, 'scan_evidence_collection': completeness,
                'scan_timestamp_source': ('plugin_completion' if completion
                                          else 'successful_invocation_request')}

    async def _node_patch(self, client, row, now):
        node_id = row['InstanceId']
        patch_response, state = await self.call(
            client, 'describe_instance_patch_states', InstanceIds=[node_id])
        states = patch_response.get('InstancePatchStates') if isinstance(
            patch_response, dict) else None
        patch = None
        if state == 'complete':
            if not isinstance(states, list) or len(states) > 1 or (
                    states and states[0].get('InstanceId') != node_id):
                self.issue('partial', 'MalformedPatchState:' + node_id)
                state = 'partial'
            elif states:
                patch = states[0]
        details, details_status = await self.pages(
            client, 'describe_instance_patches', 'Patches',
            {'InstanceId': node_id, 'MaxResults': PAGE_SIZE,
             'Filters': [{'Key': 'State', 'Values': list(PATCH_STATES), 'Type': 'Equal'}]},
            max_pages=PATCH_DETAIL_PAGES, max_items=PAGE_SIZE*PATCH_DETAIL_PAGES)
        missing = []
        for item in details:
            if isinstance(item, dict) and item.get('State') in PATCH_STATES:
                missing.append({
                    'kb_id': item.get('KBId'), 'title': item.get('Title'),
                    'classification': item.get('Classification'),
                    'severity': item.get('Severity'), 'state': item.get('State'),
                    'installed_time': iso(item.get('InstalledTime')),
                })
            else:
                details_status = 'partial'
                self.issue('partial', 'InvalidNoncompliantPatch:' + node_id)
        scan = await self._scan_evidence(client, node_id)
        observed_end = patch.get('OperationEndTime') if patch else None
        patch_age = age_hours(observed_end, now)
        ping_age = age_hours(row.get('LastPingDateTime'), now)
        counts = {}
        for field in ('CriticalNonCompliantCount', 'SecurityNonCompliantCount',
                      'OtherNonCompliantCount', 'MissingCount', 'FailedCount',
                      'InstalledPendingRebootCount', 'InstalledRejectedCount',
                      'AvailableSecurityUpdateCount', 'InstalledCount'):
            value = patch.get(field) if patch else None
            counts[field] = value if isinstance(value, int) and value >= 0 else None
        out = {
            'patch_state_collection': state,
            'patch_details_collection': details_status,
            'patch_summary_present': patch is not None,
            'patch_baseline_id': patch.get('BaselineId') if patch else None,
            'patch_group': patch.get('PatchGroup') if patch else None,
            'patch_snapshot_id': patch.get('SnapshotId') if patch else None,
            'latest_patch_operation': patch.get('Operation') if patch else None,
            'latest_patch_operation_started_at': iso(patch.get('OperationStartTime')) if patch else None,
            'latest_patch_operation_ended_at': iso(observed_end),
            'latest_patch_operation_age_hours': round(patch_age, 2) if patch_age is not None else None,
            'last_no_reboot_install_at': iso(patch.get('LastNoRebootInstallOperationTime')) if patch else None,
            'last_agent_ping_at': iso(row.get('LastPingDateTime')),
            'agent_ping_age_hours': round(ping_age, 2) if ping_age is not None else None,
            'agent_status': row.get('PingStatus'),
            'agent_version': row.get('AgentVersion'),
            'agent_is_latest': row.get('IsLatestVersion'),
            'patch_counts': counts,
            'missing_security_patch_count': counts['SecurityNonCompliantCount'],
            'critical_noncompliant_count': counts['CriticalNonCompliantCount'],
            'missing_patch_details': missing,
            **scan,
        }
        fresh = bool(patch_age is not None and patch_age <= PATCH_STALE_DAYS*24)
        online = row.get('PingStatus') == 'Online' and ping_age is not None and ping_age <= AGENT_STALE_HOURS
        successful_age = None
        if scan['last_successful_scan_at'] is not None:
            successful_age = age_hours(datetime.fromisoformat(scan['last_successful_scan_at']), now)
        scan_fresh = bool(successful_age is not None and successful_age <= PATCH_STALE_DAYS*24)
        out['last_successful_scan_age_hours'] = (
            round(successful_age, 2) if successful_age is not None else None)
        out['agent_online_recent'] = online
        out['patch_snapshot_fresh'] = fresh
        out['successful_scan_fresh'] = scan_fresh
        out['patch_observation_complete'] = (
            state == 'complete' and details_status == 'complete'
            and scan['scan_evidence_collection'] == 'complete')
        if not online:
            out['patch_health'] = 'agent_offline_or_unverified'
        elif not patch:
            out['patch_health'] = 'no_patch_state'
        elif not fresh or not scan_fresh:
            out['patch_health'] = 'stale_or_unverified_scan'
        elif any(counts[k] is None for k in ('MissingCount', 'FailedCount',
                                             'InstalledPendingRebootCount',
                                             'CriticalNonCompliantCount', 'SecurityNonCompliantCount')):
            out['patch_health'] = 'patch_counts_unknown'
        elif (counts['MissingCount'] or counts['FailedCount'] or
              counts['InstalledPendingRebootCount'] or counts['CriticalNonCompliantCount']
              or counts['SecurityNonCompliantCount']):
            out['patch_health'] = 'noncompliant'
        elif not out['patch_observation_complete']:
            out['patch_health'] = 'collection_incomplete'
        else:
            out['patch_health'] = 'observed_current'
        return out

    async def inventory(self, region, *, now=None):
        now = now or datetime.now(timezone.utc)
        data = {'baselines': [], 'patch_groups': [], 'managed_nodes': [],
                'ec2_instances': [], 'collection': {}}
        ssm = AWSFacadeUtils.get_client('ssm', self.session, region)
        ec2 = AWSFacadeUtils.get_client('ec2', self.session, region)
        if ssm is None:
            self.issue('failed', 'SSMClientUnavailable')
            data['collection'].update(baselines='partial', patch_groups='partial',
                                     managed_nodes='partial')
        else:
            baselines, state = await self.pages(ssm, 'describe_patch_baselines',
                                                'BaselineIdentities', {'MaxResults': PAGE_SIZE})
            data['collection']['baselines'] = state
            for item in baselines:
                baseline_id = item.get('BaselineId') if isinstance(item, dict) else None
                if not isinstance(baseline_id, str) or not baseline_id:
                    data['collection']['baselines'] = 'partial'
                    self.issue('partial', 'InvalidBaselineId')
                    continue
                detail, detail_status = await self.call(
                    ssm, 'get_patch_baseline', BaselineId=baseline_id)
                data['baselines'].append({
                    'baseline_id': baseline_id, 'name': item.get('BaselineName'),
                    'description': item.get('BaselineDescription'),
                    'operating_system': item.get('OperatingSystem'),
                    'is_default': item.get('DefaultBaseline'),
                    'owner': item.get('BaselineId', '').split(':')[0],
                    'detail_collection': detail_status,
                    'details': {
                        'approval_rules': detail.get('ApprovalRules'),
                        'approved_patches': detail.get('ApprovedPatches'),
                        'approved_patches_compliance_level': detail.get('ApprovedPatchesComplianceLevel'),
                        'approved_patches_enable_non_security': detail.get(
                            'ApprovedPatchesEnableNonSecurity'),
                        'rejected_patches': detail.get('RejectedPatches'),
                        'rejected_patches_action': detail.get('RejectedPatchesAction'),
                        'patch_groups': detail.get('PatchGroups'),
                        'sources': detail.get('Sources'),
                        'created_at': iso(detail.get('CreatedDate')),
                        'modified_at': iso(detail.get('ModifiedDate')),
                    } if isinstance(detail, dict) else {},
                })
            groups, state = await self.pages(ssm, 'describe_patch_groups', 'Mappings',
                                            {'MaxResults': PAGE_SIZE})
            data['patch_groups'] = groups
            data['collection']['patch_groups'] = state
            info, state = await self.pages(ssm, 'describe_instance_information',
                                           'InstanceInformationList', {'MaxResults': PAGE_SIZE})
            data['collection']['managed_nodes'] = state
            seen = set()
            valid = []
            for row in info:
                node_id = row.get('InstanceId') if isinstance(row, dict) else None
                if not isinstance(node_id, str) or not node_id or node_id in seen:
                    self.issue('partial', 'InvalidOrDuplicateManagedNode')
                    data['collection']['managed_nodes'] = 'partial'
                    continue
                seen.add(node_id)
                valid.append(row)
            semaphore = asyncio.Semaphore(8)

            async def enrich(row):
                async with semaphore:
                    return row, await self._node_patch(ssm, row, now)

            for row, state in await asyncio.gather(*(enrich(row) for row in valid)):
                data['managed_nodes'].append({
                    'instance_id': row['InstanceId'],
                    'resource_type': row.get('ResourceType'),
                    'name': row.get('Name') or row.get('ComputerName') or row['InstanceId'],
                    'platform_type': row.get('PlatformType'),
                    'platform_name': row.get('PlatformName'),
                    'platform_version': row.get('PlatformVersion'),
                    'iam_role': row.get('IamRole'), **state,
                })
        if ec2 is None:
            self.issue('failed', 'EC2ClientUnavailable')
            data['collection']['ec2_instances'] = 'partial'
        else:
            instances, state = await self.pages(ec2, 'describe_instances', 'Reservations',
                                                {'MaxResults': 1000})
            data['collection']['ec2_instances'] = state
            seen = set()
            for reservation in instances:
                if not isinstance(reservation, dict) or not isinstance(reservation.get('Instances'), list):
                    self.issue('partial', 'InvalidEC2Reservation')
                    data['collection']['ec2_instances'] = 'partial'
                    continue
                for instance in reservation['Instances']:
                    instance_id = instance.get('InstanceId') if isinstance(instance, dict) else None
                    if not isinstance(instance_id, str) or not instance_id or instance_id in seen:
                        self.issue('partial', 'InvalidOrDuplicateEC2Instance')
                        data['collection']['ec2_instances'] = 'partial'
                        continue
                    seen.add(instance_id)
                    tags = instance.get('Tags') or []
                    name = next((x.get('Value') for x in tags if isinstance(x, dict)
                                 and x.get('Key') == 'Name'), instance_id)
                    data['ec2_instances'].append({
                        'instance_id': instance_id, 'name': name,
                        'instance_state': (instance.get('State') or {}).get('Name'),
                        'launch_time': iso(instance.get('LaunchTime')),
                        'instance_type': instance.get('InstanceType'),
                        'platform_details': instance.get('PlatformDetails'),
                        'iam_instance_profile_arn': (instance.get('IamInstanceProfile') or {}).get('Arn'),
                    })
        if ssm is not None and hasattr(ssm, 'close'):
            ssm.close()
        if ec2 is not None and hasattr(ec2, 'close'):
            ec2.close()
        return data
