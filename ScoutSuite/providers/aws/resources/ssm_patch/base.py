"""M10-O: SSM patch management reconciliation including unmanaged EC2 instances."""
import asyncio

from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.resources.regions import Regions
from ScoutSuite.providers.utils import get_non_provider_id


def _issue(reason):
    ctx = get_current_run_context()
    if ctx is not None:
        ctx.record_collection_issue('partial', 'ssm', reason)


def _index(rows, field, prefix):
    result = {}
    malformed = False
    for item in rows:
        value = item.get(field) if isinstance(item, dict) else None
        if not isinstance(value, str) or not value:
            malformed = True
            _issue(prefix + 'InvalidIdentity')
            continue
        key = get_non_provider_id(value)
        if key in result:
            malformed = True
            _issue(prefix + 'DuplicateIdentity')
            continue
        result[key] = {'id': key, **item}
    return result, malformed


class SSMPatchPublic(Regions):
    _children = []

    def __init__(self, facade):
        super().__init__('ssm', facade)

    async def fetch_all(self, regions=None, excluded_regions=None,
                        partition_name='aws', **kwargs):
        self['regions'] = {}
        selected = await self.facade.build_region_list(
            self.service, regions, excluded_regions, partition_name)
        semaphore = asyncio.Semaphore(3)

        async def scan(region):
            async with semaphore:
                return region, await self.facade.ssm_patch.inventory(region)

        for region, inventory in await asyncio.gather(*(scan(r) for r in selected)):
            status = dict(inventory.get('collection') or {})
            baselines, failed = _index(inventory.get('baselines', []),
                                       'baseline_id', 'Baseline')
            if failed:
                status['baselines'] = 'partial'
            patch_groups = {}
            for i, entry in enumerate(inventory.get('patch_groups', [])):
                if not isinstance(entry, dict) or not isinstance(entry.get('PatchGroup'), str):
                    _issue('PatchGroupMalformed')
                    status['patch_groups'] = 'partial'
                    continue
                patch_group = entry['PatchGroup']
                key = get_non_provider_id(patch_group)
                if key in patch_groups:
                    _issue('PatchGroupDuplicate')
                    status['patch_groups'] = 'partial'
                    continue
                patch_groups[key] = {'id': key, 'name': patch_group, **entry}
            nodes, failed = _index(inventory.get('managed_nodes', []),
                                    'instance_id', 'ManagedNode')
            if failed:
                status['managed_nodes'] = 'partial'
            instances, failed = _index(inventory.get('ec2_instances', []),
                                        'instance_id', 'EC2Instance')
            if failed:
                status['ec2_instances'] = 'partial'
            baseline_ids = {item['baseline_id'] for item in baselines.values()}
            for node in nodes.values():
                reference = node.get('patch_baseline_id')
                node['baseline_resolution'] = (
                    'resolved' if reference in baseline_ids
                    else 'unknown' if reference or status.get('baselines') != 'complete'
                    else 'not_reported')
                node['name'] = node.get('name') or node['instance_id']
                if node.get('patch_health') == 'observed_current' and (
                        node['baseline_resolution'] != 'resolved'):
                    node['patch_health'] = 'baseline_unverified'
                node['patch_inventory_complete'] = (
                    node.get('patch_observation_complete') is True
                    and status.get('managed_nodes') == 'complete'
                    and status.get('baselines') == 'complete'
                    and node['baseline_resolution'] == 'resolved')
                node['patch_scan_needs_review'] = (
                    node.get('patch_state_collection') == 'complete'
                    and node.get('scan_evidence_collection') == 'complete'
                    and node.get('agent_online_recent') is True
                    and (node.get('successful_scan_fresh') is False
                         or node.get('patch_snapshot_fresh') is False))
                node['agent_connection_lost'] = (
                    node.get('agent_status') == 'ConnectionLost')
            by_ec2 = {value['instance_id']: value for value in nodes.values()}
            for item in instances.values():
                registered = item['instance_id'] in by_ec2
                item['ssm_managed'] = (
                    True if registered else False
                    if status.get('managed_nodes') == 'complete' else None)
                item['ssm_coverage_status'] = (
                    'managed' if registered else
                    'unmanaged_unverified_agent' if (
                        item.get('instance_state') == 'running'
                        and status.get('managed_nodes') == 'complete') else
                    'not_applicable' if item.get('instance_state') in (
                        'stopped', 'stopping', 'terminated', 'shutting-down') else
                    'unknown')
                item['patch_health'] = (
                    by_ec2[item['instance_id']]['patch_health'] if registered else None)
                item['running_unmanaged'] = (
                    item['ssm_coverage_status'] == 'unmanaged_unverified_agent')
            # Unknown region or denied enumeration cannot produce a PASS.
            data = {
                'id': region, 'name': region, 'region': region,
                'collection': status,
                'baselines': baselines,
                'patch_groups': patch_groups,
                'managed_nodes': nodes,
                'ec2_instances': instances,
                'collection_status': ('complete' if status
                                      and all(x == 'complete' for x in status.values())
                                      else 'partial'),
            }
            for key in ('baselines', 'patch_groups', 'managed_nodes', 'ec2_instances'):
                data[key + '_count'] = len(data[key])
            data['unmanaged_running_count'] = sum(
                1 for v in instances.values()
                if v['ssm_coverage_status'] == 'unmanaged_unverified_agent')
            data['critical_noncompliant_total_observed'] = sum(
                n.get('critical_noncompliant_count') or 0 for n in nodes.values())
            data['missing_security_total_observed'] = sum(
                n.get('missing_security_patch_count') or 0 for n in nodes.values())
            data['observed_counts_complete'] = (
                data['collection_status'] == 'complete'
                and all(n.get('patch_inventory_complete') is True for n in nodes.values()))
            self['regions'][region] = data
        self['regions_count'] = len(self['regions'])
        for key in ('baselines', 'patch_groups', 'managed_nodes', 'ec2_instances'):
            self[key + '_count'] = sum(
                item[key + '_count'] for item in self['regions'].values())
        self['unmanaged_running_count'] = sum(
            item['unmanaged_running_count'] for item in self['regions'].values())
        self['collection_status'] = (
            'complete' if selected and all(
                r['collection_status'] == 'complete' for r in self['regions'].values())
            else 'partial')
        if not selected:
            _issue('NoSSMRegionsEnumerated')
