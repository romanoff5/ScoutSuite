"""Best-effort Inspector2 vs independently collected AWS resource reconciliation.

No AWS SDK calls. Only resource identifiers already obtained by selected
AWS services are compared, never assert complete compliance/eligibility.
"""
from ScoutSuite.core.run_context import get_current_run_context


_RESOURCE_TYPES = {
    'ec2': 'AWS_EC2_INSTANCE',
    'ecr': 'AWS_ECR_REPOSITORY',
    'awslambda': 'AWS_LAMBDA_FUNCTION',
}


def _observed_ids(service, region, name):
    regions = service.get('regions', {}) if isinstance(service, dict) else {}
    region_data = regions.get(region) if isinstance(regions, dict) else None
    if not isinstance(region_data, dict):
        return None
    if name == 'ec2':
        vpcs = region_data.get('vpcs', {})
        if not isinstance(vpcs, dict):
            return None
        return {instance.get('id') for vpc in vpcs.values() if isinstance(vpc, dict)
                for instance in vpc.get('instances', {}).values()
                if isinstance(instance, dict) and isinstance(instance.get('id'), str)}
    if name == 'awslambda':
        functions = region_data.get('functions', {})
        if not isinstance(functions, dict):
            return None
        return {f['arn'] for f in functions.values() if isinstance(f, dict)
                and isinstance(f.get('arn'), str)}
    if name == 'ecr':
        repositories = region_data.get('repositories', {})
        if not isinstance(repositories, dict):
            return None
        return {r['repository_arn'] for r in repositories.values() if isinstance(r, dict)
                and isinstance(r.get('repository_arn'), str)}
    return None


def reconcile_inspector_inventory(services, selected_services):
    inspector = services.get('inspector2') if isinstance(services, dict) else None
    if not isinstance(inspector, dict) or not isinstance(inspector.get('regions'), dict):
        return
    context = get_current_run_context()
    for region, data in inspector['regions'].items():
        coverage = data.get('coverage', {})
        own_coverage = {
            kind: {value.get('resource_id') for value in coverage.values()
                   if isinstance(value, dict) and value.get('resource_type') == kind
                   and isinstance(value.get('resource_id'), str)}
            for kind in _RESOURCE_TYPES.values()
        } if isinstance(coverage, dict) else {}
        reconciled = {}
        for name, resource_type in _RESOURCE_TYPES.items():
            if name not in selected_services or not isinstance(services.get(name), dict):
                continue
            observed = _observed_ids(services[name], region, name)
            if observed is None:
                reconciled[name] = {
                    'status': 'unavailable', 'resource_type': resource_type,
                    'source_inventory_complete': False, 'comparison_verified': False,
                }
                continue
            matched = observed & own_coverage.get(resource_type, set())
            missing = observed - own_coverage.get(resource_type, set())
            reconciled[name] = {
                'status': 'observed', 'resource_type': resource_type,
                'selected_service': name, 'observed_resource_count': len(observed),
                'inspector_matched_resource_count': len(matched),
                'not_seen_in_inspector': sorted(missing),
                'source_inventory_complete': False,  # No independent completeness proof.
                'comparison_verified': False,  # Eligibility has not been established.
            }
            if missing and context is not None:
                context.record_collection_issue('partial', 'inspector2', 'ResourceInventoryGapUnverified')
        data['resource_reconciliation'] = reconciled
        for account in data.get('accounts', {}).values():
            account['resource_reconciliation'] = {
                name: {'observed_resource_count': value.get('observed_resource_count'),
                       'inspector_matched_resource_count': value.get('inspector_matched_resource_count'),
                       'status': value['status']}
                for name, value in reconciled.items()
            }

        organization = data.get('organization', {})
        org_service = services.get('organizations')
        if not isinstance(organization, dict) or not isinstance(org_service, dict):
            continue
        org_accounts = org_service.get('accounts', {})
        org_collection = org_service.get('collection', {})
        if (organization.get('role') != 'delegated_admin'
                or not organization.get('members_complete')
                or not isinstance(org_collection, dict)
                or org_collection.get('accounts') != 'complete'
                or not isinstance(org_accounts, dict)):
            organization['organization_roster_compared'] = False
            continue
        active = {account_id for account_id, row in org_accounts.items()
                  if isinstance(row, dict) and row.get('state') == 'ACTIVE'}
        known = set(organization.get('members', {}))
        admin_id = organization.get('delegated_admin_account_id')
        if isinstance(admin_id, str):
            known.add(admin_id)
        missing = sorted(active - known)
        organization['organization_roster_compared'] = True
        organization['organization_roster_verified'] = not missing
        organization['aws_organizations_active_accounts'] = len(active)
        organization['inspector_known_active_org_accounts'] = len(active & known)
        organization['aws_org_accounts_missing_from_inspector_members'] = missing
        if missing and context is not None:
            context.record_collection_issue('partial', 'inspector2', 'OrganizationRosterGap')
