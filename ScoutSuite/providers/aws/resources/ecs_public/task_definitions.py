"""Bounded active ECS task definitions with no secret/environment values."""
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id


class TaskDefinitions(AWSResources):
    def __init__(self, facade, region):
        super().__init__(facade)
        self.region = region

    @staticmethod
    def issue(reason):
        context = get_current_run_context()
        if context is not None:
            context.record_collection_issue('partial', 'ecs', reason)

    async def fetch_all(self):
        for item in await self.facade.ecs.get_task_definitions(self.region):
            arn = item.get('taskDefinitionArn') if isinstance(item, dict) else None
            if not isinstance(arn, str) or not arn.startswith('arn:'):
                self.issue('InvalidTaskDefinition')
                continue
            containers = item.get('containerDefinitions')
            if not isinstance(containers, list):
                self.issue('MalformedContainerDefinitions')
                continue
            names = set()
            malformed = False
            safe_containers = []
            for container in containers:
                name = container.get('name') if isinstance(container, dict) else None
                if not isinstance(name, str) or not name or name in names:
                    self.issue('MalformedContainerDefinition')
                    malformed = True
                    continue
                names.add(name)
                # Do not serialize raw environment[], command, entryPoint,
                # dockerLabels, credential/secret payloads, or image contents.
                safe_containers.append({
                    'name': name,
                    'image': container.get('image'),
                    'privileged': container.get('privileged'),
                    'readonly_root_filesystem': container.get('readonlyRootFilesystem'),
                    'user': container.get('user'),
                    'essential': container.get('essential'),
                    'linux_parameters': {
                        'init_process_enabled': (container.get('linuxParameters') or {}).get(
                            'initProcessEnabled'),
                        'capabilities': (container.get('linuxParameters') or {}).get(
                            'capabilities') or {},
                    },
                    # Log options can contain credentials (e.g. splunk-token).
                    # Preserve driver and option keys, never their values.
                    'log_driver': (container.get('logConfiguration') or {}).get('logDriver'),
                    'log_option_names': sorted(
                        ((container.get('logConfiguration') or {}).get('options') or {})),
                    'log_secret_references': [
                        {'name': value.get('name'), 'value_from': value.get('valueFrom')}
                        for value in (container.get('logConfiguration') or {}).get(
                            'secretOptions', [])
                        if isinstance(value, dict)],
                    'environment_variable_names': [
                        row['name'] for row in container.get('environment', [])
                        if isinstance(row, dict) and isinstance(row.get('name'), str)],
                    'secret_references': [
                        {'name': row.get('name'), 'value_from': row.get('valueFrom')}
                        for row in container.get('secrets', [])
                        if isinstance(row, dict)],
                })
            privilege = [c['privileged'] for c in safe_containers]
            known = (bool(safe_containers) and not malformed
                     and all(isinstance(p, bool) for p in privilege))
            registered = item.get('registeredAt')
            if hasattr(registered, 'isoformat'):
                registered = registered.isoformat()
            key = get_non_provider_id(arn)
            if key in self:
                self.issue('DuplicateTaskDefinitionResource')
                continue
            self[key] = {
                'id': key, 'name': item.get('family') or arn,
                'task_definition_arn': arn,
                'region': self.region,
                'family': item.get('family'),
                'revision': item.get('revision'),
                'status': item.get('status'),
                'registered_at': registered,
                'registered_by': item.get('registeredBy'),
                'task_role_arn': item.get('taskRoleArn'),
                'execution_role_arn': item.get('executionRoleArn'),
                'network_mode': item.get('networkMode'),
                'requires_compatibilities': item.get('requiresCompatibilities') or [],
                'cpu': item.get('cpu'),
                'memory': item.get('memory'),
                'runtime_platform': item.get('runtimePlatform') or {},
                'ephemeral_storage': item.get('ephemeralStorage') or {},
                'container_count': len(safe_containers),
                'containers': safe_containers,
                'privilege_observation_complete': known,
                'has_privileged_container': any(p is True for p in privilege),
            }
