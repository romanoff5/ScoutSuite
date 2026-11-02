"""Preserve actionable repository names, ARNs, URIs and encryption evidence."""
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id


class Repositories(AWSResources):
    def __init__(self, facade, region):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        for raw in await self.facade.ecr.get_repositories(self.region):
            parsed = self._parse_repository(raw)
            if parsed is None:
                context = get_current_run_context()
                if context is not None:
                    context.record_collection_issue('partial', 'ecr', 'InvalidRepository')
                continue
            key, value = parsed
            if key in self:
                context = get_current_run_context()
                if context is not None:
                    context.record_collection_issue('partial', 'ecr', 'DuplicateRepositoryKey')
                continue
            if hasattr(self.facade.ecr, 'get_image_scan_evidence'):
                try:
                    value['operational_image_scans'] = await self.facade.ecr.get_image_scan_evidence(
                        self.region, value['repository_name'])
                except Exception:
                    context = get_current_run_context()
                    if context is not None:
                        context.record_collection_issue('partial', 'ecr', 'ImageScanCollectionFailed')
            self[key] = value

    def _parse_repository(self, raw):
        if not isinstance(raw, dict):
            return None
        arn, name = raw.get('repositoryArn'), raw.get('repositoryName')
        owner = raw.get('registryId')
        if (not isinstance(arn, str) or not arn.startswith('arn:')
                or not isinstance(name, str) or not name
                or not isinstance(owner, str) or len(owner) != 12 or not owner.isascii()
                or not owner.isdigit()):
            return None
        mode = raw.get('imageTagMutability')
        if mode is not None and mode not in (
                'MUTABLE', 'IMMUTABLE', 'MUTABLE_WITH_EXCLUSION',
                'IMMUTABLE_WITH_EXCLUSION'):
            mode = None
        created = raw.get('createdAt')
        if hasattr(created, 'isoformat'):
            created = created.isoformat()
        key = get_non_provider_id(arn)
        return key, {
            'id': key,
            'name': name,
            'repository_name': name,
            'repository_arn': arn,
            'repository_uri': raw.get('repositoryUri'),
            'registry_id': owner,
            'region': self.region,
            'created_at': created,
            'image_tag_mutability': mode,
            'tag_mutable': mode == 'MUTABLE',
            'tag_mutability_exclusion_filters': raw.get('imageTagMutabilityExclusionFilters') or [],
            'image_scanning_configuration': raw.get('imageScanningConfiguration') or {},
            'encryption_configuration': raw.get('encryptionConfiguration') or {},
        }
