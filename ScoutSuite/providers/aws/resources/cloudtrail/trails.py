from datetime import datetime, timedelta, timezone

from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id


class Trails(AWSResources):
    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        raw_trails = await self.facade.cloudtrail.get_trails(self.region)
        for raw_trail in raw_trails:
            name, resource = self._parse_trail(raw_trail)
            self[name] = resource

    def _parse_trail(self, raw_trail):
        trail = {'name': raw_trail.pop('Name')}
        trail_id = get_non_provider_id(trail['name'])
        
        trail['arn'] = raw_trail.get('TrailARN')
        trail['is_organization_trail'] = raw_trail.get('IsOrganizationTrail')
        trail['home_region'] = raw_trail.get('HomeRegion')

        # Do not duplicate entries for multiregion trails
        if 'IsMultiRegionTrail' in raw_trail and raw_trail['IsMultiRegionTrail'] and \
                raw_trail['HomeRegion'] != self.region:
            for key in ['HomeRegion', 'TrailARN']:
                trail[key] = raw_trail[key]
            trail['scout_link'] = 'services.cloudtrail.regions.{}.trails.{}'.format(raw_trail['HomeRegion'], trail_id)
            return trail_id, trail

        for key in raw_trail:
            trail[key] = raw_trail[key]
        trail['bucket_id'] = get_non_provider_id(trail.pop('S3BucketName'))
        for key in ['IsMultiRegionTrail', 'LogFileValidationEnabled']:
            if key not in trail:
                trail[key] = False

        for key in ['KmsKeyId', 'IsLogging', 'LatestDeliveryTime', 'LatestDeliveryError', 'StartLoggingTime',
                    'StopLoggingTime', 'LatestNotificationTime', 'LatestNotificationError',
                    'LatestCloudWatchLogsDeliveryError', 'LatestCloudWatchLogsDeliveryTime']:
            trail[key] = trail[key] if key in trail else None

        # Selector collection failure is not the same as no events configured.
        if trail.get('selector_collection_status') == 'failed':
            trail['DataEventsEnabled'] = None
            trail['ManagementEventsEnabled'] = None
            trail['wildcard_data_logging'] = None
            return trail_id, trail

        basic = trail.get('EventSelectors') or []
        advanced = trail.get('AdvancedEventSelectors') or []
        data_enabled = any(
            bool(selector.get('DataResources'))
            for selector in basic
        )
        management_enabled = any(
            selector.get('IncludeManagementEvents') is True
            for selector in basic
        )
        for selector in advanced:
            categories = self._selector_values(
                selector, 'eventCategory', 'Equals'
            )
            data_enabled = data_enabled or 'Data' in categories
            management_enabled = management_enabled or 'Management' in categories

        trail['DataEventsEnabled'] = data_enabled
        trail['ManagementEventsEnabled'] = management_enabled
        trail['wildcard_data_logging'] = self.data_logging_status(trail)
        return trail_id, trail

    @staticmethod
    def _selector_values(selector, field, operator):
        values = []
        for item in selector.get('FieldSelectors', []):
            if item.get('Field') == field:
                values.extend(item.get(operator, []) or [])
        return values

    def data_logging_status(self, trail):
        if not trail.get('IsLogging') or not self.is_fresh(trail):
            return False

        for selector in trail.get('EventSelectors') or []:
            for resource in selector.get('DataResources') or []:
                if resource.get('Type') in ('AWS::S3::Object', 'AWS::Lambda::Function'):
                    arn_values = resource.get('Values') or []
                    if any(value in ('arn:aws:s3', 'arn:aws:lambda',
                                     'arn:aws-us-gov:s3', 'arn:aws-cn:s3',
                                     'arn:aws-us-gov:lambda', 'arn:aws-cn:lambda')
                           for value in arn_values):
                        return True

        for selector in trail.get('AdvancedEventSelectors') or []:
            if 'Data' not in self._selector_values(
                selector, 'eventCategory', 'Equals'
            ):
                continue
            kinds = self._selector_values(selector, 'resources.type', 'Equals')
            if not any(kind in ('AWS::S3::Object', 'AWS::Lambda::Function')
                       for kind in kinds):
                continue
            # An explicit resources.ARN restriction cannot prove wildcard
            # coverage unless it starts at the service-wide prefix.
            filters = [
                item for item in selector.get('FieldSelectors', [])
                if item.get('Field') == 'resources.ARN'
            ]
            if not filters:
                return True
            for item in filters:
                if any(value in ('arn:aws:s3:::', 'arn:aws-us-gov:s3:::',
                                 'arn:aws-cn:s3:::', 'arn:aws:lambda:',
                                 'arn:aws-us-gov:lambda:',
                                 'arn:aws-cn:lambda:')
                       for value in item.get('StartsWith', []) or []):
                    return True
        return False

    @staticmethod
    def is_fresh(trail_details, now=None):
        delivered = trail_details.get('LatestCloudWatchLogsDeliveryTime')
        if not delivered:
            return False
        if isinstance(delivered, str):
            try:
                delivered = datetime.fromisoformat(delivered.replace('Z', '+00:00'))
            except ValueError:
                return False
        if not isinstance(delivered, datetime):
            return False
        if delivered.tzinfo is None:
            delivered = delivered.replace(tzinfo=timezone.utc)
        current = now if now is not None else datetime.now(timezone.utc)
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        age = current.astimezone(timezone.utc) - delivered.astimezone(timezone.utc)
        return timedelta(0) <= age <= timedelta(hours=24)
