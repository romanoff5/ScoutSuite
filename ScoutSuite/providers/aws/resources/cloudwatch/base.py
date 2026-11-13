from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.regions import Regions

from .alarms import Alarms
from .metric_filters import MetricFilters
from .security_alerting import assess_security_metric_alerting


class CloudWatch(Regions):
    _children = [
        (Alarms, 'alarms'),
        (MetricFilters, 'metric_filters')
    ]

    def __init__(self, facade: AWSFacade):
        super().__init__('cloudwatch', facade)

    async def finalize(self):

        # For each region, check if at least one metric filter covers the desired events
        for region in self['regions']:
            self['regions'][region]['metric_filters_pattern_checks'] = {}
            # Initialize results at "False"
            self['regions'][region]['metric_filters_pattern_checks']['unauthorized_api_calls'] = False
            self['regions'][region]['metric_filters_pattern_checks']['console_login_mfa'] = False
            self['regions'][region]['metric_filters_pattern_checks']['root_usage'] = False
            self['regions'][region]['metric_filters_pattern_checks']['iam_policy_changes'] = False
            self['regions'][region]['metric_filters_pattern_checks']['cloudtrail_configuration_changes'] = False
            self['regions'][region]['metric_filters_pattern_checks']['console_authentication_failures'] = False
            self['regions'][region]['metric_filters_pattern_checks']['cmk_deletion'] = False
            self['regions'][region]['metric_filters_pattern_checks']['s3_policy_changes'] = False
            self['regions'][region]['metric_filters_pattern_checks']['aws_configuration_changes'] = False
            self['regions'][region]['metric_filters_pattern_checks']['security_group_changes'] = False
            self['regions'][region]['metric_filters_pattern_checks']['nacl_changes'] = False
            self['regions'][region]['metric_filters_pattern_checks']['network_gateways_changes'] = False
            self['regions'][region]['metric_filters_pattern_checks']['route_table_changes'] = False
            self['regions'][region]['metric_filters_pattern_checks']['vpc_changes'] = False
            for metric_filter_id, metric_filter in self['regions'][region]['metric_filters'].items():
                # Check events
                if metric_filter['pattern'] == "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }":
                    self['regions'][region]['metric_filters_pattern_checks']['unauthorized_api_calls'] = True
                    metric_filter.setdefault('security_pattern_categories', []).append('unauthorized_api_calls')
                if metric_filter['pattern'] == "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") }":
                    self['regions'][region]['metric_filters_pattern_checks']['console_login_mfa'] = True
                    metric_filter.setdefault('security_pattern_categories', []).append('console_login_mfa')
                if metric_filter['pattern'] == "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }":
                    self['regions'][region]['metric_filters_pattern_checks']['root_usage'] = True
                    metric_filter.setdefault('security_pattern_categories', []).append('root_usage')
                if metric_filter['pattern'] == "{ ($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy) }":
                    self['regions'][region]['metric_filters_pattern_checks']['iam_policy_changes'] = True
                    metric_filter.setdefault('security_pattern_categories', []).append('iam_policy_changes')
                if metric_filter['pattern'] == "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }":
                    self['regions'][region]['metric_filters_pattern_checks']['cloudtrail_configuration_changes'] = True
                    metric_filter.setdefault('security_pattern_categories', []).append('cloudtrail_configuration_changes')
                if metric_filter['pattern'] == "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }":
                    self['regions'][region]['metric_filters_pattern_checks']['console_authentication_failures'] = True
                    metric_filter.setdefault('security_pattern_categories', []).append('console_authentication_failures')
                if metric_filter['pattern'] == "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }":
                    self['regions'][region]['metric_filters_pattern_checks']['cmk_deletion'] = True
                    metric_filter.setdefault('security_pattern_categories', []).append('cmk_deletion')
                if metric_filter['pattern'] == "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketReplication)) }":
                    self['regions'][region]['metric_filters_pattern_checks']['s3_policy_changes'] = True
                    metric_filter.setdefault('security_pattern_categories', []).append('s3_policy_changes')
                if metric_filter['pattern'] == "{ ($.eventSource = config.amazonaws.com) && (($.eventName = StopConfigurationRecorder) || ($.eventName = DeleteDeliveryChannel) || ($.eventName = PutDeliveryChannel) || ($.eventName = PutConfigurationRecorder)) }":
                    self['regions'][region]['metric_filters_pattern_checks']['aws_configuration_changes'] = True
                    metric_filter.setdefault('security_pattern_categories', []).append('aws_configuration_changes')
                if metric_filter['pattern'] == "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }":
                    self['regions'][region]['metric_filters_pattern_checks']['security_group_changes'] = True
                    metric_filter.setdefault('security_pattern_categories', []).append('security_group_changes')
                if metric_filter['pattern'] == "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }":
                    self['regions'][region]['metric_filters_pattern_checks']['nacl_changes'] = True
                    metric_filter.setdefault('security_pattern_categories', []).append('nacl_changes')
                if metric_filter['pattern'] == "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }":
                    self['regions'][region]['metric_filters_pattern_checks']['network_gateways_changes'] = True
                    metric_filter.setdefault('security_pattern_categories', []).append('network_gateways_changes')
                if metric_filter['pattern'] == "{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }":
                    self['regions'][region]['metric_filters_pattern_checks']['route_table_changes'] = True
                    metric_filter.setdefault('security_pattern_categories', []).append('route_table_changes')
                if metric_filter['pattern'] == "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }":
                    self['regions'][region]['metric_filters_pattern_checks']['vpc_changes'] = True
                    metric_filter.setdefault('security_pattern_categories', []).append('vpc_changes')

            # This is an inventory-based signal for local CloudWatch metric-filter
            # alerting, not proof about EventBridge, external SIEM, or notifications.
            current = self['regions'][region]
            collector = self.facade.cloudwatch
            metrics_state = getattr(collector, 'metric_filter_collection_status', {}).get(region)
            alarms_state = getattr(collector, 'alarm_collection_status', {}).get(region)
            current['metric_filters_collection_status'] = metrics_state or 'unknown'
            current['metric_alarms_collection_status'] = alarms_state or 'unknown'
            if metrics_state != 'complete' or alarms_state != 'complete':
                current['security_metric_alerting_status'] = 'unknown'
            else:
                current['security_metric_alerting_status'] = assess_security_metric_alerting(
                    current.get('metric_filters'), current.get('alarms'))
