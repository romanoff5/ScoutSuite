from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.utils import get_name, get_keys, format_arn

from ScoutSuite.core.rule_evidence import classify_imds_v2
from ScoutSuite.providers.aws.resources.secret_detection import DETECTOR_VERSION, detect_in_text


class EC2Instances(AWSResources):
    def __init__(self, facade: AWSFacade, region: str, vpc: str):
        super().__init__(facade)
        self.region = region
        self.vpc = vpc
        self.partition = facade.partition
        self.service = 'ec2'
        self.resource_type = 'instance'

    async def fetch_all(self):
        raw_instances = await self.facade.ec2.get_instances(self.region, self.vpc)
        for raw_instance in raw_instances:
            name, resource = await self._parse_instance(raw_instance)
            self[name] = resource

    async def _parse_instance(self, raw_instance):
        instance = {}
        id = raw_instance['InstanceId']
        instance['id'] = id
        instance['arn'] = format_arn(self.partition, self.service, self.region, raw_instance['OwnerId'], raw_instance['InstanceId'], self.resource_type)
        instance['reservation_id'] = raw_instance['ReservationId']
        instance['availability_zone'] = raw_instance.get('Placement', {}).get('AvailabilityZone')
        instance['monitoring_enabled'] = raw_instance['Monitoring']['State'] == 'enabled'
        # RC9: raw user data is scanned in memory and never stored in the report.
        status, user_data = await self.facade.ec2.get_instance_user_data_evidence(self.region, id)
        instance.update(self._user_data_evidence(status, user_data))

        get_name(raw_instance, instance, 'InstanceId')
        get_keys(raw_instance, instance,
                 ['KeyName', 'LaunchTime', 'InstanceType', 'State', 'IamInstanceProfile', 'SubnetId', 'Tags'])

        if "IamInstanceProfile" in raw_instance:
            instance['iam_instance_profile_id'] = raw_instance['IamInstanceProfile']['Id']
            instance['iam_instance_profile_arn'] = raw_instance['IamInstanceProfile']['Arn']
        
        instance['network_interfaces'] = {}
        for eni in raw_instance['NetworkInterfaces']:
            nic = {}
            get_keys(eni, nic, ['Association', 'Groups', 'PrivateIpAddresses', 'SubnetId', 'Ipv6Addresses'])
            instance['network_interfaces'][eni['NetworkInterfaceId']] = nic

        instance['metadata_options'] = raw_instance.get('MetadataOptions', {})
        instance['imds_v2_status'] = {
            'secure': 'required', 'insecure': 'optional',
            'not_applicable': 'disabled', 'unknown': 'unknown'
        }[classify_imds_v2(instance)]

        if 'IamInstanceProfile' in raw_instance:
            instance['iam_role'] = raw_instance['IamInstanceProfile']['Arn'].split('/')[-1]
        else:
            instance['iam_role'] = None

        return id, instance

    @staticmethod
    def _identify_user_data_secrets(user_data):
        """Masked detections (type, line, preview) for EC2 user data; never the values."""
        return detect_in_text(user_data)

    @staticmethod
    def _user_data_evidence(status, user_data):
        evidence = {'user_data_status': status, 'user_data_secrets': [],
                    'user_data_size_bytes': None, 'user_data_line_count': None, 'user_data_format': None,
                    'secret_detector_version': DETECTOR_VERSION}
        if status == 'present' and isinstance(user_data, str):
            evidence['user_data_size_bytes'] = len(user_data.encode('utf-8'))
            evidence['user_data_line_count'] = len(user_data.splitlines())
            first = user_data.lstrip()[:64]
            evidence['user_data_format'] = (
                'cloud-config' if first.startswith('#cloud-config') else
                'shell-script' if first.startswith('#!') else
                'powershell' if first.lower().startswith('<powershell>') else
                'mime-multipart' if first.lower().startswith('content-type: multipart') else 'other')
            evidence['user_data_secrets'] = detect_in_text(user_data)
        elif status == 'present':
            status = evidence['user_data_status'] = 'undecodable'
        evidence['user_data_secret_status'] = (
            'detected' if evidence['user_data_secrets'] else
            'none' if status == 'present' else
            'no_user_data' if status == 'absent' else 'unknown')
        return evidence
