from boto3.session import Session

from ScoutSuite.providers.aws.facade.acm import AcmFacade
from ScoutSuite.providers.aws.facade.awslambda import LambdaFacade
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.cloudformation import CloudFormation
from ScoutSuite.providers.aws.facade.cloudtrail import CloudTrailFacade
from ScoutSuite.providers.aws.facade.cloudwatch import CloudWatch
from ScoutSuite.providers.aws.facade.cloudfront import CloudFront
from ScoutSuite.providers.aws.facade.codebuild import CodeBuild
from ScoutSuite.providers.aws.facade.config import ConfigFacade
from ScoutSuite.providers.aws.facade.directconnect import DirectConnectFacade
from ScoutSuite.providers.aws.facade.dynamodb import DynamoDBFacade
from ScoutSuite.providers.aws.facade.ec2 import EC2Facade
from ScoutSuite.providers.aws.facade.efs import EFSFacade
from ScoutSuite.providers.aws.facade.elasticache import ElastiCacheFacade
from ScoutSuite.providers.aws.facade.elb import ELBFacade
from ScoutSuite.providers.aws.facade.elbv2 import ELBv2Facade
from ScoutSuite.providers.aws.facade.emr import EMRFacade
from ScoutSuite.providers.aws.facade.iam import IAMFacade
from ScoutSuite.providers.aws.facade.kms import KMSFacade
from ScoutSuite.providers.aws.facade.rds import RDSFacade
from ScoutSuite.providers.aws.facade.redshift import RedshiftFacade
from ScoutSuite.providers.aws.facade.route53 import Route53Facade
from ScoutSuite.providers.aws.facade.s3 import S3Facade
from ScoutSuite.providers.aws.facade.ses import SESFacade
from ScoutSuite.providers.aws.facade.sns import SNSFacade
from ScoutSuite.providers.aws.facade.sqs import SQSFacade
from ScoutSuite.providers.aws.facade.secretsmanager import SecretsManagerFacade
from ScoutSuite.providers.aws.utils import get_aws_account_id, get_partition_name
from ScoutSuite.providers.utils import run_concurrently

from ScoutSuite.core.conditions import print_error

# Try to import proprietary facades
try:
    from ScoutSuite.providers.aws.facade.cognito_private import CognitoFacade
except ImportError:
    pass
try:
    from ScoutSuite.providers.aws.facade.docdb_private import DocDBFacade
except ImportError:
    pass
try:
    from ScoutSuite.providers.aws.facade.ecs_private import ECSFacade
except ImportError:
    pass
try:
    from ScoutSuite.providers.aws.facade.ecr_private import ECRFacade
except ImportError:
    pass
try:
    from ScoutSuite.providers.aws.facade.eks_private import EKSFacade
except ImportError:
    pass
try:
    from ScoutSuite.providers.aws.facade.guardduty_private import GuardDutyFacade
except ImportError:
    pass
try:
    from ScoutSuite.providers.aws.facade.ssm_private import SSMFacade
except ImportError:
    pass


class AWSFacade(AWSBaseFacade):
    def __init__(self, credentials=None):
        super().__init__()
        self.owner_id = get_aws_account_id(credentials.session)
        self.partition = get_partition_name(credentials.session)
        self.session = credentials.session
        self._instantiate_facades()

    async def build_region_list(self, service: str, chosen_regions=None,
                                excluded_regions=None, partition_name='aws'):
        # Endpoint metadata is local; never derive sovereign region lists
        # from a commercial-only hard-coded Region.
        home = {
            'aws': 'us-east-1',
            'aws-us-gov': 'us-gov-west-1',
            'aws-cn': 'cn-north-1'
        }.get(partition_name, getattr(self.session, 'region_name', None))
        if not home:
            raise ValueError('No AWS partition endpoint available')

        sdk = Session(region_name=home)
        available_services = await run_concurrently(sdk.get_available_services)
        names = ('cognito-idp', 'cognito-identity') if service == 'cognito' else (
            service,)
        if not all(name in available_services for name in names):
            raise ValueError('AWS service not supported by installed SDK: ' + service)

        if service == 'cognito':
            idp = await run_concurrently(
                lambda: sdk.get_available_regions('cognito-idp', partition_name))
            identities = await run_concurrently(
                lambda: sdk.get_available_regions('cognito-identity', partition_name))
            regions = [name for name in idp if name in identities]
        else:
            regions = await run_concurrently(
                lambda: sdk.get_available_regions(service, partition_name))

        # No unreviewed EKS commercial-region fallback for other partitions.
        if not regions:
            from ScoutSuite.core.run_context import get_current_run_context
            context = get_current_run_context()
            if context is not None:
                context.record_collection_issue('failed', 'aws', 'RegionModelUnavailable')
            return []

        if chosen_regions:
            regions = [region for region in regions if region in chosen_regions]
        if excluded_regions:
            regions = [region for region in regions if region not in excluded_regions]

        # Discover opt-in status from an endpoint in the *same* partition.
        # If denied, preserve candidates but explicitly report uncertainty.
        probe_regions = [home]
        configured = getattr(self.session, 'region_name', None)
        if isinstance(configured, str) and configured not in probe_regions:
            probe_regions.append(configured)
        for candidate in chosen_regions or []:
            if candidate in regions and candidate not in probe_regions:
                probe_regions.append(candidate)
        not_opted_in = None
        for candidate in probe_regions:
            try:
                response = await run_concurrently(
                    lambda candidate=candidate: self.session.client(
                        'ec2', region_name=candidate
                    ).describe_regions(
                        AllRegions=True,
                        Filters=[{'Name': 'opt-in-status', 'Values': ['not-opted-in']}]
                    ))
                not_opted_in = {
                    item['RegionName'] for item in response.get('Regions', [])
                    if isinstance(item, dict) and 'RegionName' in item
                }
                break
            except Exception:
                continue
        if not_opted_in is None:
            from ScoutSuite.core.run_context import get_current_run_context
            context = get_current_run_context()
            if context is not None:
                context.record_collection_issue('partial', 'aws', 'RegionOptInUnverified')
            return regions

        return [region for region in regions if region not in not_opted_in]

    def _instantiate_facades(self):
        self.ec2 = EC2Facade(self.session, self.owner_id)
        self.acm = AcmFacade(self.session)
        self.awslambda = LambdaFacade(self.session)
        self.cloudformation = CloudFormation(self.session)
        self.cloudtrail = CloudTrailFacade(self.session)
        self.cloudwatch = CloudWatch(self.session)
        self.config = ConfigFacade(self.session)
        self.directconnect = DirectConnectFacade(self.session)
        self.dynamodb = DynamoDBFacade(self.session)
        self.efs = EFSFacade(self.session)
        self.elasticache = ElastiCacheFacade(self.session)
        self.route53 = Route53Facade(self.session)
        self.cloudfront = CloudFront(self.session)
        self.codebuild = CodeBuild(self.session)
        self.elb = ELBFacade(self.session)
        self.elbv2 = ELBv2Facade(self.session)
        self.iam = IAMFacade(self.session)
        self.kms = KMSFacade(self.session)
        self.rds = RDSFacade(self.session)
        self.redshift = RedshiftFacade(self.session)
        self.s3 = S3Facade(self.session)
        self.ses = SESFacade(self.session)
        self.sns = SNSFacade(self.session)
        self.sqs = SQSFacade(self.session)
        self.secretsmanager = SecretsManagerFacade(self.session)
        self.emr = EMRFacade(self.session)

        # Instantiate facades for proprietary services
        try:
            self.cognito = CognitoFacade(self.session)
        except NameError:
            pass
        try:
            self.docdb = DocDBFacade(self.session)
        except NameError:
            pass
        try:
            self.ecs = ECSFacade(self.session)
        except NameError:
            pass
        try:
            self.ecr = ECRFacade(self.session)
        except NameError:
            pass
        try:
            self.eks = EKSFacade(self.session)
        except NameError:
            pass
        try:
            self.guardduty = GuardDutyFacade(self.session)
        except NameError:
            pass
        try:
            self.ssm = SSMFacade(self.session)
        except NameError:
            pass
