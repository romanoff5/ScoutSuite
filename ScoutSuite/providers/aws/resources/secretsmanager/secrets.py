"""Secrets Manager secret metadata normalization (RC9).

Derived single-field statuses keep rule conditions and evidence classifiers in
agreement: rotation_status, unused_status and policy_exposure. Original
SDK values (dates, ARNs, tags, rotation rules, policy) are preserved alongside.
"""
import re
from datetime import datetime, timezone

from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id

UNUSED_AFTER_DAYS = 90
ACCOUNT_IN_PRINCIPAL = re.compile(r'^(?:arn:aws[a-zA-Z-]*:(?:iam|sts)::)?(\d{12})(?::|$)')
# Condition keys that bind a wildcard principal to an identifiable caller set.
RESTRICTING_CONDITION_KEYS = frozenset(key.lower() for key in (
    'aws:PrincipalOrgID', 'aws:PrincipalOrgPaths', 'aws:PrincipalAccount', 'aws:PrincipalArn',
    'aws:SourceAccount', 'aws:SourceArn', 'aws:SourceOrgID', 'aws:SourceOrgPaths',
    'aws:SourceVpc', 'aws:SourceVpce', 'aws:userid'))


def _as_list(value):
    return value if isinstance(value, list) else [value]


def _restricting_condition(condition):
    if not isinstance(condition, dict):
        return False
    return any(isinstance(block, dict) and any(str(key).lower() in RESTRICTING_CONDITION_KEYS for key in block)
               for block in condition.values())


def analyze_policy(policy, policy_status, account_id):
    """Return (exposure, external_principals) for a secret resource policy.

    exposure is one of none, private, conditional, cross_account, public, unknown.
    """
    if policy_status == 'none':
        return 'none', []
    if policy_status != 'present' or not isinstance(policy, dict):
        return 'unknown', []
    statements = policy.get('Statement')
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return 'unknown', []
    public = conditional = False
    external = []
    for statement in statements:
        if not isinstance(statement, dict):
            return 'unknown', []
        if statement.get('Effect') != 'Allow':
            continue
        if 'NotPrincipal' in statement:
            public = True  # Allow + NotPrincipal grants everyone outside the exclusion.
            continue
        principal = statement.get('Principal')
        aws = principal.get('AWS') if isinstance(principal, dict) else principal
        values = [] if aws is None else _as_list(aws)
        if not all(isinstance(value, str) for value in values):
            return 'unknown', []
        if '*' in values:
            if _restricting_condition(statement.get('Condition')):
                conditional = True
            else:
                public = True
            continue
        for value in values:
            match = ACCOUNT_IN_PRINCIPAL.match(value)
            if match is None:
                return 'unknown', []
            if match.group(1) != account_id and value not in external:
                external.append(value)
    if public:
        return 'public', external
    if external:
        return 'cross_account', external
    return ('conditional' if conditional else 'private'), external


def _date(value):
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return None


def unused_status(secret, as_of):
    """in_use, unused, recently_created, scheduled_for_deletion or unknown."""
    if secret.get('deleted_date') is not None:
        return 'scheduled_for_deletion', None
    accessed = _date(secret.get('last_accessed_date'))
    if accessed is not None:
        days = (as_of.date() - accessed.date()).days
        return ('unused' if days > UNUSED_AFTER_DAYS else 'in_use'), days
    if secret.get('last_accessed_date') is not None:
        return 'unknown', None
    # AWS omits LastAccessedDate when the secret was never retrieved in the Region.
    created = _date(secret.get('created_date'))
    if created is None or secret.get('details_status') != 'complete':
        return 'unknown', None
    if (as_of.date() - created.date()).days > UNUSED_AFTER_DAYS:
        return 'unused', None
    return 'recently_created', None


def rotation_status(secret):
    if secret.get('deleted_date') is not None:
        return 'scheduled_for_deletion'
    enabled = secret.get('rotation_enabled')
    if enabled is True:
        return 'enabled'
    if enabled is False:
        return 'disabled'
    # DescribeSecret omits RotationEnabled when rotation was never configured.
    return 'disabled' if secret.get('details_status') == 'complete' else 'unknown'


class Secrets(AWSResources):
    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        as_of = datetime.now(timezone.utc)
        for raw_secret in await self.facade.secretsmanager.get_secrets(self.region):
            id, secret = self._parse_secret(raw_secret, as_of)
            self[id] = secret

    def _parse_secret(self, raw_secret, as_of=None):
        as_of = as_of or datetime.now(timezone.utc)
        secret_dict = {}
        secret_dict['id'] = get_non_provider_id(raw_secret.get('ARN'))
        secret_dict['arn'] = raw_secret.get('ARN')
        secret_dict['name'] = raw_secret.get('Name')
        secret_dict['description'] = raw_secret.get('Description')
        secret_dict['created_date'] = raw_secret.get('CreatedDate')
        secret_dict['last_changed_date'] = raw_secret.get('LastChangedDate')
        secret_dict['last_accessed_date'] = raw_secret.get('LastAccessedDate')
        secret_dict['last_rotated_date'] = raw_secret.get('LastRotatedDate')
        secret_dict['next_rotation_date'] = raw_secret.get('NextRotationDate')
        secret_dict['deleted_date'] = raw_secret.get('DeletedDate')
        secret_dict['owning_service'] = raw_secret.get('OwningService')
        secret_dict['primary_region'] = raw_secret.get('PrimaryRegion')
        secret_dict['replication_status'] = raw_secret.get('ReplicationStatus')
        secret_dict['tags'] = raw_secret.get('Tags')
        secret_dict['secret_versions_to_stages'] = raw_secret.get('SecretVersionsToStages') or \
            raw_secret.get('VersionIdsToStages')
        secret_dict['kms'] = raw_secret.get('KmsKeyId')
        secret_dict['kms_key_type'] = 'aws_managed' if secret_dict['kms'] in (None, '', 'alias/aws/secretsmanager') \
            else 'customer_managed'
        secret_dict['details_status'] = raw_secret.get('_details_status', 'unknown')
        secret_dict['rotation_enabled'] = raw_secret.get('RotationEnabled')
        secret_dict['rotation'] = secret_dict['rotation_enabled'] is True  # Legacy boolean field.
        secret_dict['rotation_lambda_arn'] = raw_secret.get('RotationLambdaARN')
        rules = raw_secret.get('RotationRules') if isinstance(raw_secret.get('RotationRules'), dict) else {}
        secret_dict['rotation_interval'] = rules.get('AutomaticallyAfterDays')
        secret_dict['rotation_schedule'] = rules.get('ScheduleExpression')
        secret_dict['rotation_window'] = rules.get('Duration')
        secret_dict['rotation_status'] = rotation_status(secret_dict)
        secret_dict['unused_status'], secret_dict['days_since_last_access'] = unused_status(secret_dict, as_of)
        secret_dict['unused_threshold_days'] = UNUSED_AFTER_DAYS
        secret_dict['policy'] = raw_secret.get('policy') or {}
        secret_dict['policy_status'] = raw_secret.get('_policy_status', 'unknown')
        arn_parts = (secret_dict['arn'] or '').split(':')
        account_id = arn_parts[4] if len(arn_parts) > 5 else None
        secret_dict['policy_exposure'], secret_dict['policy_external_principals'] = analyze_policy(
            secret_dict['policy'], secret_dict['policy_status'], account_id)
        return secret_dict['id'], secret_dict
