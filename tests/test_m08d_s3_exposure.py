"""M08-D effective S3 BPA, ownership, exposure and rule-engine contracts."""
import asyncio
from copy import deepcopy
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.rule_evidence import classify_s3_bucket_exposure
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.output.result_encoder import ScoutResultEncoder
from ScoutSuite.providers.aws.resources.s3.base import S3
from ScoutSuite.providers.aws.resources.s3.exposure import (
    PUBLIC_ACCESS_KEYS, classify_bucket_exposure, combine_public_access_blocks
)
from tests.fixtures import ROOT


PROFILE = ROOT / 'ScoutSuite/providers/aws/rules/rulesets/aws-s3-evidence-2026-11.json'


def block(value):
    return {name: value for name in PUBLIC_ACCESS_KEYS}


def acl_public():
    return {
        'AllUsers': {
            'URI': 'http://acs.amazonaws.com/groups/global/AllUsers',
            'permissions': {'read': True}
        }
    }


def item(**fields):
    data = {
        'default_encryption_enabled': True,
        'default_encryption_algorithm': 'AES256',
        'encryption_evidence': 'aws_baseline',
        'secure_transport_enabled': True,
        'policy_is_public': False,
        'acl_collection_status': 'success',
        'grantees': {},
        'object_ownership': 'BucketOwnerEnforced',
        'public_access_block_configuration': block(False)
    }
    data.update(fields)
    return data


class TestM08DS3Exposure(TestCase):
    def test_effective_bpa_is_tristate_and_never_mutates_originals(self):
        a = block(False)
        b = block(False)
        a['RestrictPublicBuckets'] = True
        b['IgnorePublicAcls'] = True
        before_a, before_b = deepcopy(a), deepcopy(b)
        effective = combine_public_access_blocks(a, b)
        self.assertTrue(effective['RestrictPublicBuckets'])
        self.assertTrue(effective['IgnorePublicAcls'])
        self.assertFalse(effective['BlockPublicPolicy'])
        self.assertEqual(a, before_a)
        self.assertEqual(b, before_b)
        self.assertIsNone(combine_public_access_blocks(None, None)['RestrictPublicBuckets'])
        self.assertTrue(combine_public_access_blocks(
            None, {'RestrictPublicBuckets': True})['RestrictPublicBuckets'])
        self.assertIsNone(combine_public_access_blocks(
            None, {'RestrictPublicBuckets': False})['RestrictPublicBuckets'])

    def test_public_policy_is_exposed_unless_existing_policy_is_restricted(self):
        exposed = item(policy_is_public=True)
        self.assertEqual(classify_bucket_exposure(exposed),
                         ('exposed', ['PublicBucketPolicy']))
        restricted = item(policy_is_public=True)
        restricted['public_access_block_configuration']['RestrictPublicBuckets'] = True
        self.assertEqual(classify_bucket_exposure(restricted)[0],
                         'no_bucket_level_exposure_detected')
        # Preventative BlockPublicPolicy does NOT suppress an existing public policy.
        preventative = item(policy_is_public=True)
        preventative['public_access_block_configuration']['BlockPublicPolicy'] = True
        self.assertEqual(classify_bucket_exposure(preventative)[0], 'exposed')

    def test_acl_only_exposure_and_existing_acl_suppression(self):
        exposed = item(object_ownership='ObjectWriter', grantees=acl_public())
        self.assertEqual(classify_bucket_exposure(exposed)[0], 'exposed')
        self.assertEqual(classify_bucket_exposure(item(
            object_ownership='BucketOwnerEnforced', grantees=acl_public()))[0],
            'no_bucket_level_exposure_detected')
        ignored = item(object_ownership='ObjectWriter', grantees=acl_public())
        ignored['public_access_block_configuration']['IgnorePublicAcls'] = True
        self.assertEqual(classify_bucket_exposure(ignored)[0],
                         'no_bucket_level_exposure_detected')
        blocked_new = item(object_ownership='ObjectWriter', grantees=acl_public())
        blocked_new['public_access_block_configuration']['BlockPublicAcls'] = True
        self.assertEqual(classify_bucket_exposure(blocked_new)[0], 'exposed')

    def test_unknown_ownership_does_not_make_acl_exposure_certain(self):
        uncertain = item(object_ownership=None, grantees=acl_public())
        self.assertEqual(classify_bucket_exposure(uncertain)[0], 'unknown')
        uncertain['public_access_block_configuration']['IgnorePublicAcls'] = True
        self.assertEqual(classify_bucket_exposure(uncertain)[0],
                         'no_bucket_level_exposure_detected')

    def test_denied_reads_and_unverified_account_constraints_are_unknown(self):
        unknown = item(policy_is_public=None, acl_collection_status='failed')
        self.assertEqual(classify_bucket_exposure(unknown)[0], 'unknown')
        self.assertEqual(classify_s3_bucket_exposure(unknown), 'unknown')
        policy = item(policy_is_public=True)
        policy['public_access_block_configuration']['RestrictPublicBuckets'] = None
        self.assertEqual(classify_bucket_exposure(policy)[0], 'unknown')

    def test_s3_finalize_preserves_raw_bucket_bpa_and_sets_provenance(self):
        async def scenario():
            service = S3(Mock())
            source = block(False)
            source['IgnorePublicAcls'] = True
            raw = item(public_access_block_configuration=source,
                       policy_is_public=True)
            service['public_access_block_configuration'] = block(False)
            service['public_access_block_configuration']['RestrictPublicBuckets'] = True
            service['buckets'] = {'example': raw}
            await service.finalize()
            self.assertTrue(raw['public_access_block_configuration'][
                'RestrictPublicBuckets'])
            self.assertFalse(raw['bucket_public_access_block_configuration'][
                'RestrictPublicBuckets'])
            self.assertTrue(raw['bucket_public_access_block_configuration'][
                'IgnorePublicAcls'])
            self.assertEqual(source['RestrictPublicBuckets'], False)
            self.assertEqual(raw['public_exposure_status'],
                             'no_bucket_level_exposure_detected')

            missing = S3(Mock())
            missing['public_access_block_configuration'] = None
            missing['buckets'] = {'unknown': item(
                public_access_block_configuration=None,
                policy_is_public=True, object_ownership='ObjectWriter'
            )}
            await missing.finalize()
            self.assertEqual(missing['buckets']['unknown']['public_exposure_status'],
                             'unknown')
        asyncio.run(scenario())

    def test_rule_engine_preserves_ids_and_marks_unknown_evidence(self):
        async def scenario():
            ctx = RunContext('aws').setup()
            dataset = {
                'secure': item(public_exposure_status='no_bucket_level_exposure_detected'),
                'exposed': item(
                    default_encryption_enabled=False,
                    default_encryption_algorithm=None,
                    encryption_evidence='api',
                    secure_transport_enabled=False,
                    public_exposure_status='exposed'
                ),
                'denied': item(
                    default_encryption_enabled=None,
                    default_encryption_algorithm=None,
                    encryption_evidence='unverified',
                    secure_transport_enabled=None,
                    public_exposure_status='unknown'
                )
            }
            provider = SimpleNamespace(services={'s3': {'buckets': dataset}},
                                       service_list=['s3'])
            try:
                ruleset = Ruleset('aws', filename=str(PROFILE))
                self.assertEqual(ruleset.profile_id, 'aws-s3-evidence')
                ProcessingEngine(ruleset).run(provider)
                checks = {
                    's3-bucket-no-default-encryption':
                        's3.buckets.exposed.default_encryption_enabled',
                    's3-bucket-allowing-cleartext':
                        's3.buckets.exposed.secure_transport_enabled',
                    's3-bucket-effective-public-exposure':
                        's3.buckets.exposed.public_exposure_status'
                }
                for key, expected in checks.items():
                    finding = provider.services['s3']['findings'][key]
                    self.assertEqual(finding['items'], [expected])
                    self.assertEqual(finding['flagged_items'], 1)
                    self.assertEqual(finding['checked_items'], 3)
                    self.assertEqual(finding['assessment_status'], 'incomplete')
                    self.assertEqual(finding['evaluation_summary']['counts'], {
                        'secure': 1, 'insecure': 1, 'unknown': 1,
                        'not_applicable': 0
                    })
                    self.assertEqual(finding['policy_profile']['version'], '2026.11.0')
                encoded = ScoutResultEncoder.to_dict(provider)
                self.assertEqual(
                    encoded['services']['s3']['findings'][
                        's3-bucket-effective-public-exposure']['items'],
                    ['s3.buckets.exposed.public_exposure_status']
                )
                # RunContext deduplicates identical issue tuples per scope.
                self.assertEqual(ctx.collection_issues, [{
                    'status': 'partial', 'scope': 's3',
                    'reason_code': 'RuleEvidenceUnknown'
                }])
            finally:
                await ctx.aclose()
        asyncio.run(scenario())
