"""Read-only bounded GuardDuty detector inventory (M10-B).

Never fetch GuardDuty findings, member accounts, IP sets or trusted lists.
"""
from botocore.exceptions import ClientError

from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently


MAX_PAGES = 1000
MAX_DETECTORS = 50000


class GuardDutyPublicFacade(AWSBaseFacade):
    async def get_detectors(self, region):
        context = get_current_run_context()

        def issue(state, reason):
            if context is not None:
                context.record_collection_issue(state, 'guardduty', reason)

        client = AWSFacadeUtils.get_client('guardduty', self.session, region)
        if client is None:
            issue('failed', 'ClientConstruction')
            return []

        identifiers = []
        seen_ids = set()
        seen_tokens = set()
        token = None
        listing_complete = False
        for _ in range(MAX_PAGES):
            params = {'MaxResults': 50}
            if token is not None:
                params['NextToken'] = token
            try:
                response = await run_concurrently(
                    lambda params=params: client.list_detectors(**params))
            except ClientError as error:
                code = error.response.get('Error', {}).get('Code', '')
                kind = 'denied' if code in ('AccessDeniedException', 'AccessDenied', 'UnauthorizedOperation') \
                    else 'unsupported' if code in ('UnsupportedOperationException', 'UnknownOperationException') \
                    else 'failed'
                issue('partial' if identifiers else kind, 'ListDetectors' + kind.capitalize())
                break
            except Exception:
                issue('partial' if identifiers else 'failed', 'ListDetectorsError')
                break

            batch = response.get('DetectorIds') if isinstance(response, dict) else None
            if not isinstance(batch, list) or any(not isinstance(k, str) or not k for k in batch):
                issue('partial' if identifiers else 'failed', 'MalformedDetectorList')
                break
            for detector_id in batch:
                if detector_id in seen_ids:
                    issue('partial', 'DuplicateDetector')
                    continue
                if len(identifiers) >= MAX_DETECTORS:
                    issue('partial', 'DetectorLimit')
                    break
                seen_ids.add(detector_id)
                identifiers.append(detector_id)
            else:
                following = response.get('NextToken')
                if not following:
                    listing_complete = True
                    break
                if not isinstance(following, str) or following in seen_tokens:
                    issue('partial', 'InvalidPaginationToken')
                    break
                seen_tokens.add(following)
                token = following
                continue
            break
        else:
            issue('partial', 'PageLimit')

        if not listing_complete and not identifiers:
            self._record_census(region, False, 0)
            return []

        results = []
        for detector_id in identifiers:
            try:
                response = await run_concurrently(
                    lambda detector_id=detector_id: client.get_detector(DetectorId=detector_id))
            except ClientError as error:
                code = error.response.get('Error', {}).get('Code', '')
                issue('partial', 'GetDetectorDenied' if code in
                      ('AccessDeniedException', 'AccessDenied', 'UnauthorizedOperation')
                      else 'GetDetectorError')
                continue
            except Exception:
                issue('partial', 'GetDetectorError')
                continue
            if not isinstance(response, dict) or not isinstance(response.get('Status'), str):
                issue('partial', 'MalformedDetectorDetail')
                continue
            results.append({
                'detector_id': detector_id,
                'status': response['Status'],
                'finding_publishing_frequency': response.get('FindingPublishingFrequency'),
                'created_at': response.get('CreatedAt'),
                'updated_at': response.get('UpdatedAt'),
                'service_role': response.get('ServiceRole'),
                'features': response.get('Features') or [],
                'data_sources': response.get('DataSources') or {},
                'tags': response.get('Tags') or {},
            })
        self._record_census(region, listing_complete and len(results) == len(identifiers), len(results))
        return results

    def _record_census(self, region, complete, count):
        """Region-level proof that the detector inventory is complete.

        An empty list after a denial or a failed page is never evidence that
        GuardDuty is not enabled; only a fully enumerated region is.
        """
        if not hasattr(self, 'detector_census'):
            self.detector_census = {}
        self.detector_census[region] = {'complete': bool(complete), 'count': count}
