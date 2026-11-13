from datetime import datetime, timedelta, timezone
from dateutil.parser import parse as parse_date

from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources

from ScoutSuite.providers.utils import get_non_provider_id


class Certificates(AWSResources):
    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        raw_certificates = await self.facade.acm.get_certificates(self.region)
        for raw_certificate in raw_certificates:
            name, resource = self._parse_certificate(raw_certificate)
            self[name] = resource

    @staticmethod
    def _expiry_evidence(cert, now=None):
        """Only DescribeCertificate.NotAfter is evidence of the expiry date."""
        stamp = cert.get('NotAfter')
        try:
            if isinstance(stamp, str):
                stamp = parse_date(stamp)
            if not isinstance(stamp, datetime):
                return 'unknown', None
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
            else:
                stamp = stamp.astimezone(timezone.utc)
            now = now or datetime.now(timezone.utc)
            delta = stamp - now
            seconds = delta.total_seconds()
            if seconds < 0:
                return 'expired', round(seconds / 86400, 2)
            if delta <= timedelta(days=45):
                return 'expiring_soon', round(seconds / 86400, 2)
            return 'valid', round(seconds / 86400, 2)
        except (ValueError, TypeError, OverflowError):
            return 'unknown', None

    def _parse_certificate(self, raw_certificate):
        # Do not mutate the SDK response used by other collectors.
        certificate = dict(raw_certificate)
        certificate['name'] = certificate.get('DomainName')
        certificate['id'] = get_non_provider_id(certificate['name'])
        certificate['arn'] = certificate.get('CertificateArn', certificate.get('DomainName'))
        status, days = self._expiry_evidence(certificate)
        certificate['expiry_status'] = status
        certificate['days_until_expiry'] = days
        certificate['renewal_review_status'] = self._renewal_review(certificate)
        return certificate['id'], certificate

    @staticmethod
    def _renewal_review(cert):
        """Imported, active certs due within 90 days need manual renewal evidence."""
        kind, usage = cert.get('Type'), cert.get('InUseBy')
        if not isinstance(kind, str) or not isinstance(usage, list):
            return 'unknown'
        if kind != 'IMPORTED' or not usage:
            return 'not_applicable'
        days = cert.get('days_until_expiry')
        if not isinstance(days, (int, float)):
            return 'unknown'
        return 'review_due' if days <= 90 else 'not_due'
