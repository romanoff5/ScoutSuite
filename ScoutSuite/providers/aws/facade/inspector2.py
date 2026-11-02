"""Read-only, own-account Inspector v2 status per selected AWS Region."""
import re

from botocore.exceptions import ClientError

from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently


SCAN_TYPES = ('ec2', 'ecr', 'lambda', 'lambdaCode', 'codeRepository')
DENIED = ('AccessDeniedException', 'AccessDenied', 'UnauthorizedOperation')
UNSUPPORTED = ('UnsupportedOperationException', 'UnknownOperationException')


class Inspector2PublicFacade(AWSBaseFacade):
    def __init__(self, session, owner_id):
        super().__init__(session)
        self.owner_id = owner_id

    async def get_account_status(self, region):
        """Read only the current account; never enumerate organization accounts."""
        context = get_current_run_context()

        def issue(kind, reason):
            if context is not None:
                context.record_collection_issue(kind, 'inspector2', reason)

        if not isinstance(self.owner_id, str) or re.fullmatch(r'[0-9]{12}', self.owner_id) is None:
            issue('failed', 'InvalidAccountId')
            return None
        client = AWSFacadeUtils.get_client('inspector2', self.session, region)
        if client is None:
            issue('failed', 'ClientConstruction')
            return None
        try:
            response = await run_concurrently(
                lambda: client.batch_get_account_status(accountIds=[self.owner_id]))
        except ClientError as error:
            code = error.response.get('Error', {}).get('Code', '')
            kind = ('denied' if code in DENIED else
                    'unsupported' if code in UNSUPPORTED else 'failed')
            issue(kind, 'BatchGetAccountStatus' + kind.capitalize())
            return None
        except Exception:
            issue('failed', 'BatchGetAccountStatusError')
            return None
        if not isinstance(response, dict):
            issue('failed', 'MalformedAccountStatus')
            return None
        accounts = response.get('accounts')
        failed = response.get('failedAccounts', [])
        if not isinstance(accounts, list) or not isinstance(failed, list):
            issue('failed', 'MalformedAccountStatus')
            return None
        if failed:
            issue('partial', 'FailedAccountStatus')
            return None
        if len(accounts) != 1 or not isinstance(accounts[0], dict):
            issue('failed', 'UnexpectedAccountScope')
            return None
        account = accounts[0]
        if account.get('accountId') != self.owner_id:
            issue('failed', 'UnexpectedAccountScope')
            return None
        state = account.get('state')
        resource_state = account.get('resourceState')
        if not isinstance(state, dict) or not isinstance(resource_state, dict):
            issue('failed', 'MalformedAccountState')
            return None
        status = state.get('status')
        if not isinstance(status, str) or not status:
            issue('failed', 'MalformedAccountState')
            return None
        scan_types = {}
        for key in SCAN_TYPES:
            detail = resource_state.get(key)
            if detail is None:
                scan_types[key] = None
                if key in ('ec2', 'ecr'):
                    issue('partial', 'MissingRequiredScanType')
                continue
            if not isinstance(detail, dict):
                issue('partial', 'MalformedScanType')
                scan_types[key] = None
                continue
            value = detail.get('status')
            if not isinstance(value, str) or not value:
                issue('partial', 'MalformedScanType')
                scan_types[key] = None
            else:
                scan_types[key] = value
        return {'account_id': self.owner_id, 'status': status, 'scan_types': scan_types}
