"""Token-based AWS API pagination with explicit incomplete-result diagnostics.

Models and permitted request keys are validated by offline SDK-contract tests.
No SDK session, credentials or network access are created here.
"""
from botocore.exceptions import ClientError, ConnectTimeoutError, EndpointConnectionError, ReadTimeoutError

from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.utils import run_concurrently


class PaginationError(RuntimeError):
    """Collection failed; the successfully obtained pages remain available."""

    def __init__(self, reason_code, items):
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.items = items


def _read(response, path, *, optional=False):
    current = response
    for index, key in enumerate(path):
        if not isinstance(current, dict):
            raise ValueError('MalformedResponse')
        if key not in current:
            if optional and index == len(path) - 1:
                return None
            raise ValueError('MalformedResponse')
        current = current[key]
    return current


def _reason(exception):
    if isinstance(exception, ClientError):
        code = exception.response.get('Error', {}).get('Code')
        if code in ('AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation',
                    'AuthorizationError', 'AccessDeniedFault'):
            return 'denied', 'AccessDenied'
        if code in ('UnsupportedOperation', 'UnknownOperationException', 'InvalidAction'):
            return 'unsupported', 'UnsupportedOperation'
        if code in ('Throttling', 'ThrottlingException', 'RequestLimitExceeded',
                    'TooManyRequestsException', 'RequestThrottled'):
            return 'failed', 'Throttled'
        return 'failed', 'ClientError'
    if isinstance(exception, (ReadTimeoutError, ConnectTimeoutError, EndpointConnectionError)):
        return 'failed', 'Timeout'
    if isinstance(exception, ValueError):
        return 'failed', str(exception) if str(exception) in (
            'MalformedResponse', 'RepeatedToken', 'MissingContinuationToken',
            'PageLimitExceeded') else 'MalformedResponse'
    return 'failed', 'ApiFailure'


async def collect_token_pages(operation, *, items_path, input_token, output_token,
                              scope, first_kwargs=None, truncated_path=None,
                              page_limit=100000, record_failure=True):
    """Accumulate all pages; never silently mislabel a failed page as successful.

    first_kwargs includes pagination page size. No token is sent on the first
    request. Values are kept in legacy list form for existing resource adapters.
    """
    collected = []
    seen = set()
    next_token = None
    for _page in range(page_limit):
        arguments = dict(first_kwargs or {})
        if next_token is not None:
            arguments[input_token] = next_token
        try:
            response = await run_concurrently(lambda: operation(**arguments))
            if not isinstance(response, dict):
                raise ValueError('MalformedResponse')
            page_items = _read(response, items_path, optional=True)
            if page_items is None:
                page_items = []
            if not isinstance(page_items, list):
                raise ValueError('MalformedResponse')
            token = _read(response, output_token, optional=True)
            truncated = _read(response, truncated_path) if truncated_path else bool(token)
            if truncated_path and not isinstance(truncated, bool):
                raise ValueError('MalformedResponse')
            if truncated and (not isinstance(token, str) or not token):
                raise ValueError('MissingContinuationToken')
            if token and (not isinstance(token, str) or token in seen):
                raise ValueError('RepeatedToken')
            collected.extend(page_items)
            if not truncated:
                return collected
            seen.add(token)
            next_token = token
        except Exception as exc:
            status, reason = _reason(exc)
            if record_failure:
                context = get_current_run_context()
                if context is not None:
                    context.record_collection_issue(
                        'partial' if collected else status, scope, reason
                    )
            raise PaginationError(reason, collected) from exc
    if record_failure:
        context = get_current_run_context()
        if context is not None:
            context.record_collection_issue(
                'partial' if collected else 'failed', scope, 'PageLimitExceeded'
            )
    raise PaginationError('PageLimitExceeded', collected)
