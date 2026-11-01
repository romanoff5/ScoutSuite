"""Run context management for synchronous and asynchronous execution.

This module provides explicit event loop, executor, throttler lifecycle management
per run, avoiding shared state and caller-loop interference.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextvars import ContextVar, Token
from contextlib import contextmanager
from dataclasses import dataclass, field
import logging
import threading
from typing import Any, Optional, Set

from asyncio_throttle import Throttler


_active_context: ContextVar[Optional['RunContext']] = ContextVar('scoutsuite_context', default=None)


def get_current_run_context() -> Optional['RunContext']:
    """Execution-scoped resources; never stored on the event loop."""
    return _active_context.get()


@dataclass
class RunContext:
    """Manages loop, executor, throttler, and cancellation per run.
    
    This provides explicit lifecycle management for ScoutSuite runs,
    ensuring proper isolation between runs and avoiding shared state
    pollution.
    
    Attributes:
        provider: The cloud provider being used (aws, azure, gcp, etc.)
        max_workers: Maximum number of worker threads for the executor
        max_rate: Optional rate limit for API calls (uses Throttler)
        _loop: The event loop for this run
        _executor: The thread pool executor
        _throttler: The rate limiter
        _owns_loop: Whether we created the loop ourselves
    """
    provider: str
    max_workers: int = 10
    max_rate: Optional[int] = None
    _loop: Optional[asyncio.AbstractEventLoop] = field(default=None, init=False, repr=False)
    _executor: Optional[ThreadPoolExecutor] = field(default=None, init=False, repr=False)
    _throttler: Optional[Throttler] = field(default=None, init=False, repr=False)
    _owns_loop: bool = field(default=False, init=False, repr=False)
    _token: Optional[Token] = field(default=None, init=False, repr=False)
    _children: Set[asyncio.Future] = field(default_factory=set, init=False, repr=False)
    _clients: dict = field(default_factory=dict, init=False, repr=False)
    _client_lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)
    
    def __post_init__(self):
        """Initialize the run context components."""
        # Create our own throttler with the specified rate limit
        self._throttler = Throttler(
            rate_limit=self.max_rate if self.max_rate else 999999,
            period=1
        )
    
    @property
    def loop(self) -> asyncio.AbstractEventLoop:
        """Borrow a running loop; otherwise allocate a private one (never install it)."""
        if self._loop is not None and not self._loop.is_closed():
            return self._loop
        try:
            self._loop = asyncio.get_running_loop()
            self._owns_loop = False
        except RuntimeError:
            self._loop = asyncio.new_event_loop()
            self._owns_loop = True
        return self._loop

    @property
    def executor(self) -> ThreadPoolExecutor:
        """Get or create the thread pool executor for this run."""
        if self._executor is None:
            self._executor = ThreadPoolExecutor(max_workers=self.max_workers)
        return self._executor
    
    @property
    def throttler(self) -> Throttler:
        """Get the throttler for this run."""
        return self._throttler
    
    def setup(self) -> 'RunContext':
        """Bind resources to the current task without replacing any event loop."""
        if self._token is not None:
            raise RuntimeError('RunContext is already set up')
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is not None:
            if self._loop is not None and self._loop is not running:
                raise RuntimeError('RunContext already bound to another event loop')
            self._loop = running
            self._owns_loop = False
        else:
            self.loop  # create a private loop for sync RunContext clients
        self._token = _active_context.set(self)
        return self

    def track_future(self, future: asyncio.Future) -> asyncio.Future:
        """Record only future/task work started by this assessment."""
        if future.get_loop() is not self.loop:
            raise RuntimeError('Cannot track future from another event loop')
        self._children.add(future)
        future.add_done_callback(self._children.discard)
        return future

    def get_cached_client(self, session, service, region, factory):
        """Cache SDK clients within one assessment and session identity.

        Locking prevents duplicate construction during concurrent collector calls.
        Keeping the session reference prevents identity reuse before cleanup.
        """
        key = (id(session), service, region)
        with self._client_lock:
            if key not in self._clients:
                self._clients[key] = (session, factory())
            return self._clients[key][1]

    def close_clients(self) -> None:
        """Close each SDK client once, including on exceptional shutdown."""
        with self._client_lock:
            clients = list(self._clients.values())
            self._clients.clear()
        for _session, client in clients:
            close = getattr(client, 'close', None)
            if callable(close):
                try:
                    close()
                except Exception as exc:
                    logging.getLogger('scout').warning(
                        'Unable to close SDK client (%s)', type(exc).__name__
                    )

    def cancel_all_tasks(self) -> None:
        """Cancel this assessment's tracked work, not the caller's other tasks."""
        for future in tuple(self._children):
            if not future.done():
                future.cancel()

    def _release_loop(self) -> None:
        if self._token is not None:
            _active_context.reset(self._token)
            self._token = None
        if self._owns_loop and self._loop is not None and not self._loop.is_closed():
            if self._loop.is_running():
                raise RuntimeError('Cannot close a running event loop')
            self._loop.close()
        self._loop = None
        self._owns_loop = False
        self._children.clear()

    async def aclose(self) -> None:
        """Drain owned tasks and join workers without blocking the event loop."""
        self.cancel_all_tasks()
        try:
            if self._children:
                await asyncio.gather(*tuple(self._children), return_exceptions=True)
            if self._executor is not None:
                executor, self._executor = self._executor, None
                # Workers may be waiting for callbacks scheduled on this loop.
                await asyncio.to_thread(executor.shutdown, wait=True, cancel_futures=True)
            await asyncio.to_thread(self.close_clients)
        finally:
            self._release_loop()

    def cleanup(self) -> None:
        """Sync compatibility cleanup; async paths must use aclose()."""
        self.cancel_all_tasks()
        if self._executor is not None:
            executor, self._executor = self._executor, None
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                wait = True
            else:
                wait = False
            executor.shutdown(wait=wait, cancel_futures=True)
        self.close_clients()
        self._release_loop()

    def run_until_complete(self, coro) -> Any:
        """Run a coroutine to completion in this context's loop.
        
        Args:
            coro: The coroutine to run
            
        Returns:
            The result of the coroutine
        """
        return self.loop.run_until_complete(coro)
    
    @contextmanager
    def lifecycle(self):
        """Context manager for the full run lifecycle.
        
        Sets up and tears down resources properly.
        """
        try:
            self.setup()
            yield self
        finally:
            self.cleanup()


@dataclass
class CollectionStatus:
    """Status metadata for collection/evaluation operations.
    
    Provides explicit visibility into what happened during collection:
    - success: Operation completed with data (even if empty)
    - denied: Access was denied (insufficient permissions)
    - unsupported: Service/feature not supported in this context
    - failed: Operation raised an unexpected exception
    - partial: Some items succeeded, some failed
    - not_applicable: Rule doesn't apply to this resource type
    """
    status: str  # one of: success, denied, unsupported, failed, partial, not_applicable
    message: str = ""
    resource_ids: list = field(default_factory=list)
    checked_items: int = 0
    flagged_items: int = 0
    
    @classmethod
    def success(cls, resource_ids: list = None, checked: int = 0, flagged: int = 0) -> 'CollectionStatus':
        """Create a successful collection status."""
        return cls(
            status='success',
            resource_ids=resource_ids or [],
            checked_items=checked,
            flagged_items=flagged
        )
    
    @classmethod
    def denied(cls, message: str, resource_ids: list = None) -> 'CollectionStatus':
        """Create a denied collection status (insufficient permissions)."""
        return cls(
            status='denied',
            message=message,
            resource_ids=resource_ids or []
        )
    
    @classmethod
    def unsupported(cls, message: str, resource_ids: list = None) -> 'CollectionStatus':
        """Create an unsupported collection status."""
        return cls(
            status='unsupported',
            message=message,
            resource_ids=resource_ids or []
        )
    
    @classmethod
    def failed(cls, message: str, resource_ids: list = None) -> 'CollectionStatus':
        """Create a failed collection status."""
        return cls(
            status='failed',
            message=message,
            resource_ids=resource_ids or []
        )
    
    @classmethod
    def partial(cls, message: str, resource_ids: list = None) -> 'CollectionStatus':
        """Create a partial collection status."""
        return cls(
            status='partial',
            message=message,
            resource_ids=resource_ids or []
        )
    
    @classmethod
    def not_applicable(cls, resource_ids: list = None) -> 'CollectionStatus':
        """Create a not applicable status."""
        return cls(
            status='not_applicable',
            resource_ids=resource_ids or []
        )
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        result = {'status': self.status}
        if self.message:
            result['message'] = self.message
        if self.resource_ids:
            result['resource_ids'] = self.resource_ids
        if self.checked_items:
            result['checked_items'] = self.checked_items
        if self.flagged_items:
            result['flagged_items'] = self.flagged_items
        return result


def is_success(status: CollectionStatus) -> bool:
    """Check if a collection status represents a successful operation.
    
    Even an empty result is considered success - we must not confuse
    'no data collected' with 'something went wrong'.
    """
    return status.status == 'success'


def is_complete(status: CollectionStatus) -> bool:
    """Check if a collection status represents a complete assessment."""
    return status.status in ('success', 'not_applicable')