"""Run context management for synchronous and asynchronous execution.

This module provides explicit event loop, executor, throttler lifecycle management
per run, avoiding shared state and caller-loop interference.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Optional

from asyncio_throttle import Throttler


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
    
    def __post_init__(self):
        """Initialize the run context components."""
        # Create our own throttler with the specified rate limit
        self._throttler = Throttler(
            rate_limit=self.max_rate if self.max_rate else 999999,
            period=1
        )
    
    @property
    def loop(self) -> asyncio.AbstractEventLoop:
        """Get or create the event loop for this run."""
        if self._loop is None or self._loop.is_closed():
            self._loop = asyncio.new_event_loop()
            self._owns_loop = True
            asyncio.set_event_loop(self._loop)
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
        """Set up the loop with executor and throttler.
        
        Called before running async code to ensure proper configuration.
        """
        loop = self.loop
        # Attach throttler to loop for legacy compatibility
        loop.throttler = self._throttler
        loop.set_default_executor(self.executor)
        return self
    
    def cleanup(self) -> None:
        """Clean up all resources owned by this context.
        
        Closes the executor and event loop if we own them.
        """
        if self._executor is not None:
            self._executor.shutdown(wait=True)
            self._executor = None
        
        if self._owns_loop and self._loop is not None:
            if not self._loop.is_closed():
                self._loop.close()
            self._loop = None
            self._owns_loop = False
    
    def cancel_all_tasks(self) -> None:
        """Cancel all tasks in the loop."""
        if self._loop is not None and not self._loop.is_closed():
            for task in asyncio.all_tasks(self._loop):
                task.cancel()
    
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
    return status.status in ('success', 'unsupported', 'not_applicable')