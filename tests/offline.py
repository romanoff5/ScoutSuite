"""Fail-closed boundaries for trusted tests, installed before application imports.

This is a test guard, not an operating-system sandbox for hostile native code.
Blocked operations remain failures even if a collector catches their exception.
"""

import atexit
from contextlib import contextmanager
from contextvars import ContextVar
import importlib
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import tempfile
import traceback


class OfflineViolation(RuntimeError):
    """A test attempted an operation outside the offline boundary."""


class OfflineGuard:
    def __init__(self):
        self.events = []
        self.last_origin = []
        self.active = True
        self._socketpair = ContextVar('scoutsuite_test_socketpair', default=False)
        self._temporary_home = tempfile.TemporaryDirectory(prefix='scoutsuite-offline-')
        self.home = Path(self._temporary_home.name).resolve()

    def deny(self, category):
        # Never include command arguments, tokens, URLs or file contents in diagnostics.
        self.events.append(category)
        self.last_origin = [Path(frame.filename).name + ':' + str(frame.lineno) + ':' + frame.name
                            for frame in traceback.extract_stack(limit=8)]
        raise OfflineViolation('Offline test boundary blocked: ' + category)

    @contextmanager
    def expect_violation(self, category):
        """Acknowledge exactly one denied operation in a negative boundary test."""
        start = len(self.events)
        try:
            yield
        except OfflineViolation:
            assert self.events[start:] == [category], 'Unexpected offline violation(s)'
            del self.events[start:]
        else:
            raise AssertionError('Expected offline boundary violation: ' + category)

    def assert_no_violations(self):
        events, self.events = self.events, []
        assert not events, ('Unacknowledged offline boundary violation(s): ' + ', '.join(events)
                            + ' from ' + ' -> '.join(self.last_origin))

    def _audit(self, event, args):
        if not self.active:
            return
        if event in ('socket.connect', 'socket.bind'):
            address = args[1]
            internal = self._socketpair.get() and isinstance(address, tuple)
            if internal and address[0] in ('127.0.0.1', '::1'):
                return
            self.deny('network')
        if event in ('socket.getaddrinfo', 'socket.gethostbyname', 'socket.gethostbyaddr',
                     'socket.sendto', 'socket.sendmsg'):
            self.deny('network')
        if event in ('subprocess.Popen', 'os.system', 'os.fork', 'os.forkpty', 'os.posix_spawn',
                     'os.spawn', 'os.exec', 'os.startfile', 'os.startfile/2', 'os.openpty'):
            self.deny('subprocess')
        if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
            path = Path(os.fsdecode(args[0])).absolute()
            if self.home in path.parents:
                return
            parts = [part.lower() for part in path.parts]
            sensitive = any(part in ('.aws', '.azure', '.kube', '.oci', '.boto') for part in parts)
            sensitive |= any(parts[i:i + 2] == ['.config', 'gcloud'] for i in range(len(parts)))
            if sensitive:
                self.deny('credential-file')

    def install(self):
        # Windows platform identification uses a local subprocess. Warm it before the guard.
        platform.platform()
        platform.uname().processor
        for key in list(os.environ):
            if key.startswith(('AWS_', 'AZURE_', 'GOOGLE_', 'GCLOUD_', 'CLOUDSDK_', 'MSI_', 'IDENTITY_', 'OCI_')):
                os.environ.pop(key)
            elif key in ('KUBECONFIG', 'BOTO_CONFIG'):
                os.environ.pop(key)
        os.environ.update({
            'HOME': str(self.home), 'USERPROFILE': str(self.home), 'APPDATA': str(self.home),
            'LOCALAPPDATA': str(self.home), 'CLOUDSDK_CONFIG': str(self.home / 'gcloud'),
            'AZURE_CONFIG_DIR': str(self.home / 'azure'), 'AWS_EC2_METADATA_DISABLED': 'true',
            'AWS_CONFIG_FILE': str(self.home / 'aws-config'),
            'AWS_SHARED_CREDENTIALS_FILE': str(self.home / 'aws-credentials'),
            'BOTO_CONFIG': str(self.home / 'boto'), 'KUBECONFIG': str(self.home / 'kube-config'),
        })
        # urllib3 probes IPv6 with a local bind at import. Warm only that dependency;
        # provider imports and every test still run under the network audit hook.
        importlib.import_module('urllib3.util.connection')
        sys.addaudithook(self._audit)
        original_pair = socket.socketpair

        def socketpair(*args, **kwargs):
            token = self._socketpair.set(True)
            try:
                return original_pair(*args, **kwargs)
            finally:
                self._socketpair.reset(token)

        socket.socketpair = socketpair
        original_popen = subprocess.Popen

        # Preserve the class: asyncio.windows_utils subclasses Popen while importing.
        def blocked_popen(*args, **kwargs):
            self.deny('subprocess')

        original_popen.__init__ = blocked_popen
        for name in ('system', 'popen', 'fork', 'forkpty', 'posix_spawn', 'posix_spawnp',
                     'execl', 'execle', 'execlp', 'execlpe', 'execv', 'execve', 'execvp', 'execvpe',
                     'spawnl', 'spawnle', 'spawnlp', 'spawnlpe', 'spawnv', 'spawnve', 'spawnvp', 'spawnvpe', 'startfile'):
            if hasattr(os, name):
                setattr(os, name, blocked_popen)
        native = '_winapi' if os.name == 'nt' else '_posixsubprocess'
        self._block(importlib.import_module(native), 'CreateProcess' if os.name == 'nt' else 'fork_exec', 'subprocess')
        self._install_sdk_guards()
        atexit.register(self._cleanup)
        return self

    def _block(self, module, name, category):
        def blocked(*args, **kwargs):
            self.deny(category)
        setattr(module, name, blocked)

    def _install_sdk_guards(self):
        # Import the actual SDKs. A missing dependency is an error, never a skipped provider.
        import botocore.credentials
        import botocore.endpoint
        import botocore.utils
        import google.auth
        import google.auth._default
        import google.auth.credentials
        import google.oauth2.service_account
        import azure.identity
        import grpc
        import grpc.aio

        self._block(botocore.credentials.CredentialResolver, 'load_credentials', 'credentials')
        self._block(botocore.endpoint.Endpoint, 'make_request', 'cloud-api')
        self._block(botocore.utils.InstanceMetadataFetcher, 'retrieve_iam_role_credentials', 'credentials')
        self._block(botocore.utils.ContainerMetadataFetcher, 'retrieve_uri', 'credentials')
        self._block(botocore.utils.ContainerMetadataFetcher, 'retrieve_full_uri', 'credentials')
        for module in (google.auth, google.auth._default):
            for name in ('default', 'load_credentials_from_file'):
                self._block(module, name, 'credentials')
        self._block(google.auth.credentials.Credentials, 'before_request', 'credentials')
        self._block(google.oauth2.service_account.Credentials, 'from_service_account_file', 'credentials')
        for name in dir(azure.identity):
            cls = getattr(azure.identity, name)
            if isinstance(cls, type) and name.endswith('Credential') and hasattr(cls, 'get_token'):
                self._block(cls, '__init__', 'credentials')
                self._block(cls, 'get_token', 'credentials')
        for module in (grpc, grpc.aio):
            for name in ('secure_channel', 'insecure_channel'):
                self._block(module, name, 'network')

    def _cleanup(self):
        # Remain guarded until process exit, including pytest's own cleanup hooks.
        self._temporary_home.cleanup()


def validate_test_item(item):
    """Fail collection instead of silently hiding unsafe or non-executing tests."""
    import inspect
    import unittest

    forbidden = ('credential', 'cloudwatch', 'profiles', 'skip', 'skipif', 'xfail')
    for marker in forbidden:
        if item.get_closest_marker(marker) is not None:
            raise ValueError('Offline suite cannot collect marker: ' + marker)
    if inspect.iscoroutinefunction(item.obj):
        cls = getattr(item, 'cls', None)
        if cls is None or not issubclass(cls, unittest.IsolatedAsyncioTestCase):
            raise ValueError('Async tests require IsolatedAsyncioTestCase')
