"""Negative tests assert the guard fires before an operation can reach the host."""

import _socket
import asyncio
from contextlib import closing
import importlib
from pathlib import Path
import os
import socket
import subprocess
import sys
from types import SimpleNamespace
import unittest

import boto3
import botocore.session
from botocore.utils import ContainerMetadataFetcher, InstanceMetadataFetcher
from botocore.stub import Stubber
import google.auth
import grpc
import grpc.aio
import pytest
import requests
from _pytest.runner import CallInfo
from azure.identity import AzureCliCredential, DefaultAzureCredential, ManagedIdentityCredential

from tests.offline import OfflineViolation, validate_test_item


@pytest.mark.parametrize('address', [('198.51.100.1', 443), ('169.254.169.254', 80), ('127.0.0.1', 80), ('::1', 80)])
def test_socket_connections_are_denied(offline, address):
    family = socket.AF_INET6 if ':' in address[0] else socket.AF_INET
    with socket.socket(family) as client, offline.expect_violation('network'):
        client.connect(address)


def test_raw_socket_cannot_bypass_guard(offline):
    with closing(_socket.socket()) as client, offline.expect_violation('network'):
        client.connect(('198.51.100.1', 443))


def test_udp_and_dns_are_denied(offline):
    with socket.socket(type=socket.SOCK_DGRAM) as client, offline.expect_violation('network'):
        client.sendto(b'synthetic', ('198.51.100.1', 53))
    with offline.expect_violation('network'):
        socket.getaddrinfo('offline.invalid', 443)


def test_implicit_server_listen_is_denied(offline):
    with socket.socket() as server, offline.expect_violation('network'):
        server.listen()


def test_http_cannot_use_environment_proxy_to_escape(offline):
    with offline.expect_violation('network'):
        requests.get('https://offline.invalid', timeout=0.1)


@pytest.mark.parametrize('factory', [grpc.secure_channel, grpc.insecure_channel,
                                   grpc.aio.secure_channel, grpc.aio.insecure_channel])
def test_native_grpc_channels_are_denied(offline, factory):
    with offline.expect_violation('network'):
        factory('offline.invalid:443')


def test_subprocesses_and_shells_are_denied(offline, tmp_path):
    sentinel = tmp_path / 'child-ran'
    with offline.expect_violation('subprocess'):
        subprocess.run([sys.executable, '-c', 'raise SystemExit(99)'], check=True)
    with offline.expect_violation('subprocess'):
        os.system('echo forbidden')
    assert not sentinel.exists()


def test_native_process_creation_is_denied(offline):
    module = importlib.import_module('_winapi' if os.name == 'nt' else '_posixsubprocess')
    create = getattr(module, 'CreateProcess' if os.name == 'nt' else 'fork_exec')
    with offline.expect_violation('subprocess'):
        create()  # Guard rejects the call before parsing OS-specific launch arguments.


def test_credential_files_cannot_be_opened(offline):
    # No real home or credential store is inspected; audit rejection precedes filesystem access.
    with offline.expect_violation('credential-file'):
        (offline.home.parent / 'scoutsuite-credential-probe' / '.aws' / 'credentials').read_text()
    assert Path.home() == offline.home
    assert Path(os.environ['AWS_SHARED_CREDENTIALS_FILE']).parent == offline.home
    assert os.environ['AWS_EC2_METADATA_DISABLED'] == 'true'


def test_default_aws_credential_discovery_is_denied(offline):
    with offline.expect_violation('credentials'):
        botocore.session.get_session().get_credentials()


def test_metadata_credential_discovery_is_denied(offline):
    with offline.expect_violation('credentials'):
        InstanceMetadataFetcher().retrieve_iam_role_credentials()
    with offline.expect_violation('credentials'):
        ContainerMetadataFetcher().retrieve_uri('/synthetic')


def test_default_google_credentials_are_denied(offline):
    with offline.expect_violation('credentials'):
        google.auth.default()


@pytest.mark.parametrize('credential', [DefaultAzureCredential, AzureCliCredential, ManagedIdentityCredential])
def test_azure_credential_chains_are_denied(offline, credential):
    with offline.expect_violation('credentials'):
        credential()


def test_unstubbed_aws_call_is_denied_but_stubber_is_supported(offline):
    client = boto3.client('sts', region_name='us-east-1', aws_access_key_id='testing', aws_secret_access_key='testing')
    response = {'Account': '000000000000', 'Arn': 'arn:aws:iam::000000000000:user/offline', 'UserId': 'offline'}
    with Stubber(client) as stub:
        stub.add_response('get_caller_identity', response, {})
        assert client.get_caller_identity() == response
        stub.assert_no_pending_responses()
    with offline.expect_violation('cloud-api'):
        client.get_caller_identity()
    client.close()


def test_socketpair_allows_only_internal_ipc():
    left, right = socket.socketpair()
    with left, right:
        left.send(b'x')
        assert right.recv(1) == b'x'
    with asyncio.Runner() as runner:
        assert runner.run(asyncio.sleep(0, result='executed')) == 'executed'


def test_swallowed_violation_still_fails_boundary_check(offline):
    try:
        socket.getaddrinfo('offline.invalid', 443)
    except OfflineViolation:
        pass
    with pytest.raises(AssertionError, match='Unacknowledged'):
        offline.assert_no_violations()


@pytest.mark.parametrize('marker', ['credential', 'cloudwatch', 'profiles', 'skip', 'skipif', 'xfail'])
def test_live_and_nonexecuting_markers_are_rejected(marker):
    item = SimpleNamespace(obj=lambda: None, get_closest_marker=lambda name: object() if name == marker else None)
    with pytest.raises(ValueError, match='cannot collect'):
        validate_test_item(item)


def test_unawaited_test_methods_are_rejected():
    class BrokenTest(unittest.TestCase):
        async def test_body(self):
            raise AssertionError('Must execute')

    item = SimpleNamespace(obj=BrokenTest.test_body, cls=BrokenTest, get_closest_marker=lambda name: None)
    with pytest.raises(ValueError, match='IsolatedAsyncioTestCase'):
        validate_test_item(item)


@pytest.mark.parametrize('terminate', [pytest.skip, pytest.xfail], ids=['runtime-skip', 'runtime-xfail'])
def test_runtime_short_circuit_is_reported_as_failure(request, terminate):
    # Exercise the actual registered report-hook stack, including pytest's own xfail hook.
    call = CallInfo.from_call(lambda: terminate('synthetic boundary probe'), when='call')
    report = request.config.hook.pytest_runtest_makereport(item=request.node, call=call)
    assert report.failed
    assert not report.skipped
