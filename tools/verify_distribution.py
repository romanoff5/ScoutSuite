"""Guarded dependency/artifact smoke; run with a clean interpreter outside the checkout."""

import argparse
import contextlib
import hashlib
import importlib.metadata
import importlib.util
import io
import json
from pathlib import Path
import socket
import sys
import tempfile
from types import SimpleNamespace


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--profile', choices=['core', 'aws', 'combined'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve()
    assert not Path.cwd().resolve().is_relative_to(source), 'Run outside the source checkout'
    spec = importlib.util.spec_from_file_location('m01_offline', source / 'tests/offline.py')
    offline = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(offline)
    required = {'core': (), 'aws': ('aws',), 'combined': ('aws', 'azure', 'gcp')}[args.profile]
    guard = offline.OfflineGuard(required_providers=required).install()
    with guard.expect_violation('network'):
        socket.getaddrinfo('offline.invalid', 443)
    import dateutil.parser
    import netaddr
    import cherrypy
    import policyuniverse
    from sqlitedict import SqliteDict
    assert dateutil.parser.parse('2020-01-01').year == 2020
    assert str(netaddr.IPNetwork('192.0.2.0/24')) == '192.0.2.0/24'
    assert cherrypy.__version__
    assert policyuniverse.__file__
    with tempfile.TemporaryDirectory() as temporary:
        with SqliteDict(str(Path(temporary) / 'synthetic.db')) as database:
            database['offline'] = True
            assert database['offline'] is True
    result = {'profile': args.profile, 'python': sys.version.split()[0], 'checks': ['network-denial', 'core-imports']}
    if args.profile != 'combined':
        absent = ['ScoutSuite', 'azure-identity', 'google-auth']
        if args.profile == 'core':
            absent += ['boto3', 'botocore']
        for name in absent:
            try:
                importlib.metadata.version(name)
            except importlib.metadata.PackageNotFoundError:
                continue
            raise AssertionError('Minimal dependency environment contains unexpected package: ' + name)
        result['checks'] += ['minimal-dependency-profile']
    if args.profile != 'core':
        import boto3
        import botocore.session
        from botocore.stub import Stubber
        with guard.expect_violation('credentials'):
            botocore.session.get_session().get_credentials()
        client = boto3.client('sts', region_name='us-east-1', aws_access_key_id='testing', aws_secret_access_key='testing')
        identity = {'Account': '000000000000', 'Arn': 'arn:aws:iam::000000000000:user/offline', 'UserId': 'offline'}
        try:
            with Stubber(client) as stub:
                stub.add_response('get_caller_identity', identity, {})
                assert client.get_caller_identity() == identity
                stub.assert_no_pending_responses()
            with guard.expect_violation('cloud-api'):
                client.get_caller_identity()
        finally:
            client.close()
        result['checks'] += ['credential-denial', 'aws-stubber', 'unstubbed-api-denial']
    if args.profile == 'combined':
        import ScoutSuite
        installed = Path(ScoutSuite.__file__).resolve().parent
        assert not installed.is_relative_to(source), 'Source checkout shadowed installed artifact'
        extensions = {'.py', '.json', '.html', '.js', '.css', '.zip', '.ico'}
        count = 0
        for path in (source / 'ScoutSuite').rglob('*'):
            if path.is_file() and (path.suffix in extensions or path.name in ('.keep', '.gitkeep')):
                relative = path.relative_to(source / 'ScoutSuite')
                actual = installed / relative
                assert actual.is_file(), 'Missing packaged asset: ' + str(relative)
                assert hashlib.sha256(actual.read_bytes()).digest() == hashlib.sha256(path.read_bytes()).digest(), relative
                count += 1
        dist = importlib.metadata.distribution('ScoutSuite')
        from packaging.requirements import Requirement
        declared = {Requirement(line.strip()) for line in (source / 'requirements.txt').read_text().splitlines()
                    if line.strip() and not line.lstrip().startswith('#')}
        assert {Requirement(line) for line in dist.requires} == declared
        assert dist.metadata['Requires-Python'] == '>=3.11'
        entry = next(ep for ep in dist.entry_points if ep.group == 'console_scripts' and ep.name == 'scout')
        assert entry.value == 'ScoutSuite.__main__:run_from_cli'
        old_argv = sys.argv
        try:
            sys.argv = ['scout', '--help']
            with contextlib.redirect_stdout(io.StringIO()) as stdout:
                try:
                    entry.load()()
                except SystemExit as error:
                    assert error.code == 0
                else:
                    raise AssertionError('CLI help did not execute')
            assert 'aws' in stdout.getvalue() and 'azure' in stdout.getvalue() and 'gcp' in stdout.getvalue()
        finally:
            sys.argv = old_argv
        from ScoutSuite.core.ruleset import Ruleset
        from ScoutSuite.output.html import ScoutReport
        from ScoutSuite import ERRORS_LIST
        ERRORS_LIST.clear()
        for provider in ('aws', 'azure', 'gcp'):
            rules = Ruleset(cloud_provider=provider, filename='default.json')
            assert rules.rules
            with tempfile.TemporaryDirectory() as report_dir:
                report = ScoutReport(provider, 'synthetic', report_dir)
                output = report.save(SimpleNamespace(services={}, service_list=[]), {}, force_write=True)
                assert Path(output).is_file()
                assert report.encoder.load_from_file('RESULTS')['services'] == {}
        assert not ERRORS_LIST
        origin = json.loads(dist.read_text('direct_url.json'))
        result.update(package_version=dist.version, packaged_files_verified=count,
                      runtime_requirements_verified=len(declared),
                      installed_archive_sha256=origin['archive_info']['hashes']['sha256'])
        result['checks'] += ['all-source-assets-sha256', 'installed-cli-entry', 'aws-azure-gcp-rules-and-reports']
    guard.assert_no_violations()
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
