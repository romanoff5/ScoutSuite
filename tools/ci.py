"""CI acquisition and explicit offline gates; no scanner or cloud CLI invocation."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import time
import urllib.request
import xml.etree.ElementTree as ET
import zipfile


SOURCE = Path(__file__).resolve().parents[1]
PHASES = ('acquire', 'workflows', 'build', 'dependencies', 'lint', 'tests', 'packaging')
CLI_CASES = {'test_empty', 'test_aws_provider', 'test_gcp_provider', 'test_azure_provider',
             'test_unauthenticated', 'test_keyboardinterrupted'}
ACTIONLINT = {
    'Windows': ('windows_amd64.zip', '6e7241b51e6817ea6a047693d8e6fed13b31819c9a0dd6c5a726e1592d22f6e9'),
    'Linux': ('linux_amd64.tar.gz', '8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8'),
}


def clean_environment(root, offline):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('AWS_', 'AZURE_', 'GOOGLE_', 'GCLOUD_', 'CLOUDSDK_', 'MSI_',
                                  'IDENTITY_', 'OCI_', 'ACTIONS_'))
           and key not in ('GH_TOKEN', 'GITHUB_TOKEN', 'KUBECONFIG', 'BOTO_CONFIG', 'PYTHONPATH', 'PYTHONHOME')}
    home = root / 'home'
    home.mkdir(exist_ok=True)
    env.update(HOME=str(home), USERPROFILE=str(home), APPDATA=str(home), LOCALAPPDATA=str(home),
               AWS_EC2_METADATA_DISABLED='true', PYTHONDONTWRITEBYTECODE='1',
               PIP_DISABLE_PIP_VERSION_CHECK='1', PIP_CACHE_DIR=str(root / 'pip-cache'),
               SOURCE_DATE_EPOCH='1793404800')
    if offline:
        env.update(PIP_NO_INDEX='1', UV_OFFLINE='1')
    return env


def python_at(root, name):
    return str(root / name / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python'))


def verify_execution(junit, manifest):
    """Missing bodies, skipped results and incomplete fixture verification fail CI."""
    cases = list(ET.fromstring(junit).iter('testcase'))
    assert cases, 'No test bodies recorded'
    assert not any(child.tag in ('skipped', 'failure', 'error')
                   for case in cases for child in case), 'Non-passing test result'
    cli = {case.attrib['name'] for case in cases if case.attrib.get('classname', '').endswith('TestMainClass')}
    assert CLI_CASES <= cli, 'Formerly async CLI bodies did not all execute'
    for module in ('test_offline', 'test_cli_assertions', 'test_characterization'):
        assert any(module in case.attrib.get('classname', '') for case in cases), 'Missing M01 gate: ' + module
    assert manifest['exitstatus'] == 0
    assert manifest['cases'] and all(row['test_status'] == 'verified' and row['fixture_status'] == 'valid'
                                     for row in manifest['cases']), 'Incomplete fixture verification'
    return {'junit_cases': len(cases), 'cli_bodies': len(cli),
            'verified_fixture_cases': len(manifest['cases']), 'warnings': manifest['warnings'],
            'untested_rules': {name: len(keys) for name, keys in manifest['untested'].items()}}


class Pipeline:
    def __init__(self, root, phase):
        self.root = root.resolve()
        assert not self.root.is_relative_to(SOURCE), 'CI environments must be outside the checkout'
        self.root.mkdir(parents=True, exist_ok=True)
        self.phase = phase
        self.offline = phase != 'acquire'
        self.env = clean_environment(self.root, self.offline)
        self.enforce = os.environ.get('SCOUT_CI_ENFORCE_OS_ISOLATION') == '1'

    def run(self, command, cwd=None):
        command = [str(arg) for arg in command]
        if self.offline and self.enforce and os.name != 'nt':
            preserved = ('HOME,USERPROFILE,APPDATA,LOCALAPPDATA,AWS_EC2_METADATA_DISABLED,'
                         'PYTHONDONTWRITEBYTECODE,PIP_DISABLE_PIP_VERSION_CHECK,PIP_CACHE_DIR,'
                         'SOURCE_DATE_EPOCH,PIP_NO_INDEX,UV_OFFLINE')
            command = ['sudo', '-n', '--preserve-env=' + preserved,
                       'unshare', '--net', '--', 'runuser', '--preserve-environment',
                       '-u', os.environ['USER'], '--'] + command
        print('+ ' + ' '.join(command), flush=True)
        subprocess.run(command, cwd=cwd or self.root, env=self.env, check=True)

    def pip(self, name, *arguments):
        self.run([python_at(self.root, name), '-m', 'pip', '--isolated', *arguments])

    def create(self, name):
        assert not (self.root / name).exists(), 'Use a fresh CI root: ' + name
        self.run([sys.executable, '-m', 'venv', self.root / name])

    def acquire(self):
        self.create('build')
        self.pip('build', 'install', '--cache-dir', self.root / 'pip-cache',
                 '-r', SOURCE / 'constraints/build-py311.txt', '-r', SOURCE / 'constraints/ci-py311.txt')
        self.pip('build', 'wheel', '--no-build-isolation', '--cache-dir', self.root / 'pip-cache',
                 '-r', SOURCE / 'tests/requirements-offline.txt', '-r', SOURCE / 'constraints/build-py311.txt',
                 '-c', SOURCE / 'constraints/ci-py311.txt', '-c', SOURCE / 'constraints/combined-py311.txt',
                 '--wheel-dir', self.root / 'wheelhouse')
        for name in ('core', 'aws'):
            self.create(name)
            self.pip(name, 'install', '--cache-dir', self.root / 'pip-cache', 'pip==24.0',
                     'setuptools==80.9.0', 'wheel==0.45.1')
            if name == 'aws':
                self.pip(name, 'install', '--cache-dir', self.root / 'pip-cache', '--no-build-isolation',
                         '--require-hashes', '-r', SOURCE / 'constraints/aws-core-py311.lock')
            else:
                self.pip(name, 'install', '--cache-dir', self.root / 'pip-cache', '--no-build-isolation',
                         '-r', SOURCE / 'requirements-core.txt', '-c', SOURCE / 'constraints/aws-core-py311.txt')
        suffix, digest = ACTIONLINT[platform.system()]
        archive = self.root / ('actionlint_' + suffix)
        url = 'https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_' + suffix
        with urllib.request.urlopen(url, timeout=60) as response:
            archive.write_bytes(response.read())
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == digest, 'actionlint digest mismatch'
        binary = 'actionlint.exe' if os.name == 'nt' else 'actionlint'
        if archive.suffix == '.zip':
            with zipfile.ZipFile(archive) as release:
                (self.root / binary).write_bytes(release.read(binary))
        else:
            with tarfile.open(archive) as release:
                (self.root / binary).write_bytes(release.extractfile(binary).read())
            (self.root / binary).chmod(0o755)

    def workflows(self):
        binary = self.root / ('actionlint.exe' if os.name == 'nt' else 'actionlint')
        self.run([binary, '-color', '-shellcheck=', '-pyflakes='], cwd=SOURCE)

    def build(self):
        # Only tracked files enter the staging tree, never ambient reports/credentials.
        archive = self.root / 'source.zip'
        self.run(['git', '-C', SOURCE, 'archive', '--format=zip', '--output', archive, 'HEAD'])
        staging = self.root / 'source'
        with zipfile.ZipFile(archive) as checkout:
            checkout.extractall(staging)
        self.run([python_at(self.root, 'build'), '-m', 'build', '--no-isolation',
                  '--outdir', self.root / 'dist', staging])
        wheel, = (self.root / 'dist').glob('*.whl')
        sdist, = (self.root / 'dist').glob('*.tar.gz')
        for name, artifact in (('test', wheel), ('wheel', wheel), ('sdist', sdist)):
            self.create(name)
            self.pip(name, 'install', '--no-index', '--find-links', self.root / 'wheelhouse',
                     '-r', SOURCE / 'constraints/build-py311.txt')
            self.pip(name, 'install', '--no-index', '--no-build-isolation', '--find-links', self.root / 'wheelhouse',
                     '-c', SOURCE / 'constraints/combined-py311.txt', '-c', SOURCE / 'constraints/ci-py311.txt', artifact)
            if name == 'test':
                self.pip(name, 'install', '--no-index', '--find-links', self.root / 'wheelhouse',
                         '-c', SOURCE / 'constraints/combined-py311.txt', '-c', SOURCE / 'constraints/ci-py311.txt',
                         '-r', SOURCE / 'tests/requirements-offline.txt')
        self.write('artifacts', {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                 for path in (wheel, sdist)})

    def dependencies(self):
        for name in ('build', 'core', 'aws', 'test', 'wheel', 'sdist'):
            self.pip(name, 'check')
            # Exact versions only, no environment variables, credential files or pip config.
            code = ('import importlib.metadata as m,json,sys; '
                    'print(json.dumps({"python":sys.version.split()[0],"packages":'
                    '{d.metadata["Name"]:d.version for d in m.distributions()}},sort_keys=True))')
            self.run([python_at(self.root, name), '-I', '-c', code])

    def lint(self):
        self.run([python_at(self.root, 'test'), '-m', 'flake8', '.'], cwd=SOURCE)

    def tests(self):
        self.run([python_at(self.root, 'test'), '-B', '-m', 'pytest', '-q', '-p', 'no:cacheprovider',
                  '--tb=short', '--show-capture=no', '-o', 'junit_family=xunit1',
                  '--junitxml=' + str(self.root / 'junit.xml'),
                  '--offline-manifest-report=' + str(self.root / 'fixtures.json')], cwd=SOURCE)
        data = verify_execution((self.root / 'junit.xml').read_text(encoding='utf-8'),
                                json.loads((self.root / 'fixtures.json').read_text(encoding='utf-8')))
        # Node-based browser-helper checks require subprocess. Run them from
        # the CI orchestrator, NOT from guarded pytest, preserving the
        # pytest network/subprocess audit boundary. Pipeline.run still applies
        # Linux network namespaces / Windows firewall isolation.
        self.run([python_at(self.root, 'test'), '-I', '-B',
                  SOURCE / 'tools/m09b_viewer_js_check.py'], cwd=SOURCE)
        self.write('test-execution', data)
        print(json.dumps(data, sort_keys=True), flush=True)

    def packaging(self):
        for name in ('core', 'aws', 'wheel', 'sdist'):
            profile = name if name in ('core', 'aws') else 'combined'
            self.run([python_at(self.root, name), '-I', '-B', SOURCE / 'tools/verify_distribution.py',
                      '--source', self.root / 'source', '--profile', profile,
                      '--output', self.root / (name + '-smoke.json')])

    def write(self, name, value):
        (self.root / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')

    def summary(self):
        rows = []
        for phase in PHASES:
            path = self.root / ('phase-' + phase + '.json')
            rows.append(json.loads(path.read_text()) if path.exists() else {'phase': phase, 'status': 'NOT RUN'})
        text = '## Offline CI gate outcomes\n\n| Gate | Result |\n| --- | --- |\n'
        text += ''.join('| {phase} | {status} |\n'.format(**row) for row in rows)
        for name in ('test-execution', 'artifacts'):
            path = self.root / (name + '.json')
            if path.exists():
                text += '\n```json\n' + path.read_text() + '```\n'
        text += ('\nExact interpreter/package versions are in the dependency-check step logs. '
                 'Warnings remain visible. No reports or coverage were uploaded.\n')
        print(text)
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as stream:
                stream.write(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=PHASES + ('summary',))
    parser.add_argument('--root', type=Path, default=os.environ.get('SCOUT_CI_ROOT'))
    args = parser.parse_args()
    if args.root is None:
        parser.error('Set SCOUT_CI_ROOT to a fresh directory outside the checkout')
    pipeline = Pipeline(Path(args.root), args.phase)
    started = time.monotonic()
    status = 'FAILED'
    try:
        getattr(pipeline, args.phase)()
        status = 'PASSED'
    finally:
        pipeline.write('phase-' + args.phase, {'phase': args.phase, 'status': status,
                                             'seconds': round(time.monotonic() - started, 2)})


if __name__ == '__main__':
    main()
