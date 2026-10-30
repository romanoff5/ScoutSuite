# Offline validation record

Date: **2026-10-30**. Revision: `7909f2fc6186063e5c9e7ddef8c4d7d1072c8f3d`. Platform: Windows, CPython **3.11.9**. This is a deliberately limited baseline pass, not full application compatibility certification. No tracked implementation files were changed.

## Observed checks

| Check | Result | Interpretation |
| --- | --- | --- |
| Compile source without executing it | 526 Python files compile on 3.11 | Includes application, 13 test modules, Python tools, launcher and setup script; does not prove import/runtime compatibility |
| Parse application JSON | 633 JSON files under `ScoutSuite/` parse | Test aliases and intentionally invalid test files are not part of this count |
| Bundled includes archive | ZIP CRC validation passes | Does not establish dependency security or browser correctness |
| Requirement syntax | 49 runtime entries valid; 1 invalid development entry | `dev-requirements.txt:6`, `pytest>=5.*`, rejected by packaging (wildcards only with equality/inequality operators) |
| AWS operation-model lookup | 129 recognized service/operation pairs, 29 SDK services, all present | Static partial inventory against botocore 1.43.123; see [inventory](AWS_API_INVENTORY.md) |
| Fixture manifest | 19 matching input/output filename pairs for 147 AWS default rule keys | Presence only: about 12.9%; not a branch/rule coverage measurement |
| Git fixture representation | 20 tracked symlinks, all materialized as plain text locally | Git `core.symlinks=false`; files contain `ec2.json` or `iam-password-policy.json` instead of JSON |
| Guarded pytest selection | **46 passed, 2 failed, 1 skipped, 63 warnings; exit 1** | 49 selected of 52 test methods; at least 6 reported passes never execute their async bodies |

The two failures:

1. `tests/test_output.py::TestScoutOutput::test_get_filename`: expected a slash-separated string, but Windows `get_filename('REPORT')` returns `('scoutsuite-report\\report.html', None)`. This demonstrates a platform-specific assertion, not a proven report-generation failure.
2. `tests/test_rules_processingengine.py::TestScoutRulesProcessingEngine::test_all_finding_rules`: `json.load` fails on a fixture alias materialized as text (`ec2-default-security-group-in-use.json` contains `ec2.json`). Git records these files as mode `120000`. This does not establish the same failure on a symlink-capable checkout.

The skip is the existing EC2 user-data secret-recognition test. The six `TestMainClass` async methods report `coroutine ... was never awaited` and unittest return-value warnings. Their bodies, mocks and assertions are not validated. Other warnings include invalid regex escape sequences and deprecated unittest assertion spelling. A placeholder condition test and weak assertions further limit what the pass count proves.

Excluded from execution:

- Both `test_scoutsuite.py` cases: shell-spawned CLI help bypasses the in-process guard, while the default xfailed scanner case is not a safe offline test and has broken setup.
- `test_utils_fs.py::TestOpinelFsClass::test_save_blob_as_json`: writes fixed filenames including `/root/tmp1.json`, outside a dedicated fixture/output directory.

Harness development initially blocked local Windows platform identification and asyncio's internal loopback socket pair. Those harness errors were corrected before the final result above: cache local platform identification, preserve the `Popen` class while guarding its constructor, and permit loopback IPC. They are not repository defects. No external network was enabled to correct them. No failing application tests were edited or suppressed.

## Environment and isolation

A fresh Python 3.11 virtual environment was created under a task-specific temporary directory, outside the checkout. The installed **minimal selection** was pytest, coloredlogs 10.0, python-dateutil 2.8.0, netaddr, policyuniverse, sqlitedict, boto3, CherryPy, cherrypy-cors, asyncio-throttle 0.1.1 and azure-identity 1.5.0, plus their dependencies. This deliberately bypassed the invalid development requirement. Azure management SDKs, Graph and GCP client packages were not installed: their collection behavior was reviewed statically only. Downloads used the package index/cache during setup, not during test execution.

Before importing application/provider code, the runner cleared cloud-related environment settings without printing their values, redirected home/config locations to a fresh temporary directory, disabled EC2 metadata, disabled pytest plugin autoload, denied DNS/external socket connections and datagrams, denied subprocess construction, and rejected every unmocked botocore API call. AWS/Azure auth tests retained their existing mocks. Fixture reads used repository test data and bundled public IP metadata. No customer reports or ambient credential files were loaded.

Loopback connections were permitted for Windows asyncio's internal socket pair; no test contacted a cloud endpoint. This audited allowlist runner is a baseline procedure, not the completed M01 harness. M01 must enforce and self-test the boundary for all transports and subprocesses before broadening test selection.

## Repeat the guarded selection

Use Python 3.11 in an isolated environment with the dependency snapshot below. Acquire required wheels before testing; an offline installation can use `python -m pip install --no-index --find-links <wheelhouse> -r <snapshot-file>`. The snapshot is historical evidence, not the recommended future dependency set. Do not install the full invalid `dev-requirements.txt` as if it already works.

Save the following runner outside the repository, run it from the repository root with that environment's interpreter, and expect the recorded failures on the same Windows fixture representation. Do not substitute an unrestricted `pytest` invocation or a real `scout aws` run. The runner disables bytecode/cache outputs; the existing rule test may create small synthetic temporary ruleset files outside the checkout.

```python
import os, pathlib, platform, socket, subprocess, sys, tempfile
sys.dont_write_bytecode = True
for key in list(os.environ):
    if key.startswith(('AWS_', 'AZURE_', 'GOOGLE_', 'GCLOUD_', 'CLOUDSDK_', 'MSI_', 'IDENTITY_', 'OCI_')) or key in ('KUBECONFIG','BOTO_CONFIG'):
        os.environ.pop(key, None)
with tempfile.TemporaryDirectory(prefix='scoutsuite-offline-') as sandbox:
    os.environ.update(HOME=sandbox, USERPROFILE=sandbox, APPDATA=sandbox, LOCALAPPDATA=sandbox,
                      AWS_EC2_METADATA_DISABLED='true', AWS_SHARED_CREDENTIALS_FILE=sandbox+'/credentials',
                      AWS_CONFIG_FILE=sandbox+'/config', BOTO_CONFIG=sandbox+'/boto',
                      PYTEST_DISABLE_PLUGIN_AUTOLOAD='1')
    # Warm local OS identification before prohibiting child processes.
    platform.platform()
    platform.uname().processor
    import pytest
    def deny(*args, **kwargs):
        raise AssertionError('OFFLINE GUARD: network or child process attempted')
    socket.create_connection = deny
    socket.getaddrinfo = deny
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    def connect_local(self, address):
        if isinstance(address, tuple) and address[0] in ('127.0.0.1', '::1'):
            return original_connect(self, address)
        return deny()
    def connect_ex_local(self, address):
        if isinstance(address, tuple) and address[0] in ('127.0.0.1', '::1'):
            return original_connect_ex(self, address)
        return deny()
    socket.socket.connect = connect_local
    socket.socket.connect_ex = connect_ex_local
    socket.socket.sendto = deny
    subprocess.Popen.__init__ = deny
    import botocore.client
    botocore.client.BaseClient._make_api_call = deny
    targets = [str(p) for p in sorted(pathlib.Path('tests').glob('test_*.py'))
               if p.name not in ('test_scoutsuite.py','test_utils_fs.py')]
    targets += ['tests/test_utils_fs.py::TestOpinelFsClass::'+n for n in
                ('test_CustomJSONEncoder','test_load_data','test_read_ip_ranges')]
    rc = pytest.main(['-q','-p','no:cacheprovider','--tb=short','--show-capture=no','--disable-warnings',*targets])
    print('BASELINE_PYTEST_EXIT',rc)
    sys.exit(rc)
```

The selection includes all `tests/test_*.py` except the scanner and filesystem modules, then explicitly adds the filesystem encoder/load/IP-range cases. It does not load live assessments or contact external APIs. Preserve the exclusion rationale if moving this into a future harness.

## Resolved minimal environment snapshot

Captured through installed distribution metadata. Pinning a name/version alone is not a future release lock: Phase 2 adds hashes, platform/interpreter constraints and provenance. This environment is for reproducing the historical result, including its old package caps.

```text
annotated-doc==0.0.5
asyncio-throttle==0.1.1
azure-core==1.41.0
azure-identity==1.5.0
backports.tarfile==1.2.0
boto3==1.43.123
botocore==1.43.123
certifi==2026.10.23
cffi==2.1.1
charset-normalizer==3.5.2
cheroot==11.1.2
cherrypy-cors==1.7.0
CherryPy==18.10.0
colorama==0.4.6
coloredlogs==10.0
cryptography==50.0.2
httpagentparser==1.9.9
humanfriendly==10.0
idna==3.20
iniconfig==2.3.1
jaraco.collections==5.2.1
jaraco.context==6.1.2
jaraco.functools==4.6.0
jaraco.text==4.3.0
jmespath==1.1.0
markdown-it-py==4.2.0
mdurl==0.1.2
more-itertools==11.2.1
msal-extensions==0.3.1
msal==1.39.0
netaddr==1.3.0
packaging==26.3
pip==24.0
pluggy==1.7.0
policyuniverse==1.5.1.20231109
portalocker==2.10.1
portend==3.2.1
pycparser==3.12
Pygments==2.21.0
PyJWT==2.15.1
pyreadline3==3.5.6
pytest==9.2.0
python-dateutil==2.8.0
pywin32==312
requests==2.34.2
rich==15.0.0
s3transfer==0.19.3
setuptools==65.5.0
shellingham==1.5.4
six==1.17.0
sqlitedict==2.1.0
tempora==5.13.0
typer-slim==0.24.0
typer==0.27.3
typing_extensions==4.16.0
urllib3==2.8.0
zc.lockfile==4.0
```

## Limits and next evidence

Not run: the full unguarded test suite; credential/live-cloud tests; actual AWS/Azure/GCP collection; full dependency resolution; installed-wheel/sdist/container validation; hosted CI; Python 3.12-3.15 execution suites; browser rendering/interaction or large-report benchmarks; advisory/reachability analysis. The default Python on this host is 3.14.4, but the measured suite explicitly used 3.11.9. Compiler success must not be reported as runtime success on any other interpreter.

Use [Phase 1](ROADMAP.md) to turn this limited evidence into a trustworthy baseline. Preserve these dated results as history when failures are fixed.

