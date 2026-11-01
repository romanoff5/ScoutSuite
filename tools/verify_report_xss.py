"""Isolated adversarial JS/Chromium checks (outside guarded pytest, still offline).

The main M01 pytest suite deliberately blocks all subprocess creation. This
entry point is executed by the separate CI gate under OS network isolation
(with cloud credentials removed), so Node and headless Chromium can run.
"""
from pathlib import Path
import os
import runpy
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def main():
    tests = runpy.run_path(str(ROOT / 'tests' / 'test_m09b_xss_audit.py'))
    tests['check_legacy_js_action_parser_rejects_code_injection_and_malicious_urls']()
    print('XSS action parser adversarial checks: PASSED', flush=True)
    with tempfile.TemporaryDirectory(prefix='scoutsuite-xss-browser-') as directory:
        ran = tests['check_compiled_markup_blocks_dom_xss_in_real_chromium_when_available'](
            Path(directory))
        if not ran and os.name != 'nt':
            raise RuntimeError('Headless Chromium/Chrome is required for the Linux XSS security gate')
        print('Headless browser DOM XSS checks: ' + ('PASSED' if ran else 'NOT AVAILABLE (Windows)'),
              flush=True)


if __name__ == '__main__':
    main()
