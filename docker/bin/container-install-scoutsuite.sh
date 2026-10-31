#!/bin/bash
set -euo pipefail
# Legacy helper: an explicit local source tree is mandatory. Never fall back to PyPI.
scout_source="${SCOUTSUITE_SOURCE:?Set SCOUTSUITE_SOURCE to the local fork source directory}"
test -f "${scout_source}/pyproject.toml"
python3 -m venv /opt/scoutsuite
/opt/scoutsuite/bin/python -m pip install setuptools==80.9.0 wheel==0.45.1
/opt/scoutsuite/bin/python -m pip install --no-build-isolation \
  -c "${scout_source}/constraints/combined-py311.txt" "${scout_source}"
/opt/scoutsuite/bin/python -m pip check
